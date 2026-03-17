/**
 * Deferred retry queue worker per spec section 3.10.
 * Processes queued verification requests when IVS becomes available.
 */

const { getDb } = require('../database/db');
const { decryptPayload } = require('../crypto');
const { isIvsAvailable } = require('../services/ivs-simulator');
const { sendVerification } = require('../services/ivs-client');
const { verifyClaim } = require('../crypto');
const { recordAuditEvent, EventTypes } = require('../audit');
const config = require('../config');

let workerInterval = null;

function startQueueWorker() {
  if (workerInterval) return;

  workerInterval = setInterval(() => {
    processQueue();
  }, config.queue.workerIntervalMs);

  console.log(`[Queue Worker] Started, interval: ${config.queue.workerIntervalMs}ms`);
}

function stopQueueWorker() {
  if (workerInterval) {
    clearInterval(workerInterval);
    workerInterval = null;
    console.log('[Queue Worker] Stopped');
  }
}

async function processQueue() {
  if (!isIvsAvailable()) return;

  const db = getDb();

  // Find items ready for retry
  const items = db.prepare(`
    SELECT * FROM verification_queue
    WHERE status IN ('queued', 'retrying')
      AND (next_retry_at IS NULL OR next_retry_at <= datetime('now'))
      AND expires_at > datetime('now')
    ORDER BY created_at ASC
    LIMIT 10
  `).all();

  for (const item of items) {
    await processQueueItem(item, db);
  }

  // Expire old items
  const expired = db.prepare(`
    UPDATE verification_queue SET status = 'expired'
    WHERE status IN ('queued', 'retrying') AND expires_at <= datetime('now')
  `).run();

  if (expired.changes > 0) {
    // Record audit events for expired items
    const expiredItems = db.prepare("SELECT correlation_id FROM verification_queue WHERE status = 'expired'").all();
    for (const ei of expiredItems) {
      recordAuditEvent(EventTypes.QUEUED_REQUEST_EXPIRED, ei.correlation_id, {});
      // Update the main request status too
      db.prepare("UPDATE verification_requests SET status = 'expired', completed_at = datetime('now') WHERE correlation_id = ?").run(ei.correlation_id);
    }
  }
}

async function processQueueItem(item, db) {
  const correlationId = item.correlation_id;

  try {
    // Decrypt the stored request
    const requestJson = decryptPayload(item.encrypted_request_payload);
    const request = JSON.parse(requestJson);

    recordAuditEvent(EventTypes.QUEUED_REQUEST_RETRIED, correlationId, { retry_count: item.retry_count + 1 });

    // Update queue status
    db.prepare(`
      UPDATE verification_queue SET status = 'retrying', retry_count = retry_count + 1, last_retry_at = datetime('now')
      WHERE id = ?
    `).run(item.id);

    // Attempt verification
    const ivsResponse = await sendVerification(request);

    // Normalize: extract fields from wherever the IVS puts them
    const verificationStatus = ivsResponse.verification_status
      || ivsResponse.claim?.verification_status
      || ivsResponse.data?.verification_status
      || (ivsResponse.status === 'error' ? 'error' : null);
    const claim = ivsResponse.claim || ivsResponse.data?.claim || null;

    if (ivsResponse.status === 'success' && verificationStatus !== 'registry_unavailable') {
      // Verify IVS signature
      let sigVerified = false;
      if (claim?.signature) {
        const { signature, ...claimWithoutSig } = claim;
        sigVerified = verifyClaim(claimWithoutSig, signature);
      }

      const finalStatus = verificationStatus || 'unknown';

      // Store result
      db.prepare(`
        INSERT INTO verification_results (correlation_id, verification_status, claim_json, ivs_signature_verified)
        VALUES (?, ?, ?, ?)
      `).run(correlationId, finalStatus, JSON.stringify(claim), sigVerified ? 1 : 0);

      // Update statuses
      db.prepare("UPDATE verification_queue SET status = 'succeeded' WHERE id = ?").run(item.id);
      db.prepare("UPDATE verification_requests SET status = ?, completed_at = datetime('now') WHERE correlation_id = ?").run(finalStatus, correlationId);

      recordAuditEvent(EventTypes.QUEUED_REQUEST_SUCCEEDED, correlationId, {
        verification_status: finalStatus,
      });
    } else {
      // Still failing, schedule next retry
      const retrySchedule = config.queue.retryScheduleMinutes;
      const nextRetryIdx = Math.min(item.retry_count, retrySchedule.length - 1);
      const nextRetryMinutes = retrySchedule[nextRetryIdx];

      db.prepare(`
        UPDATE verification_queue SET status = 'queued', next_retry_at = datetime('now', '+${nextRetryMinutes} minutes')
        WHERE id = ?
      `).run(item.id);
    }
  } catch (err) {
    console.error(`[Queue Worker] Error processing item ${correlationId}:`, err.message);
    // Schedule next retry
    db.prepare(`
      UPDATE verification_queue SET status = 'queued', retry_count = retry_count + 1, last_retry_at = datetime('now')
      WHERE id = ?
    `).run(item.id);
  }
}

/**
 * Get queue statistics for monitoring.
 */
function getQueueStats() {
  const db = getDb();
  const total = db.prepare('SELECT COUNT(*) as count FROM verification_queue').get();
  const byStatus = db.prepare('SELECT status, COUNT(*) as count FROM verification_queue GROUP BY status').all();
  const pending = db.prepare("SELECT COUNT(*) as count FROM verification_queue WHERE status IN ('queued', 'retrying')").get();
  return { total: total.count, pending: pending.count, byStatus };
}

module.exports = { startQueueWorker, stopQueueWorker, processQueue, getQueueStats };
