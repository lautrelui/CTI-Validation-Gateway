/**
 * Deferred retry queue worker per spec section 3.10.
 *
 * Processes two queues:
 * 1. verification_queue — retries IVS calls when IVS was unavailable
 * 2. callback_delivery_queue — retries Central DIT callbacks (Rule C: guarantee delivery)
 */

const { getDb } = require('../database/db');
const { decryptPayload, verifyClaim, verifyClaimHs512, encryptPayload } = require('../crypto');
const { isIvsAvailable } = require('../services/ivs-simulator');
const { sendVerification, verifyClaimRemote } = require('../services/ivs-client');
const { postVerificationCallback } = require('../services/central-dit-client');
const { buildCallbackPayload } = require('../services/callback-payload-builder');
const { recordAuditEvent, EventTypes } = require('../audit');
const config = require('../config');

// --- Signature verification helper (mirrors route logic) ---

async function verifyClaimSignature(claim) {
  if (!claim?.signature) return { verified: false, method: 'none' };

  const mode = config.ivs.claimVerifyMode;
  const effectiveMode = mode === 'auto'
    ? (config.ivs.signingKey ? 'local' : config.ivs.mode === 'external' ? 'remote' : 'legacy')
    : mode;

  if (effectiveMode === 'none') return { verified: true, method: 'skipped' };

  if (effectiveMode === 'local') {
    const result = verifyClaimHs512(claim.signature, config.ivs.signingKey);
    return { verified: result.verified, method: 'local_hs512' };
  }

  if (effectiveMode === 'remote') {
    try {
      const ivsResult = await verifyClaimRemote(claim);
      return { verified: ivsResult.verified === true || ivsResult.status === 'valid', method: 'remote_ivs' };
    } catch {
      return { verified: false, method: 'remote_ivs' };
    }
  }

  // Legacy RSA
  const { signature, ...claimWithoutSig } = claim;
  return { verified: verifyClaim(claimWithoutSig, signature), method: 'legacy_rsa' };
}

// --- Worker lifecycle ---

let workerInterval = null;

function startQueueWorker() {
  if (workerInterval) return;

  workerInterval = setInterval(() => {
    processQueue();
    processCallbackQueue();
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

// --- IVS verification queue processing ---

async function processQueue() {
  if (!isIvsAvailable()) return;

  const db = getDb();

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
    const expiredItems = db.prepare("SELECT correlation_id FROM verification_queue WHERE status = 'expired'").all();
    for (const ei of expiredItems) {
      recordAuditEvent(EventTypes.QUEUED_REQUEST_EXPIRED, ei.correlation_id, {});
      db.prepare("UPDATE verification_requests SET status = 'expired', completed_at = datetime('now') WHERE correlation_id = ?").run(ei.correlation_id);
    }
  }
}

async function processQueueItem(item, db) {
  const correlationId = item.correlation_id;

  try {
    let requestJson;
    try {
      requestJson = decryptPayload(item.encrypted_request_payload);
    } catch (decryptErr) {
      console.error(`[Queue Worker] Cannot decrypt payload for ${correlationId} — marking as failed (key mismatch). Set CVG_HMAC_KEY in .env for stable encryption.`);
      db.prepare("UPDATE verification_queue SET status = 'failed' WHERE id = ?").run(item.id);
      db.prepare("UPDATE verification_requests SET status = 'failed', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);
      return;
    }
    const request = JSON.parse(requestJson);

    recordAuditEvent(EventTypes.QUEUED_REQUEST_RETRIED, correlationId, { retry_count: item.retry_count + 1 });

    db.prepare(`
      UPDATE verification_queue SET status = 'retrying', retry_count = retry_count + 1, last_retry_at = datetime('now')
      WHERE id = ?
    `).run(item.id);

    const ivsResponse = await sendVerification(request);

    const verificationStatus = ivsResponse.verification_status
      || ivsResponse.claim?.verification_status
      || ivsResponse.data?.verification_status
      || (ivsResponse.status === 'error' ? 'error' : null);
    const claim = ivsResponse.claim || ivsResponse.data?.claim || null;

    if (ivsResponse.status === 'success' && verificationStatus !== 'registry_unavailable') {
      const sigResult = await verifyClaimSignature(claim);
      const sigVerified = sigResult.verified;

      const finalStatus = verificationStatus || 'unknown';

      db.prepare(`
        INSERT INTO verification_results (correlation_id, verification_status, claim_json, ivs_signature_verified)
        VALUES (?, ?, ?, ?)
      `).run(correlationId, finalStatus, JSON.stringify(claim), sigVerified ? 1 : 0);

      db.prepare("UPDATE verification_queue SET status = 'succeeded' WHERE id = ?").run(item.id);
      db.prepare("UPDATE verification_requests SET status = ?, completed_at = datetime('now') WHERE correlation_id = ?").run(finalStatus, correlationId);

      recordAuditEvent(EventTypes.QUEUED_REQUEST_SUCCEEDED, correlationId, {
        verification_status: finalStatus,
      });

      // NEW: After successful IVS verification from queue, send callback to Central DIT
      const verReq = db.prepare('SELECT * FROM verification_requests WHERE correlation_id = ?').get(correlationId);
      if (verReq?.verification_request_id) {
        await deliverCallbackAfterQueueSuccess(db, {
          verification_request_id: verReq.verification_request_id,
          correlation_id: correlationId,
          gateway_audit_ref: verReq.gateway_audit_ref,
          onebox_id: verReq.onebox_id,
          requesting_assujetti_id: verReq.requesting_assujetti_id,
          verification_status: finalStatus,
          claim,
          signature_verified: sigVerified,
          signature_method: sigResult.method,
        });
      }
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
    db.prepare(`
      UPDATE verification_queue SET status = 'queued', retry_count = retry_count + 1, last_retry_at = datetime('now')
      WHERE id = ?
    `).run(item.id);
  }
}

/**
 * After a queued IVS verification succeeds, deliver the callback to Central DIT.
 * If delivery fails, enqueue it in callback_delivery_queue.
 */
async function deliverCallbackAfterQueueSuccess(db, ctx) {
  const callbackPayload = buildCallbackPayload(ctx);

  recordAuditEvent(EventTypes.CENTRAL_DIT_CALLBACK_ATTEMPTED, ctx.correlation_id, {
    verification_request_id: ctx.verification_request_id,
    source: 'ivs_queue_worker',
  });

  const result = await postVerificationCallback(callbackPayload);

  if (result.success) {
    recordAuditEvent(EventTypes.CENTRAL_DIT_CALLBACK_SUCCEEDED, ctx.correlation_id, {
      verification_request_id: ctx.verification_request_id,
    });
    db.prepare(`
      UPDATE verification_requests SET callback_status = 'delivered', callback_delivered_at = datetime('now')
      WHERE correlation_id = ?
    `).run(ctx.correlation_id);
  } else {
    recordAuditEvent(EventTypes.CENTRAL_DIT_CALLBACK_FAILED, ctx.correlation_id, {
      error: result.error,
    });

    // Enqueue for callback retry
    const { v4: uuidv4 } = require('uuid');
    const id = uuidv4();
    const encryptedPayload = encryptPayload(JSON.stringify(callbackPayload));
    db.prepare(`
      INSERT INTO callback_delivery_queue (id, verification_request_id, correlation_id, payload_encrypted, status, retry_count, next_retry_at, last_error)
      VALUES (?, ?, ?, ?, 'queued', 0, datetime('now', '+1 minutes'), ?)
    `).run(id, ctx.verification_request_id, ctx.correlation_id, encryptedPayload, result.error || null);

    recordAuditEvent(EventTypes.CALLBACK_DELIVERY_QUEUED, ctx.correlation_id, {
      verification_request_id: ctx.verification_request_id,
    });

    db.prepare(`
      UPDATE verification_requests SET callback_status = 'pending_delivery', callback_last_error = ?
      WHERE correlation_id = ?
    `).run(result.error, ctx.correlation_id);
  }
}

// --- Callback delivery queue processing ---

const CALLBACK_MAX_RETRIES = 10;
const CALLBACK_RETRY_SCHEDULE_MINUTES = [1, 2, 5, 15, 30, 60, 120, 240, 480, 720];

async function processCallbackQueue() {
  const db = getDb();

  const items = db.prepare(`
    SELECT * FROM callback_delivery_queue
    WHERE status IN ('queued', 'retrying')
      AND (next_retry_at IS NULL OR next_retry_at <= datetime('now'))
    ORDER BY created_at ASC
    LIMIT 10
  `).all();

  for (const item of items) {
    await processCallbackItem(item, db);
  }
}

async function processCallbackItem(item, db) {
  const { id, correlation_id, verification_request_id } = item;

  if (item.retry_count >= CALLBACK_MAX_RETRIES) {
    db.prepare("UPDATE callback_delivery_queue SET status = 'failed' WHERE id = ?").run(id);
    db.prepare(`
      UPDATE verification_requests SET callback_status = 'failed', callback_last_error = 'Max retries exceeded'
      WHERE correlation_id = ?
    `).run(correlation_id);
    recordAuditEvent(EventTypes.CENTRAL_DIT_CALLBACK_FAILED, correlation_id, {
      reason: 'MAX_RETRIES_EXCEEDED',
      retry_count: item.retry_count,
    });
    return;
  }

  let payloadJson;
  try {
    payloadJson = decryptPayload(item.payload_encrypted);
  } catch (decryptErr) {
    // Encryption key changed (container restart without stable CVG_HMAC_KEY) — mark as permanently failed
    console.error(`[Callback Worker] Cannot decrypt payload for ${correlation_id} — marking as failed (key mismatch). Set CVG_HMAC_KEY in .env for stable encryption.`);
    db.prepare("UPDATE callback_delivery_queue SET status = 'failed', last_error = ? WHERE id = ?")
      .run('Decryption failed: encryption key changed between restarts', id);
    db.prepare("UPDATE verification_requests SET callback_status = 'failed', callback_last_error = ? WHERE correlation_id = ?")
      .run('Payload undecryptable after key rotation', correlation_id);
    recordAuditEvent(EventTypes.CENTRAL_DIT_CALLBACK_FAILED, correlation_id, {
      reason: 'DECRYPTION_FAILED',
      detail: 'Encryption key changed between container restarts',
    });
    return;
  }

  try {
    const payload = JSON.parse(payloadJson);

    recordAuditEvent(EventTypes.CALLBACK_DELIVERY_RETRIED, correlation_id, {
      verification_request_id,
      retry_count: item.retry_count + 1,
    });

    db.prepare(`
      UPDATE callback_delivery_queue SET status = 'retrying', retry_count = retry_count + 1, last_retry_at = datetime('now')
      WHERE id = ?
    `).run(id);

    const result = await postVerificationCallback(payload);

    if (result.success) {
      db.prepare(`
        UPDATE callback_delivery_queue SET status = 'delivered', delivered_at = datetime('now')
        WHERE id = ?
      `).run(id);

      db.prepare(`
        UPDATE verification_requests SET callback_status = 'delivered', callback_delivered_at = datetime('now'), callback_last_error = NULL
        WHERE correlation_id = ?
      `).run(correlation_id);

      recordAuditEvent(EventTypes.CENTRAL_DIT_CALLBACK_SUCCEEDED, correlation_id, {
        verification_request_id,
        retry_count: item.retry_count + 1,
      });
    } else {
      // Schedule next retry
      const nextRetryIdx = Math.min(item.retry_count, CALLBACK_RETRY_SCHEDULE_MINUTES.length - 1);
      const nextRetryMinutes = CALLBACK_RETRY_SCHEDULE_MINUTES[nextRetryIdx];

      db.prepare(`
        UPDATE callback_delivery_queue SET status = 'queued', next_retry_at = datetime('now', '+${nextRetryMinutes} minutes'), last_error = ?
        WHERE id = ?
      `).run(result.error, id);

      db.prepare(`
        UPDATE verification_requests SET callback_last_error = ?
        WHERE correlation_id = ?
      `).run(result.error, correlation_id);
    }
  } catch (err) {
    console.error(`[Callback Worker] Error processing item ${correlation_id}:`, err.message);
    db.prepare(`
      UPDATE callback_delivery_queue SET status = 'queued', retry_count = retry_count + 1, last_retry_at = datetime('now'), last_error = ?
      WHERE id = ?
    `).run(err.message, id);
  }
}

// --- Stats ---

function getQueueStats() {
  const db = getDb();
  const total = db.prepare('SELECT COUNT(*) as count FROM verification_queue').get();
  const byStatus = db.prepare('SELECT status, COUNT(*) as count FROM verification_queue GROUP BY status').all();
  const pending = db.prepare("SELECT COUNT(*) as count FROM verification_queue WHERE status IN ('queued', 'retrying')").get();
  return { total: total.count, pending: pending.count, byStatus };
}

function getCallbackQueueStats() {
  const db = getDb();
  const total = db.prepare('SELECT COUNT(*) as count FROM callback_delivery_queue').get();
  const byStatus = db.prepare('SELECT status, COUNT(*) as count FROM callback_delivery_queue GROUP BY status').all();
  const pending = db.prepare("SELECT COUNT(*) as count FROM callback_delivery_queue WHERE status IN ('queued', 'retrying')").get();
  const failed = db.prepare("SELECT COUNT(*) as count FROM callback_delivery_queue WHERE status = 'failed'").get();
  return { total: total.count, pending: pending.count, failed: failed.count, byStatus };
}

module.exports = { startQueueWorker, stopQueueWorker, processQueue, processCallbackQueue, getQueueStats, getCallbackQueueStats };
