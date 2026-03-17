/**
 * Correlation ID and audit ref generation per spec section 3.9.
 *
 * Uses a single daily counter so each request gets one increment.
 * The correlation_id, audit_ref, and local_verification_ref for the
 * same request derive from the SAME counter value to avoid collisions.
 */

const { getDb } = require('../database/db');

let dailyCounter = 0;
let lastDate = '';

function getDateStr() {
  const now = new Date();
  return now.toISOString().slice(0, 10).replace(/-/g, '');
}

function getNextCounter() {
  const today = getDateStr();
  if (today !== lastDate) {
    lastDate = today;
    // Restore counter from DB — use the max suffix from existing correlation IDs
    const db = getDb();
    const row = db.prepare(
      "SELECT correlation_id FROM verification_requests WHERE correlation_id LIKE ? ORDER BY correlation_id DESC LIMIT 1"
    ).get(`cvg-${today}-%`);
    if (row) {
      const suffix = parseInt(row.correlation_id.split('-').pop(), 10);
      dailyCounter = isNaN(suffix) ? 0 : suffix;
    } else {
      dailyCounter = 0;
    }
  }
  dailyCounter++;
  return dailyCounter;
}

/**
 * Generate correlation_id: cvg-YYYYMMDD-NNNNNN
 */
function generateCorrelationId() {
  const counter = getNextCounter();
  return `cvg-${getDateStr()}-${String(counter).padStart(6, '0')}`;
}

/**
 * Generate gateway_audit_ref from correlation_id counter.
 * Called AFTER generateCorrelationId() for the same request — reuses
 * the current counter value so we don't burn a second number.
 */
function generateAuditRef() {
  return `AUD-CVG-${getDateStr()}-${String(dailyCounter).padStart(5, '0')}`;
}

/**
 * Generate local verification ref for queued items.
 * Also reuses the current counter value.
 */
function generateLocalVerificationRef() {
  return `CVG-VER-${getDateStr()}-${String(dailyCounter).padStart(6, '0')}`;
}

module.exports = { generateCorrelationId, generateAuditRef, generateLocalVerificationRef };
