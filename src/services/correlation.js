/**
 * Correlation ID and audit ref generation per spec section 3.9.
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
    // Restore counter from DB — check both correlation IDs and audit refs
    const db = getDb();
    const row = db.prepare(
      "SELECT MAX(id) as max_id FROM verification_requests WHERE created_at >= date('now')"
    ).get();
    // Also check the max correlation_id suffix directly
    const corrRow = db.prepare(
      "SELECT correlation_id FROM verification_requests WHERE correlation_id LIKE ? ORDER BY correlation_id DESC LIMIT 1"
    ).get(`cvg-${today}-%`);
    let maxFromCorr = 0;
    if (corrRow) {
      const suffix = parseInt(corrRow.correlation_id.split('-').pop(), 10);
      if (!isNaN(suffix)) maxFromCorr = suffix;
    }
    // Also check max audit ref suffix to avoid collisions with old data
    const audRow = db.prepare(
      "SELECT gateway_audit_ref FROM verification_requests WHERE gateway_audit_ref LIKE ? ORDER BY gateway_audit_ref DESC LIMIT 1"
    ).get(`AUD-CVG-${today}-%`);
    let maxFromAud = 0;
    if (audRow) {
      const suffix = parseInt(audRow.gateway_audit_ref.split('-').pop(), 10);
      if (!isNaN(suffix)) maxFromAud = suffix;
    }
    dailyCounter = Math.max(maxFromCorr, maxFromAud);
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
 * Derive gateway_audit_ref from the correlation_id.
 * Deterministic 1:1 mapping — no separate counter.
 */
function generateAuditRef(correlationId) {
  // cvg-YYYYMMDD-NNNNNN → AUD-CVG-YYYYMMDD-NNNNNN
  const parts = correlationId.split('-');
  // parts: ['cvg', 'YYYYMMDD', 'NNNNNN']
  return `AUD-CVG-${parts[1]}-${parts[2]}`;
}

/**
 * Generate local verification ref for queued items.
 * Also derived from correlation_id.
 */
function generateLocalVerificationRef(correlationId) {
  const parts = correlationId.split('-');
  return `CVG-VER-${parts[1]}-${parts[2]}`;
}

module.exports = { generateCorrelationId, generateAuditRef, generateLocalVerificationRef };
