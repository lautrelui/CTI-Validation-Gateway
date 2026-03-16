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
    // Restore counter from DB
    const db = getDb();
    const row = db.prepare("SELECT COUNT(*) as cnt FROM verification_requests WHERE created_at >= date('now')").get();
    dailyCounter = row.cnt;
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
 * Generate gateway_audit_ref: AUD-CVG-YYYYMMDD-NNNNN
 */
function generateAuditRef() {
  const counter = getNextCounter();
  return `AUD-CVG-${getDateStr()}-${String(counter).padStart(5, '0')}`;
}

/**
 * Generate local verification ref for queued items.
 */
function generateLocalVerificationRef() {
  const counter = getNextCounter();
  return `CVG-VER-${getDateStr()}-${String(counter).padStart(6, '0')}`;
}

module.exports = { generateCorrelationId, generateAuditRef, generateLocalVerificationRef };
