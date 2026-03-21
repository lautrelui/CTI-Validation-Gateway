const { getDb } = require('../database/db');

// Audit event types from spec section 3.12 and 4.15
const EventTypes = {
  // CVG events
  VERIFICATION_REQUEST_RECEIVED: 'VERIFICATION_REQUEST_RECEIVED',
  CALLER_AUTHENTICATED: 'CALLER_AUTHENTICATED',
  REQUEST_VALIDATED: 'REQUEST_VALIDATED',
  CORRELATION_ID_ASSIGNED: 'CORRELATION_ID_ASSIGNED',
  IVS_CALL_ATTEMPTED: 'IVS_CALL_ATTEMPTED',
  IVS_CALL_SUCCEEDED: 'IVS_CALL_SUCCEEDED',
  IVS_CALL_FAILED: 'IVS_CALL_FAILED',
  REQUEST_QUEUED: 'REQUEST_QUEUED',
  QUEUED_REQUEST_RETRIED: 'QUEUED_REQUEST_RETRIED',
  QUEUED_REQUEST_SUCCEEDED: 'QUEUED_REQUEST_SUCCEEDED',
  QUEUED_REQUEST_EXPIRED: 'QUEUED_REQUEST_EXPIRED',
  RESPONSE_RETURNED_TO_ONEBOX: 'RESPONSE_RETURNED_TO_ONEBOX',
  CENTRAL_DIT_CALLBACK_ATTEMPTED: 'CENTRAL_DIT_CALLBACK_ATTEMPTED',
  CENTRAL_DIT_CALLBACK_SUCCEEDED: 'CENTRAL_DIT_CALLBACK_SUCCEEDED',
  CENTRAL_DIT_CALLBACK_FAILED: 'CENTRAL_DIT_CALLBACK_FAILED',
  CALLBACK_DELIVERY_QUEUED: 'CALLBACK_DELIVERY_QUEUED',
  CALLBACK_DELIVERY_RETRIED: 'CALLBACK_DELIVERY_RETRIED',

  // IVS events
  VERIFY_REQUEST_RECEIVED: 'VERIFY_REQUEST_RECEIVED',
  IDENTIFIER_NORMALIZED: 'IDENTIFIER_NORMALIZED',
  CONNECTOR_CALL_STARTED: 'CONNECTOR_CALL_STARTED',
  CONNECTOR_CALL_SUCCEEDED: 'CONNECTOR_CALL_SUCCEEDED',
  CONNECTOR_CALL_FAILED: 'CONNECTOR_CALL_FAILED',
  CLAIM_ISSUED_VERIFIED: 'CLAIM_ISSUED_VERIFIED',
  CLAIM_ISSUED_PROTECTED_ONLY: 'CLAIM_ISSUED_PROTECTED_ONLY',
  VERIFY_REJECTED_INVALID_FORMAT: 'VERIFY_REJECTED_INVALID_FORMAT',
  VERIFY_RESULT_NOT_FOUND: 'VERIFY_RESULT_NOT_FOUND',
  VERIFY_RESULT_INCONCLUSIVE: 'VERIFY_RESULT_INCONCLUSIVE',
};

/**
 * Record an immutable audit event.
 * Per spec: never log raw identifiers.
 */
function recordAuditEvent(eventType, correlationId, details = {}, entityType = null, entityId = null) {
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO audit_events (event_type, correlation_id, entity_type, entity_id, details_json, created_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
  `);
  stmt.run(eventType, correlationId, entityType, entityId, JSON.stringify(details));
}

/**
 * Get audit events, optionally filtered.
 */
function getAuditEvents({ correlationId, eventType, limit = 100, offset = 0 } = {}) {
  const db = getDb();
  let query = 'SELECT * FROM audit_events WHERE 1=1';
  const params = [];

  if (correlationId) {
    query += ' AND correlation_id = ?';
    params.push(correlationId);
  }
  if (eventType) {
    query += ' AND event_type = ?';
    params.push(eventType);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  return db.prepare(query).all(...params);
}

function getAuditStats() {
  const db = getDb();
  const total = db.prepare('SELECT COUNT(*) as count FROM audit_events').get();
  const byType = db.prepare('SELECT event_type, COUNT(*) as count FROM audit_events GROUP BY event_type ORDER BY count DESC').all();
  const last24h = db.prepare("SELECT COUNT(*) as count FROM audit_events WHERE created_at >= datetime('now', '-1 day')").get();
  return { total: total.count, last24h: last24h.count, byType };
}

module.exports = { EventTypes, recordAuditEvent, getAuditEvents, getAuditStats };
