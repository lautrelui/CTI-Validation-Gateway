/**
 * Embedded IVS Simulator.
 * In production, IVS would be a separate MTN-hosted service.
 * This simulator implements the full IVS verification flow per spec section 4.
 */

const { v4: uuidv4 } = require('uuid');
const { getDb } = require('../database/db');
const { generateIdentifierHmac, maskValue, signClaim } = require('../crypto');
const { normalizeIdentifier, validateIdentifierFormat } = require('./normalizer');
const { recordAuditEvent, EventTypes } = require('../audit');
const config = require('../config');

// Simulated registry data (in production, these would be real connector calls)
const MOCK_REGISTRY = {
  NIU: {
    '1234567890123': { full_name: 'JEAN GEOFFRION', date_of_birth: '1980-05-10', status: 'active' },
    '9876543210123': { full_name: 'MARIE DUPONT', date_of_birth: '1992-03-22', status: 'active' },
    '5555555555555': { full_name: 'PAUL MBONGO', date_of_birth: '1975-11-15', status: 'active' },
    '1111111111111': { full_name: 'SOPHIE NGOMA', date_of_birth: '1988-07-01', status: 'active' },
  },
  PASSPORT: {
    'CG1234567': { full_name: 'JEAN GEOFFRION', date_of_birth: '1980-05-10', status: 'active' },
    'CG9876543': { full_name: 'MARIE DUPONT', date_of_birth: '1992-03-22', status: 'active' },
  },
  NID: {
    'NID2024001234': { full_name: 'PIERRE MABALA', date_of_birth: '1970-01-30', status: 'active' },
  },
  DRIVER_LICENSE: {
    'DL2024CG00123': { full_name: 'ALAIN KOUMBA', date_of_birth: '1985-12-10', status: 'active' },
  },
};

// Simulate IVS availability (can be toggled for testing)
let ivsAvailable = true;

function setIvsAvailable(available) {
  ivsAvailable = available;
}

function isIvsAvailable() {
  return ivsAvailable;
}

/**
 * Process a verification request as IVS would.
 * Implements the full flow: normalize → validate → connector lookup → HMAC → sign claim.
 */
function processVerification(request) {
  const { correlation_id, identifier, source_context, options } = request;
  const db = getDb();

  if (!ivsAvailable) {
    return { status: 'error', error_code: 'IVS_UNAVAILABLE', message: 'IVS is currently unavailable' };
  }

  // Record IVS request
  recordAuditEvent(EventTypes.VERIFY_REQUEST_RECEIVED, correlation_id, {
    identifier_type: identifier.identifier_type,
    issuer_country: identifier.issuer_country,
    gateway_id: source_context?.gateway_id,
  });

  const ivsReqStmt = db.prepare(`
    INSERT INTO ivs_verification_requests (correlation_id, identifier_type, issuer_country, request_status, source_context_json)
    VALUES (?, ?, ?, 'processing', ?)
  `);
  const ivsReqResult = ivsReqStmt.run(
    correlation_id,
    identifier.identifier_type,
    identifier.issuer_country,
    JSON.stringify(source_context)
  );
  const ivsRequestId = ivsReqResult.lastInsertRowid;

  // Step 1: Normalize
  const normResult = normalizeIdentifier(identifier.identifier_type, identifier.raw_value, identifier.issuer_country);
  recordAuditEvent(EventTypes.IDENTIFIER_NORMALIZED, correlation_id, {
    identifier_type: identifier.identifier_type,
    normalization_version: normResult.normalization_version,
    notes: normResult.normalization_notes,
  });

  // Step 2: Validate format
  const formatCheck = validateIdentifierFormat(identifier.identifier_type, normResult.normalized_value, identifier.issuer_country);
  if (!formatCheck.valid) {
    recordAuditEvent(EventTypes.VERIFY_REJECTED_INVALID_FORMAT, correlation_id, { reason: formatCheck.reason });
    db.prepare("UPDATE ivs_verification_requests SET request_status = 'rejected', completed_at = datetime('now') WHERE id = ?").run(ivsRequestId);
    return {
      status: 'error',
      verification_status: 'invalid',
      error_code: 'INVALID_IDENTIFIER_FORMAT',
      message: formatCheck.reason,
      correlation_id,
    };
  }

  // Step 3: Connector lookup
  const connectorName = `${identifier.identifier_type}_CONNECTOR`;
  const startedAt = new Date().toISOString();
  recordAuditEvent(EventTypes.CONNECTOR_CALL_STARTED, correlation_id, { connector: connectorName });

  const registry = MOCK_REGISTRY[identifier.identifier_type] || {};
  const registryResult = registry[normResult.normalized_value];

  // Record connector audit
  const connStatus = registryResult ? 'success' : 'not_found';
  db.prepare(`
    INSERT INTO ivs_connector_audit (request_id, connector_name, connector_status, started_at, ended_at, details_json)
    VALUES (?, ?, ?, ?, datetime('now'), ?)
  `).run(ivsRequestId, connectorName, connStatus, startedAt, JSON.stringify({ lookup_key_masked: maskValue(normResult.normalized_value) }));

  if (connStatus === 'success') {
    recordAuditEvent(EventTypes.CONNECTOR_CALL_SUCCEEDED, correlation_id, { connector: connectorName });
  } else {
    recordAuditEvent(EventTypes.CONNECTOR_CALL_FAILED, correlation_id, { connector: connectorName, reason: 'not_found' });
  }

  if (!registryResult) {
    // Check if protection-only fallback is allowed
    if (options?.allow_protection_without_registry) {
      return buildProtectedOnlyClaim(correlation_id, identifier, normResult, ivsRequestId, db);
    }

    recordAuditEvent(EventTypes.VERIFY_RESULT_NOT_FOUND, correlation_id, { identifier_type: identifier.identifier_type });
    db.prepare("UPDATE ivs_verification_requests SET request_status = 'not_found', completed_at = datetime('now') WHERE id = ?").run(ivsRequestId);

    return {
      status: 'success',
      verification_status: 'not_found',
      correlation_id,
      claim: null,
      message: 'No authoritative record found for the provided identifier',
    };
  }

  // Step 4: Generate protected representation
  const identifierHmac = generateIdentifierHmac(identifier.identifier_type, identifier.issuer_country, normResult.normalized_value);
  const maskedValue = maskValue(normResult.normalized_value);

  // Step 5: Build and sign claim
  const claimId = `ivs-claim-${uuidv4()}`;
  const claimPayload = {
    claim_id: claimId,
    claim_type: 'IDENTIFIER_VERIFIED',
    verification_status: 'verified',
    identifier_type: identifier.identifier_type,
    identifier_hmac: identifierHmac,
    masked_value: maskedValue,
    issuer_country: identifier.issuer_country,
    source_registry: identifier.identifier_type,
    verified_at: new Date().toISOString(),
    verified_by: config.ivs.instanceId,
    confirmed_attributes: options?.return_confirmed_attributes !== false ? registryResult : undefined,
    normalization_version: normResult.normalization_version,
    policy_version: 'v1',
    correlation_id,
    key_version: config.hmac.keyVersion,
    signature_key_version: config.signing.keyVersion,
  };

  const signature = signClaim(claimPayload);
  claimPayload.signature = signature;

  // Record result
  recordAuditEvent(EventTypes.CLAIM_ISSUED_VERIFIED, correlation_id, {
    claim_id: claimId,
    identifier_type: identifier.identifier_type,
    masked_value: maskedValue,
  });

  db.prepare(`
    INSERT INTO ivs_verification_results (request_id, verification_status, identifier_hmac, masked_value, source_registry, confirmed_attributes_json, claim_id, signature_key_version)
    VALUES (?, 'verified', ?, ?, ?, ?, ?, ?)
  `).run(ivsRequestId, identifierHmac, maskedValue, identifier.identifier_type, JSON.stringify(registryResult), claimId, config.signing.keyVersion);

  db.prepare("UPDATE ivs_verification_requests SET request_status = 'verified', completed_at = datetime('now') WHERE id = ?").run(ivsRequestId);

  return {
    status: 'success',
    verification_status: 'verified',
    claim: claimPayload,
    correlation_id,
  };
}

function buildProtectedOnlyClaim(correlationId, identifier, normResult, ivsRequestId, db) {
  const identifierHmac = generateIdentifierHmac(identifier.identifier_type, identifier.issuer_country, normResult.normalized_value);
  const maskedValue = maskValue(normResult.normalized_value);
  const claimId = `ivs-claim-${uuidv4()}`;

  const claimPayload = {
    claim_id: claimId,
    claim_type: 'IDENTIFIER_PROTECTED_ONLY',
    verification_status: 'protected_only',
    identifier_type: identifier.identifier_type,
    identifier_hmac: identifierHmac,
    masked_value: maskedValue,
    issuer_country: identifier.issuer_country,
    verified_at: new Date().toISOString(),
    verified_by: config.ivs.instanceId,
    normalization_version: normResult.normalization_version,
    policy_version: 'v1',
    correlation_id: correlationId,
    key_version: config.hmac.keyVersion,
    signature_key_version: config.signing.keyVersion,
  };

  const signature = signClaim(claimPayload);
  claimPayload.signature = signature;

  recordAuditEvent(EventTypes.CLAIM_ISSUED_PROTECTED_ONLY, correlationId, { claim_id: claimId });

  db.prepare(`
    INSERT INTO ivs_verification_results (request_id, verification_status, identifier_hmac, masked_value, source_registry, claim_id, signature_key_version)
    VALUES (?, 'protected_only', ?, ?, ?, ?, ?)
  `).run(ivsRequestId, identifierHmac, maskedValue, identifier.identifier_type, claimId, config.signing.keyVersion);

  db.prepare("UPDATE ivs_verification_requests SET request_status = 'protected_only', completed_at = datetime('now') WHERE id = ?").run(ivsRequestId);

  return {
    status: 'success',
    verification_status: 'protected_only',
    claim: claimPayload,
    correlation_id: correlationId,
  };
}

module.exports = { processVerification, setIvsAvailable, isIvsAvailable };
