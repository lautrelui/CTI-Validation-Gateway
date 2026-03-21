/**
 * CVG Verification API routes per spec section 3.5.
 *
 * NEW ARCHITECTURE: CVG is the delivery guarantor.
 * - After IVS verification + signature validation, CVG posts result to Central DIT.
 * - OneBox receives only a submission acknowledgment (no claim returned).
 * - If Central DIT is unreachable, callback is queued for retry.
 */

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const router = express.Router();
const { getDb } = require('../database/db');
const { authenticateOneBox } = require('../middleware/auth');
const { validateVerificationRequest } = require('../middleware/validate');
const { generateCorrelationId, generateAuditRef, generateLocalVerificationRef } = require('../services/correlation');
const { isIvsAvailable } = require('../services/ivs-simulator');
const { sendVerification, verifyClaimRemote } = require('../services/ivs-client');
const { maskValue, verifyClaim, verifyClaimHs512, encryptPayload } = require('../crypto');
const { postVerificationCallback } = require('../services/central-dit-client');
const { buildCallbackPayload } = require('../services/callback-payload-builder');
const { recordAuditEvent, EventTypes } = require('../audit');
const config = require('../config');

// --- Signature verification helpers (unchanged) ---

function getClaimVerifyMode() {
  const mode = config.ivs.claimVerifyMode;
  if (mode !== 'auto') return mode;
  if (config.ivs.signingKey) return 'local';
  if (config.ivs.mode === 'external') return 'remote';
  return 'legacy';
}

async function verifyIvsClaim(claim) {
  if (!claim?.signature) {
    return { verified: false, method: 'none', error: 'No signature on claim' };
  }

  const mode = getClaimVerifyMode();

  if (mode === 'none') {
    return { verified: true, method: 'skipped' };
  }

  if (mode === 'local') {
    const result = verifyClaimHs512(claim.signature, config.ivs.signingKey);
    return { verified: result.verified, method: 'local_hs512', error: result.error || undefined };
  }

  if (mode === 'remote') {
    try {
      const ivsResult = await verifyClaimRemote(claim);
      const verified = ivsResult.verified === true || ivsResult.status === 'valid';
      return { verified, method: 'remote_ivs', error: verified ? undefined : (ivsResult.error || ivsResult.message) };
    } catch (err) {
      return { verified: false, method: 'remote_ivs', error: err.message };
    }
  }

  // Legacy RSA verification (simulator mode)
  const { signature, ...claimWithoutSig } = claim;
  const verified = verifyClaim(claimWithoutSig, signature);
  return { verified, method: 'legacy_rsa' };
}

// --- Main verification endpoint ---

/**
 * POST /api/v1/verification/identifiers
 */
router.post('/identifiers',
  authenticateOneBox,
  validateVerificationRequest,
  (req, res, next) => {
    handleVerification(req, res).catch(next);
  }
);

async function handleVerification(req, res) {
  const db = getDb();
  const { verification_request_id, identifier, request_context, person_context, options } = req.body;
  const correlationId = generateCorrelationId();
  const gatewayAuditRef = generateAuditRef(correlationId);
  const maskedPreview = maskValue(identifier.raw_value);

  // Audit: request received
  recordAuditEvent(EventTypes.VERIFICATION_REQUEST_RECEIVED, correlationId, {
    verification_request_id,
    identifier_type: identifier.identifier_type,
    masked_value: maskedPreview,
    onebox_id: req.caller.oneboxId,
    assujetti: req.caller.assujetti,
  });

  recordAuditEvent(EventTypes.CALLER_AUTHENTICATED, correlationId, {
    onebox_id: req.caller.oneboxId,
    assujetti: req.caller.assujetti,
  });

  recordAuditEvent(EventTypes.REQUEST_VALIDATED, correlationId, {
    identifier_type: identifier.identifier_type,
    purpose: request_context.purpose,
  });

  recordAuditEvent(EventTypes.CORRELATION_ID_ASSIGNED, correlationId, {
    gateway_audit_ref: gatewayAuditRef,
    verification_request_id,
  });

  // Store the request (now includes verification_request_id)
  db.prepare(`
    INSERT INTO verification_requests (correlation_id, verification_request_id, requesting_assujetti_id, onebox_id, identifier_type, masked_value_preview, status, gateway_audit_ref, local_request_ref, purpose)
    VALUES (?, ?, ?, ?, ?, ?, 'processing', ?, ?, ?)
  `).run(
    correlationId,
    verification_request_id,
    request_context.requesting_assujetti_id,
    req.caller.oneboxId,
    identifier.identifier_type,
    maskedPreview,
    gatewayAuditRef,
    request_context.local_request_ref || null,
    request_context.purpose
  );

  // Check IVS availability
  if (!isIvsAvailable()) {
    const queueAllowed = options?.queue_if_ivs_unavailable !== false && config.queue.enabled;

    if (queueAllowed) {
      return handleQueueRequest(req, res, correlationId, verification_request_id, gatewayAuditRef, identifier, request_context, person_context, options, db);
    }

    recordAuditEvent(EventTypes.IVS_CALL_FAILED, correlationId, { reason: 'IVS_UNAVAILABLE', queued: false });
    db.prepare("UPDATE verification_requests SET status = 'failed', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);

    return res.status(503).json({
      status: 'error',
      error_code: 'IVS_UNAVAILABLE',
      verification_request_id,
      correlation_id: correlationId,
      gateway_audit_ref: gatewayAuditRef,
      message: 'IVS is currently unavailable and queuing is not enabled for this request',
    });
  }

  // Synchronous relay to IVS
  recordAuditEvent(EventTypes.IVS_CALL_ATTEMPTED, correlationId, {});

  const ivsRequest = {
    correlation_id: correlationId,
    verification_request_id,
    identifier: {
      identifier_type: identifier.identifier_type,
      raw_value: identifier.raw_value,
      issuer_country: identifier.issuer_country,
    },
    source_context: {
      requesting_assujetti_id: request_context.requesting_assujetti_id,
      onebox_id: req.caller.oneboxId,
      gateway_id: config.gateway.id,
      local_request_ref: request_context.local_request_ref,
      purpose: request_context.purpose,
    },
    options: {
      return_confirmed_attributes: true,
      allow_protection_without_registry: options?.allow_protection_without_registry || false,
    },
  };

  try {
    const ivsResponse = await sendVerification(ivsRequest);

    // Log the raw IVS response for debugging (external mode)
    if (config.ivs.mode === 'external') {
      console.log(`[CVG] IVS response for ${correlationId}:`, JSON.stringify(ivsResponse, null, 2));
    }

    // Normalize: extract verification_status from wherever the IVS puts it
    const verificationStatus = ivsResponse.verification_status
      || ivsResponse.claim?.verification_status
      || ivsResponse.data?.verification_status
      || (ivsResponse.status === 'error' ? 'error' : null);

    const claim = ivsResponse.claim || ivsResponse.data?.claim || null;

    if (ivsResponse.status === 'error' && ivsResponse.error_code === 'IVS_UNAVAILABLE') {
      const queueAllowed = options?.queue_if_ivs_unavailable !== false && config.queue.enabled;
      if (queueAllowed) {
        return handleQueueRequest(req, res, correlationId, verification_request_id, gatewayAuditRef, identifier, request_context, person_context, options, db);
      }
      recordAuditEvent(EventTypes.IVS_CALL_FAILED, correlationId, { reason: 'IVS_UNAVAILABLE' });
      db.prepare("UPDATE verification_requests SET status = 'failed', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);
      return res.status(503).json({
        status: 'error',
        error_code: 'IVS_UNAVAILABLE',
        verification_request_id,
        correlation_id: correlationId,
        gateway_audit_ref: gatewayAuditRef,
      });
    }

    if (ivsResponse.status === 'error') {
      recordAuditEvent(EventTypes.IVS_CALL_FAILED, correlationId, { error: ivsResponse.error_code });
      db.prepare("UPDATE verification_requests SET status = 'failed', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);
      return res.status(400).json({
        ...ivsResponse,
        verification_request_id,
        correlation_id: correlationId,
        gateway_audit_ref: gatewayAuditRef,
      });
    }

    // IVS call succeeded
    recordAuditEvent(EventTypes.IVS_CALL_SUCCEEDED, correlationId, {
      verification_status: verificationStatus,
    });

    // Verify IVS signature (spec section 3.13)
    const sigResult = await verifyIvsClaim(claim);
    const signatureVerified = sigResult.verified;
    if (claim?.signature && !signatureVerified) {
      recordAuditEvent(EventTypes.IVS_CALL_FAILED, correlationId, {
        reason: 'SIGNATURE_VERIFICATION_FAILED',
        method: sigResult.method,
        error: sigResult.error,
      });
      db.prepare("UPDATE verification_requests SET status = 'signature_failed', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);
      return res.status(502).json({
        status: 'error',
        error_code: 'SIGNATURE_VERIFICATION_FAILED',
        verification_request_id,
        correlation_id: correlationId,
        gateway_audit_ref: gatewayAuditRef,
        message: `IVS claim signature verification failed (${sigResult.method}): ${sigResult.error || 'unknown'}`,
      });
    }

    // Store result
    const finalStatus = verificationStatus || 'unknown';
    db.prepare(`
      INSERT INTO verification_results (correlation_id, verification_status, claim_json, ivs_signature_verified)
      VALUES (?, ?, ?, ?)
    `).run(correlationId, finalStatus, JSON.stringify(claim), signatureVerified ? 1 : 0);

    db.prepare("UPDATE verification_requests SET status = ?, completed_at = datetime('now') WHERE correlation_id = ?")
      .run(finalStatus, correlationId);

    // ========== NEW: Central DIT callback ==========
    // Rule B: CVG must POST the verification result to Central DIT
    const callbackPayload = buildCallbackPayload({
      verification_request_id,
      correlation_id: correlationId,
      gateway_audit_ref: gatewayAuditRef,
      onebox_id: req.caller.oneboxId,
      requesting_assujetti_id: request_context.requesting_assujetti_id,
      verification_status: finalStatus,
      claim,
      signature_verified: signatureVerified,
      signature_method: sigResult.method,
    });

    recordAuditEvent(EventTypes.CENTRAL_DIT_CALLBACK_ATTEMPTED, correlationId, {
      verification_request_id,
    });

    const callbackResult = await postVerificationCallback(callbackPayload);

    if (callbackResult.success) {
      // Callback delivered successfully
      recordAuditEvent(EventTypes.CENTRAL_DIT_CALLBACK_SUCCEEDED, correlationId, {
        verification_request_id,
      });

      db.prepare(`
        UPDATE verification_requests
        SET callback_status = 'delivered', callback_delivered_at = datetime('now')
        WHERE correlation_id = ?
      `).run(correlationId);

      recordAuditEvent(EventTypes.RESPONSE_RETURNED_TO_ONEBOX, correlationId, {
        status: 'submitted',
        callback_delivered: true,
      });

      // Rule A: CVG must NOT return the signed claim to OneBox
      return res.status(200).json({
        status: 'submitted',
        verification_request_id,
        correlation_id: correlationId,
        gateway_audit_ref: gatewayAuditRef,
        message: 'Verification complete. Result delivered to Central DIT.',
      });
    }

    // Callback failed — queue for retry (Rule C: guarantee delivery)
    recordAuditEvent(EventTypes.CENTRAL_DIT_CALLBACK_FAILED, correlationId, {
      error: callbackResult.error,
      retryable: callbackResult.retryable,
    });

    enqueueCallbackDelivery(db, {
      verification_request_id,
      correlation_id: correlationId,
      payload: callbackPayload,
      error: callbackResult.error,
    });

    recordAuditEvent(EventTypes.CALLBACK_DELIVERY_QUEUED, correlationId, {
      verification_request_id,
      reason: callbackResult.error,
    });

    db.prepare(`
      UPDATE verification_requests
      SET callback_status = 'pending_delivery', callback_last_error = ?
      WHERE correlation_id = ?
    `).run(callbackResult.error, correlationId);

    recordAuditEvent(EventTypes.RESPONSE_RETURNED_TO_ONEBOX, correlationId, {
      status: 'pending_callback_delivery',
    });

    // Rule A still applies: no claim returned to OneBox
    return res.status(202).json({
      status: 'pending_callback_delivery',
      verification_request_id,
      correlation_id: correlationId,
      gateway_audit_ref: gatewayAuditRef,
      message: 'Verification complete. Callback to Central DIT queued for delivery.',
    });

  } catch (err) {
    console.error(`[CVG] Verification error for ${correlationId}:`, err.message);
    recordAuditEvent(EventTypes.IVS_CALL_FAILED, correlationId, { error: err.message });
    db.prepare("UPDATE verification_requests SET status = 'error', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);

    return res.status(500).json({
      status: 'error',
      error_code: 'INTERNAL_ERROR',
      verification_request_id,
      correlation_id: correlationId,
      gateway_audit_ref: gatewayAuditRef,
      message: 'Internal gateway error during verification processing',
    });
  }
}

// --- Callback delivery queue helper ---

function enqueueCallbackDelivery(db, { verification_request_id, correlation_id, payload, error }) {
  const id = uuidv4();
  const encryptedPayload = encryptPayload(JSON.stringify(payload));

  db.prepare(`
    INSERT INTO callback_delivery_queue (id, verification_request_id, correlation_id, payload_encrypted, status, retry_count, next_retry_at, last_error)
    VALUES (?, ?, ?, ?, 'queued', 0, datetime('now', '+1 minutes'), ?)
  `).run(id, verification_request_id, correlation_id, encryptedPayload, error || null);
}

// --- IVS queue (unchanged logic, updated to include verification_request_id) ---

function handleQueueRequest(req, res, correlationId, verificationRequestId, gatewayAuditRef, identifier, requestContext, personContext, options, db) {
  const localVerRef = generateLocalVerificationRef(correlationId);

  const ivsRequest = {
    correlation_id: correlationId,
    verification_request_id: verificationRequestId,
    identifier: {
      identifier_type: identifier.identifier_type,
      raw_value: identifier.raw_value,
      issuer_country: identifier.issuer_country,
    },
    source_context: {
      requesting_assujetti_id: requestContext.requesting_assujetti_id,
      onebox_id: req.caller.oneboxId,
      gateway_id: config.gateway.id,
      local_request_ref: requestContext.local_request_ref,
      purpose: requestContext.purpose,
    },
    options: {
      return_confirmed_attributes: true,
      allow_protection_without_registry: options?.allow_protection_without_registry || false,
    },
  };

  const encryptedPayload = encryptPayload(JSON.stringify(ivsRequest));
  const ttlHours = config.queue.defaultTtlHours;

  db.prepare(`
    INSERT INTO verification_queue (correlation_id, encrypted_request_payload, status, next_retry_at, expires_at)
    VALUES (?, ?, 'queued', datetime('now', '+1 minutes'), datetime('now', '+${ttlHours} hours'))
  `).run(correlationId, encryptedPayload);

  db.prepare("UPDATE verification_requests SET status = 'queued' WHERE correlation_id = ?").run(correlationId);

  recordAuditEvent(EventTypes.REQUEST_QUEUED, correlationId, {
    reason: 'IVS_UNAVAILABLE',
    local_verification_ref: localVerRef,
    expires_hours: ttlHours,
  });

  recordAuditEvent(EventTypes.RESPONSE_RETURNED_TO_ONEBOX, correlationId, {
    status: 'pending',
    queued: true,
  });

  return res.status(202).json({
    status: 'pending',
    verification_status: 'queued',
    verification_request_id: verificationRequestId,
    correlation_id: correlationId,
    gateway_audit_ref: gatewayAuditRef,
    reason: 'IVS_UNAVAILABLE',
    local_verification_ref: localVerRef,
  });
}

// --- Status check endpoint ---

/**
 * GET /api/v1/verification/requests/:correlation_id
 */
router.get('/requests/:correlation_id', authenticateOneBox, (req, res) => {
  const db = getDb();
  const { correlation_id } = req.params;

  const request = db.prepare('SELECT * FROM verification_requests WHERE correlation_id = ?').get(correlation_id);
  if (!request) {
    return res.status(404).json({
      status: 'error',
      error_code: 'NOT_FOUND',
      message: 'Verification request not found',
    });
  }

  // Check caller owns this request
  if (request.onebox_id !== req.caller.oneboxId) {
    return res.status(403).json({
      status: 'error',
      error_code: 'UNAUTHORIZED_CALLER',
      message: 'You are not authorized to view this request',
    });
  }

  const result = db.prepare('SELECT * FROM verification_results WHERE correlation_id = ?').get(correlation_id);
  const queueItem = db.prepare('SELECT status, retry_count, next_retry_at, expires_at FROM verification_queue WHERE correlation_id = ?').get(correlation_id);
  const callbackItem = db.prepare('SELECT status, retry_count, next_retry_at, delivered_at, last_error FROM callback_delivery_queue WHERE correlation_id = ?').get(correlation_id);

  const response = {
    status: 'success',
    correlation_id: request.correlation_id,
    verification_request_id: request.verification_request_id,
    gateway_audit_ref: request.gateway_audit_ref,
    verification_status: request.status,
    callback_status: request.callback_status || null,
    identifier_type: request.identifier_type,
    masked_value_preview: request.masked_value_preview,
    created_at: request.created_at,
    completed_at: request.completed_at,
  };

  // Rule A: Do NOT return claim to OneBox. Only return verification metadata.
  if (result) {
    response.ivs_signature_verified = !!result.ivs_signature_verified;
  }

  if (queueItem) {
    response.queue_info = queueItem;
  }

  if (callbackItem) {
    response.callback_info = callbackItem;
  }

  return res.status(200).json(response);
});

module.exports = router;
