/**
 * CVG Verification API routes per spec section 3.5.
 */

const express = require('express');
const router = express.Router();
const { getDb } = require('../database/db');
const { authenticateOneBox } = require('../middleware/auth');
const { validateVerificationRequest } = require('../middleware/validate');
const { generateCorrelationId, generateAuditRef, generateLocalVerificationRef } = require('../services/correlation');
const { isIvsAvailable } = require('../services/ivs-simulator');
const { sendVerification } = require('../services/ivs-client');
const { maskValue, verifyClaim, encryptPayload } = require('../crypto');
const { recordAuditEvent, EventTypes } = require('../audit');
const config = require('../config');

/**
 * POST /api/v1/verification/identifiers
 * Main verification endpoint per spec section 3.6.
 */
router.post('/identifiers',
  authenticateOneBox,
  validateVerificationRequest,
  async (req, res) => {
    const db = getDb();
    const { identifier, request_context, person_context, options } = req.body;
    const correlationId = generateCorrelationId();
    const gatewayAuditRef = generateAuditRef();
    const maskedPreview = maskValue(identifier.raw_value);

    // Audit: request received
    recordAuditEvent(EventTypes.VERIFICATION_REQUEST_RECEIVED, correlationId, {
      identifier_type: identifier.identifier_type,
      masked_value: maskedPreview,
      onebox_id: req.caller.oneboxId,
      assujetti: req.caller.assujetti,
    });

    // Audit: caller authenticated
    recordAuditEvent(EventTypes.CALLER_AUTHENTICATED, correlationId, {
      onebox_id: req.caller.oneboxId,
      assujetti: req.caller.assujetti,
    });

    // Audit: request validated
    recordAuditEvent(EventTypes.REQUEST_VALIDATED, correlationId, {
      identifier_type: identifier.identifier_type,
      purpose: request_context.purpose,
    });

    // Audit: correlation assigned
    recordAuditEvent(EventTypes.CORRELATION_ID_ASSIGNED, correlationId, {
      gateway_audit_ref: gatewayAuditRef,
    });

    // Store the request
    db.prepare(`
      INSERT INTO verification_requests (correlation_id, requesting_assujetti_id, onebox_id, identifier_type, masked_value_preview, status, gateway_audit_ref, local_request_ref, purpose)
      VALUES (?, ?, ?, ?, ?, 'processing', ?, ?, ?)
    `).run(
      correlationId,
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
      // Deferred retry path per spec section 3.10
      const queueAllowed = options?.queue_if_ivs_unavailable !== false && config.queue.enabled;

      if (queueAllowed) {
        return handleQueueRequest(req, res, correlationId, gatewayAuditRef, identifier, request_context, person_context, options, db);
      }

      recordAuditEvent(EventTypes.IVS_CALL_FAILED, correlationId, { reason: 'IVS_UNAVAILABLE', queued: false });
      db.prepare("UPDATE verification_requests SET status = 'failed', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);

      return res.status(503).json({
        status: 'error',
        error_code: 'IVS_UNAVAILABLE',
        correlation_id: correlationId,
        gateway_audit_ref: gatewayAuditRef,
        message: 'IVS is currently unavailable and queuing is not enabled for this request',
      });
    }

    // Synchronous relay to IVS
    recordAuditEvent(EventTypes.IVS_CALL_ATTEMPTED, correlationId, {});

    const ivsRequest = {
      correlation_id: correlationId,
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

      // Extract claim from possible wrapper
      const claim = ivsResponse.claim || ivsResponse.data?.claim || null;

      if (ivsResponse.status === 'error' && ivsResponse.error_code === 'IVS_UNAVAILABLE') {
        // IVS became unavailable during processing
        const queueAllowed = options?.queue_if_ivs_unavailable !== false && config.queue.enabled;
        if (queueAllowed) {
          return handleQueueRequest(req, res, correlationId, gatewayAuditRef, identifier, request_context, person_context, options, db);
        }
        recordAuditEvent(EventTypes.IVS_CALL_FAILED, correlationId, { reason: 'IVS_UNAVAILABLE' });
        db.prepare("UPDATE verification_requests SET status = 'failed', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);
        return res.status(503).json({
          status: 'error',
          error_code: 'IVS_UNAVAILABLE',
          correlation_id: correlationId,
          gateway_audit_ref: gatewayAuditRef,
        });
      }

      if (ivsResponse.status === 'error') {
        recordAuditEvent(EventTypes.IVS_CALL_FAILED, correlationId, { error: ivsResponse.error_code });
        db.prepare("UPDATE verification_requests SET status = 'failed', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);
        return res.status(400).json({
          ...ivsResponse,
          correlation_id: correlationId,
          gateway_audit_ref: gatewayAuditRef,
        });
      }

      // IVS call succeeded
      recordAuditEvent(EventTypes.IVS_CALL_SUCCEEDED, correlationId, {
        verification_status: verificationStatus,
      });

      // Verify IVS signature (spec section 3.13)
      let signatureVerified = false;
      if (claim?.signature) {
        const { signature, ...claimWithoutSig } = claim;
        signatureVerified = verifyClaim(claimWithoutSig, signature);
        if (!signatureVerified) {
          recordAuditEvent(EventTypes.IVS_CALL_FAILED, correlationId, { reason: 'SIGNATURE_VERIFICATION_FAILED' });
          db.prepare("UPDATE verification_requests SET status = 'signature_failed', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);
          return res.status(502).json({
            status: 'error',
            error_code: 'SIGNATURE_VERIFICATION_FAILED',
            correlation_id: correlationId,
            gateway_audit_ref: gatewayAuditRef,
            message: 'IVS claim signature verification failed',
          });
        }
      }

      // Store result
      const finalStatus = verificationStatus || 'unknown';
      db.prepare(`
        INSERT INTO verification_results (correlation_id, verification_status, claim_json, ivs_signature_verified)
        VALUES (?, ?, ?, ?)
      `).run(correlationId, finalStatus, JSON.stringify(claim), signatureVerified ? 1 : 0);

      // Update request status
      db.prepare("UPDATE verification_requests SET status = ?, completed_at = datetime('now') WHERE correlation_id = ?")
        .run(finalStatus, correlationId);

      // Audit: response returned
      recordAuditEvent(EventTypes.RESPONSE_RETURNED_TO_ONEBOX, correlationId, {
        verification_status: finalStatus,
        signature_verified: signatureVerified,
      });

      // Return the response per spec section 3.7
      return res.status(200).json({
        status: 'success',
        verification_status: finalStatus,
        correlation_id: correlationId,
        gateway_audit_ref: gatewayAuditRef,
        claim,
      });

    } catch (err) {
      console.error(`[CVG] Verification error for ${correlationId}:`, err.message);
      recordAuditEvent(EventTypes.IVS_CALL_FAILED, correlationId, { error: err.message });
      db.prepare("UPDATE verification_requests SET status = 'error', completed_at = datetime('now') WHERE correlation_id = ?").run(correlationId);

      return res.status(500).json({
        status: 'error',
        error_code: 'INTERNAL_ERROR',
        correlation_id: correlationId,
        gateway_audit_ref: gatewayAuditRef,
        message: 'Internal gateway error during verification processing',
      });
    }
  }
);

/**
 * Handle queuing when IVS is unavailable (spec section 3.8, 3.10).
 */
function handleQueueRequest(req, res, correlationId, gatewayAuditRef, identifier, requestContext, personContext, options, db) {
  const localVerRef = generateLocalVerificationRef();

  // Encrypt the request payload for transient storage
  const ivsRequest = {
    correlation_id: correlationId,
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
    correlation_id: correlationId,
    gateway_audit_ref: gatewayAuditRef,
    reason: 'IVS_UNAVAILABLE',
    local_verification_ref: localVerRef,
  });
}

/**
 * GET /api/v1/verification/requests/:correlation_id
 * Status check endpoint per spec section 3.5.
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

  const response = {
    status: 'success',
    correlation_id: request.correlation_id,
    gateway_audit_ref: request.gateway_audit_ref,
    verification_status: request.status,
    identifier_type: request.identifier_type,
    masked_value_preview: request.masked_value_preview,
    created_at: request.created_at,
    completed_at: request.completed_at,
  };

  if (result) {
    response.claim = result.claim_json ? JSON.parse(result.claim_json) : null;
    response.ivs_signature_verified = !!result.ivs_signature_verified;
  }

  if (queueItem) {
    response.queue_info = queueItem;
  }

  return res.status(200).json(response);
});

module.exports = router;
