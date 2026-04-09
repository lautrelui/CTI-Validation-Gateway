/**
 * Callback Payload Builder
 *
 * Builds the payload that CVG sends to Central DIT after IVS verification.
 */

const config = require('../config');

/**
 * Central DIT accepted verification_status enum values.
 * IVS may return other statuses — map them to the closest match.
 */
const CENTRAL_DIT_STATUS_ENUM = ['VERIFIED', 'INVALID', 'NOT_FOUND', 'INCONCLUSIVE', 'ERROR'];

const STATUS_MAP = {
  'REGISTRY_UNAVAILABLE': 'INCONCLUSIVE',
  'PENDING': 'INCONCLUSIVE',
  'UNKNOWN': 'INCONCLUSIVE',
  'TIMEOUT': 'ERROR',
  'FAILED': 'ERROR',
};

function toCentralDitStatus(status) {
  const upper = (status || 'ERROR').toUpperCase();
  if (CENTRAL_DIT_STATUS_ENUM.includes(upper)) return upper;
  return STATUS_MAP[upper] || 'ERROR';
}

/**
 * Build a callback payload for Central DIT.
 */
function buildCallbackPayload(ctx) {
  return {
    verification_request_id: ctx.verification_request_id,
    correlation_id: ctx.correlation_id,
    gateway_id: config.gateway.id,
    gateway_audit_ref: ctx.gateway_audit_ref,
    onebox_id: ctx.onebox_id,
    requesting_assujetti_id: ctx.requesting_assujetti_id,
    verification_status: toCentralDitStatus(ctx.verification_status),
    claim: normalizeClaimStatus(ctx.claim),
    signature_verified: ctx.signature_verified || false,
    signature_method: ctx.signature_method || null,
    processed_at: new Date().toISOString(),
    delivered_at: new Date().toISOString(),
  };
}

/**
 * Normalize claim.verification_status to Central DIT enum.
 */
function normalizeClaimStatus(claim) {
  if (!claim) return null;
  return {
    ...claim,
    verification_status: toCentralDitStatus(claim.verification_status),
  };
}

module.exports = { buildCallbackPayload };
