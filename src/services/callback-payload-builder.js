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
  'PROTECTED_ONLY': 'INCONCLUSIVE',
  'PENDING': 'INCONCLUSIVE',
  'UNKNOWN': 'INCONCLUSIVE',
  'TIMEOUT': 'ERROR',
  'FAILED': 'ERROR',
};

function toCentralDitStatus(status) {
  const upper = (status || 'ERROR').toUpperCase();
  if (CENTRAL_DIT_STATUS_ENUM.includes(upper)) return upper;
  return STATUS_MAP[upper] || 'INCONCLUSIVE';
}

/**
 * Build a callback payload for Central DIT.
 *
 * Preserves the original IVS verification status when the mapped
 * Central DIT status differs, so downstream consumers retain the
 * full semantic context.
 */
function buildCallbackPayload(ctx) {
  const mappedStatus = toCentralDitStatus(ctx.verification_status);
  const originalStatus = (ctx.verification_status || '').toLowerCase();
  const statusWasMapped = mappedStatus !== (ctx.verification_status || '').toUpperCase();

  const payload = {
    verification_request_id: ctx.verification_request_id,
    correlation_id: ctx.correlation_id,
    gateway_id: config.gateway.id,
    gateway_audit_ref: ctx.gateway_audit_ref,
    onebox_id: ctx.onebox_id,
    requesting_assujetti_id: ctx.requesting_assujetti_id,
    verification_status: mappedStatus,
    claim: normalizeClaimStatus(ctx.claim),
    signature_verified: ctx.signature_verified || false,
    signature_method: ctx.signature_method || null,
    processed_at: new Date().toISOString(),
    delivered_at: new Date().toISOString(),
  };

  // Preserve original IVS semantic status when it differs from the mapped value
  if (statusWasMapped && originalStatus) {
    payload.ivs_original_verification_status = originalStatus;
  }

  return payload;
}

/**
 * Normalize claim.verification_status to Central DIT enum.
 * Preserves the original IVS status as original_verification_status
 * when mapping changes the value.
 */
function normalizeClaimStatus(claim) {
  if (!claim) return null;
  const mappedStatus = toCentralDitStatus(claim.verification_status);
  const originalStatus = (claim.verification_status || '').toLowerCase();
  const statusWasMapped = mappedStatus !== (claim.verification_status || '').toUpperCase();

  const normalized = {
    ...claim,
    verification_status: mappedStatus,
  };

  if (statusWasMapped && originalStatus) {
    normalized.original_verification_status = originalStatus;
  }

  return normalized;
}

module.exports = { buildCallbackPayload };
