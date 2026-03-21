/**
 * Callback Payload Builder
 *
 * Builds the payload that CVG sends to Central DIT after IVS verification.
 */

const config = require('../config');

/**
 * Build a callback payload for Central DIT.
 *
 * @param {object} ctx
 * @param {string} ctx.verification_request_id - Central DIT's request ID
 * @param {string} ctx.correlation_id - CVG correlation ID
 * @param {string} ctx.gateway_audit_ref - CVG audit reference
 * @param {string} ctx.onebox_id - Originating OneBox ID
 * @param {string} ctx.requesting_assujetti_id - Assujetti ID
 * @param {string} ctx.verification_status - IVS verification result
 * @param {object|null} ctx.claim - Signed claim from IVS
 * @param {boolean} ctx.signature_verified - Whether CVG verified the claim signature
 * @param {string} ctx.signature_method - Method used to verify (local_hs512, remote_ivs, etc.)
 * @returns {object} Callback payload matching Central DIT spec
 */
function buildCallbackPayload(ctx) {
  return {
    verification_request_id: ctx.verification_request_id,
    correlation_id: ctx.correlation_id,
    gateway_id: config.gateway.id,
    gateway_audit_ref: ctx.gateway_audit_ref,
    onebox_id: ctx.onebox_id,
    requesting_assujetti_id: ctx.requesting_assujetti_id,
    verification_status: ctx.verification_status?.toUpperCase(),
    claim: normalizeClaimStatus(ctx.claim),
    signature_verified: ctx.signature_verified || false,
    signature_method: ctx.signature_method || null,
    delivered_at: new Date().toISOString(),
  };
}

/**
 * Central DIT expects verification_status as uppercase enum.
 * The IVS simulator returns lowercase — normalize before sending.
 */
function normalizeClaimStatus(claim) {
  if (!claim) return null;
  return {
    ...claim,
    verification_status: claim.verification_status?.toUpperCase(),
  };
}

module.exports = { buildCallbackPayload };
