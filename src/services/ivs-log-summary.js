'use strict';

/**
 * Safe log projection for IVS responses.
 *
 * CVG previously dumped the entire IVS response with JSON.stringify at INFO
 * level. That response carries `claim.signature` — the compact signed JWT —
 * which is bearer-grade material and must never reach the logs.
 *
 * This module returns an allow-listed summary: only fields that are useful
 * for operational debugging and are safe to persist in log storage.
 *
 * NEVER add to the allow-list: signature / compact JWT, raw identifier,
 * API keys, signing keys, HMAC material.
 */

/**
 * Build a redacted, allow-listed summary of an IVS response.
 *
 * @param {object} ivsResponse - Raw response object from the IVS client.
 * @param {object} [meta] - Extra safe context (correlation_id, verification_request_id, ...).
 * @returns {object} Summary safe for INFO logging.
 */
function summarizeIvsResponse(ivsResponse, meta = {}) {
  const response = ivsResponse || {};
  const claim = response.claim || response.data?.claim || null;

  const summary = {
    correlation_id:
      meta.correlation_id || response.correlation_id || claim?.correlation_id || null,
    verification_request_id: meta.verification_request_id || null,
    ivs_status: response.status || null,
    verification_status:
      response.verification_status
      || claim?.verification_status
      || response.data?.verification_status
      || null,
    claim_id: claim?.claim_id || null,
    claim_type: claim?.claim_type || null,
    identifier_type: claim?.identifier_type || null,
    issuer_country: claim?.issuer_country || null,
    // Issuer identity: /protect signs as protected_by, /verify as verified_by.
    issuer: claim?.protected_by || claim?.verified_by || null,
    signing_key_version: claim?.signature_key_version || null,
    signature_present: Boolean(claim?.signature),
    response_time_ms: response.response_time_ms ?? null,
  };

  if (response.error || response.error_code) {
    summary.error_code = response.error_code || response.error || null;
  }

  if (Object.prototype.hasOwnProperty.call(meta, 'signature_verified')) {
    summary.signature_verified = meta.signature_verified;
  }

  return summary;
}

module.exports = { summarizeIvsResponse };
