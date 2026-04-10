/**
 * Shared claim signature verification logic.
 *
 * Used by both the synchronous verification route and the queue worker
 * to ensure identical behavior across both paths.
 */

const { verifyClaim, verifyClaimHs512 } = require('../crypto');
const { verifyClaimRemote } = require('./ivs-client');
const config = require('../config');

/**
 * Determine the effective claim verification mode.
 */
function getClaimVerifyMode() {
  const mode = config.ivs.claimVerifyMode;
  if (mode !== 'auto') return mode;
  if (config.ivs.signingKey) return 'local';
  if (config.ivs.mode === 'external') return 'remote';
  return 'legacy';
}

/**
 * Verify the signature on an IVS claim.
 *
 * Returns { verified: boolean, method: string, error?: string }.
 *
 * Remote verification checks `signature_valid` (primary IVS contract),
 * with `verified` accepted as a backward-compatible fallback.
 */
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
      // Primary contract: signature_valid (real IVS POST /api/v1/claims/verify)
      // Backward-compatible fallback: verified, status === 'valid'
      const verified = ivsResult.signature_valid === true
        || ivsResult.verified === true
        || ivsResult.status === 'valid';
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

module.exports = { verifyIvsClaim, getClaimVerifyMode };
