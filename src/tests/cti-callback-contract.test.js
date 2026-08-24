/**
 * CVG -> CTI callback contract tests.
 *
 * CTI's ingestion schema (dit-cti app/models/schemas.py, VerificationClaimIn)
 * is written against the exact payload buildCallbackPayload() produces. A
 * protected-only claim from IVS POST /api/v1/identifiers/protect is
 * structurally different from a verification claim — it carries
 * protected_at / protected_by and names no registry — and CTI normalises those
 * at its own boundary.
 *
 * These tests pin the CVG half of that contract so the shape cannot drift
 * without a failing test here. The matching CTI half lives in
 * dit-cti/tests/test_verification_claim_ingestion.py, against the fixture
 * dit-cti/tests/fixtures/cvg_callback_protected_only.json.
 *
 * Dependency-light on purpose: callback-payload-builder pulls in nothing
 * outside the standard library, so this runs without node_modules.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { buildCallbackPayload } = require('../services/callback-payload-builder');

/** The claim object literal IVS/src/routes/protect.js signs. */
function ivsProtectClaim(overrides = {}) {
  return {
    claim_id: 'ivs-11111111-2222-3333-4444-555555555555',
    claim_type: 'IDENTIFIER_PROTECTED_ONLY',
    verification_status: 'protected_only',
    identifier_type: 'NIU',
    identifier_hmac: 'a'.repeat(64),
    identifier_hmac_key_version: 'v1',
    masked_value: '***4321',
    fingerprint: 'b'.repeat(64),
    issuer_country: 'CG',
    protected_at: '2026-08-24T10:00:00.000Z',
    protected_by: 'IVS-MTN-01',
    normalization_version: 'v1',
    policy_version: 'v1',
    correlation_id: 'corr-protect-001',
    signature: 'eyJhbGciOiJIUzUxMiJ9.PAYLOAD.SIG',
    signature_key_version: 'v1',
    ...overrides,
  };
}

/** The claim object literal IVS/src/services/verification.js signs. */
function ivsVerifyClaim(overrides = {}) {
  return {
    claim_id: 'ivs-99999999-8888-7777-6666-555555555555',
    claim_type: 'IDENTIFIER_VERIFIED',
    verification_status: 'verified',
    identifier_type: 'NIU',
    identifier_hmac: 'a'.repeat(64),
    identifier_hmac_key_version: 'v1',
    masked_value: '***4321',
    fingerprint: 'b'.repeat(64),
    issuer_country: 'CG',
    source_registry: 'IVS-NIU-CG',
    verified_at: '2026-08-24T10:00:00.000Z',
    verified_by: 'IVS-MTN-01',
    normalization_version: 'v1',
    policy_version: 'v1',
    correlation_id: 'corr-001',
    signature: 'eyJhbGciOiJIUzUxMiJ9.PAYLOAD.SIG',
    signature_key_version: 'v1',
    ...overrides,
  };
}

function buildFor(claim, verificationStatus) {
  return buildCallbackPayload({
    verification_request_id: 'vr-protect-001',
    correlation_id: claim.correlation_id,
    gateway_audit_ref: 'audit-001',
    onebox_id: 'OBX-BGFI-01',
    requesting_assujetti_id: 'ASSUJ-BGFI',
    verification_status: verificationStatus,
    claim,
    signature_verified: true,
    signature_method: 'remote',
  });
}

describe('CVG -> CTI callback contract: protected-only claims', () => {
  it('maps the IVS protected_only status onto the Central DIT enum', () => {
    const payload = buildFor(ivsProtectClaim(), 'protected_only');
    assert.equal(payload.verification_status, 'INCONCLUSIVE');
    assert.equal(payload.claim.verification_status, 'INCONCLUSIVE');
  });

  it('preserves the pre-mapping IVS status CTI keys protected-only off', () => {
    const payload = buildFor(ivsProtectClaim(), 'protected_only');
    assert.equal(payload.ivs_original_verification_status, 'protected_only');
    assert.equal(payload.claim.original_verification_status, 'protected_only');
  });

  it('forwards the protect-specific fields CTI normalises from', () => {
    const payload = buildFor(ivsProtectClaim(), 'protected_only');
    assert.equal(payload.claim.protected_at, '2026-08-24T10:00:00.000Z');
    assert.equal(payload.claim.protected_by, 'IVS-MTN-01');
  });

  it('forwards the signed claim_type unchanged', () => {
    const payload = buildFor(ivsProtectClaim(), 'protected_only');
    assert.equal(payload.claim.claim_type, 'IDENTIFIER_PROTECTED_ONLY');
  });

  it('does not invent the verification fields IVS never signed', () => {
    // CVG must not fabricate signed claim fields — normalising the
    // protected-only shape is CTI's job, at its own ingestion boundary.
    const payload = buildFor(ivsProtectClaim(), 'protected_only');
    for (const field of ['source_registry', 'verified_at', 'verified_by']) {
      assert.ok(
        !(field in payload.claim),
        `CVG must not synthesise ${field} into the signed claim`,
      );
    }
  });

  it('passes the signature through byte for byte', () => {
    const claim = ivsProtectClaim();
    const payload = buildFor(claim, 'protected_only');
    assert.equal(payload.claim.signature, claim.signature);
    assert.equal(payload.claim.signature_key_version, claim.signature_key_version);
  });

  it('produces every field CTI VerificationClaimIn requires or reads', () => {
    const payload = buildFor(ivsProtectClaim(), 'protected_only');
    for (const field of [
      'claim_id', 'claim_type', 'verification_status', 'identifier_type',
      'identifier_hmac', 'identifier_hmac_key_version', 'correlation_id',
      'signature', 'signature_key_version', 'issuer_country',
      'protected_at', 'protected_by',
    ]) {
      assert.ok(field in payload.claim, `missing claim field: ${field}`);
    }
    for (const field of [
      'verification_request_id', 'gateway_id', 'processed_at', 'claim',
    ]) {
      assert.ok(field in payload, `missing callback field: ${field}`);
    }
  });
});

describe('CVG -> CTI callback contract: verification claims unchanged', () => {
  it('keeps VERIFIED verbatim and adds no original-status noise', () => {
    const payload = buildFor(ivsVerifyClaim(), 'verified');
    assert.equal(payload.verification_status, 'VERIFIED');
    assert.equal(payload.claim.verification_status, 'VERIFIED');
    assert.ok(!('original_verification_status' in payload.claim));
    assert.ok(!('ivs_original_verification_status' in payload));
  });

  it('keeps the registry fields a verification claim does carry', () => {
    const payload = buildFor(ivsVerifyClaim(), 'verified');
    assert.equal(payload.claim.source_registry, 'IVS-NIU-CG');
    assert.equal(payload.claim.verified_at, '2026-08-24T10:00:00.000Z');
    assert.equal(payload.claim.verified_by, 'IVS-MTN-01');
  });

  it('maps not_found onto the Central DIT enum', () => {
    const claim = ivsVerifyClaim({
      verification_status: 'not_found',
      claim_type: 'IDENTIFIER_CHECK_RESULT',
    });
    const payload = buildFor(claim, 'not_found');
    assert.equal(payload.verification_status, 'NOT_FOUND');
    assert.equal(payload.claim.verification_status, 'NOT_FOUND');
  });

  it('maps registry_unavailable to INCONCLUSIVE and keeps the reason', () => {
    const claim = ivsVerifyClaim({
      verification_status: 'registry_unavailable',
      claim_type: 'IDENTIFIER_CHECK_RESULT',
    });
    const payload = buildFor(claim, 'registry_unavailable');
    assert.equal(payload.claim.verification_status, 'INCONCLUSIVE');
    assert.equal(payload.claim.original_verification_status, 'registry_unavailable');
  });
});
