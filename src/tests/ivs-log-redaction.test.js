/**
 * IVS response logging must never contain the compact signed JWT.
 *
 * CVG used to log the whole IVS response at INFO level:
 *
 *   console.log(`[CVG] IVS response for ${id}:`, JSON.stringify(ivsResponse, null, 2))
 *
 * That object carries `claim.signature` — the compact signed JWT IVS issues —
 * so bearer-grade material landed in stdout, `docker logs`, and any attached
 * log shipper on every external-mode verification. Confirmed on the
 * protect-only E2E run 001.
 *
 * This pins the invariant at the log projection itself.
 * src/services/ivs-log-summary.js has no dependencies, so this runs on a bare
 * checkout — no listener, no database, no npm install.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { summarizeIvsResponse } = require('../services/ivs-log-summary');

/** A distinctive compact JWT. Its appearance anywhere in output is a leak. */
const SENTINEL_JWT =
  'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.SENTINEL-JWT-PAYLOAD.SENTINEL-JWT-SIGNATURE';

const SENTINEL_RAW_NIU = 'SENTINEL-RAW-NIU-1234567890';
const SENTINEL_HMAC_KEY = 'SENTINEL-HMAC-SIGNING-KEY';
const SENTINEL_API_KEY = 'SENTINEL-IVS-API-KEY';

/** Shaped like the real IVS /protect response observed in run 001. */
function protectOnlyResponse() {
  return {
    status: 'success',
    claim: {
      claim_id: 'ivs-4685e524-b260-4bfb-b946-e04bac770109',
      claim_type: 'IDENTIFIER_PROTECTED_ONLY',
      verification_status: 'protected_only',
      identifier_type: 'NIU',
      identifier_hmac:
        '56d8d23f1a4db554dd78854c3e6846f6b70855bdea691270989208690b5ea1c3',
      identifier_hmac_key_version: 'v1',
      masked_value: '*************0001',
      fingerprint: '672473961ad1dcde',
      issuer_country: 'CG',
      protected_at: '2026-08-24T19:57:18.147Z',
      protected_by: 'IVS-MTN-01',
      normalization_version: 'v1',
      policy_version: 'v1',
      correlation_id: 'cvg-20260824-000001',
      signature: SENTINEL_JWT,
      signature_key_version: 'v1',
      // Fields IVS does not send, planted here to prove the summary is an
      // allow-list rather than a deny-list.
      raw_identifier: SENTINEL_RAW_NIU,
      signing_key: SENTINEL_HMAC_KEY,
      api_key: SENTINEL_API_KEY,
    },
    correlation_id: 'cvg-20260824-000001',
    response_time_ms: 2,
  };
}

/** Render exactly as the route does, so the assertion covers real output. */
function rendered(summary) {
  return JSON.stringify(summary);
}

describe('summarizeIvsResponse — secret redaction', () => {
  it('omits the compact signed JWT', () => {
    const output = rendered(
      summarizeIvsResponse(protectOnlyResponse(), {
        correlation_id: 'cvg-20260824-000001',
        verification_request_id: 'vreq-test-0001',
      }),
    );

    assert.ok(
      !output.includes(SENTINEL_JWT),
      'rendered log output must not contain the compact signed JWT',
    );
    // Also guard against a truncated-but-still-usable prefix leaking.
    assert.ok(
      !/eyJ[A-Za-z0-9_-]{4,}/.test(output),
      'rendered log output must not contain any compact JWT fragment',
    );
  });

  it('omits raw identifier, signing keys, and API keys', () => {
    const output = rendered(summarizeIvsResponse(protectOnlyResponse()));

    for (const secret of [SENTINEL_RAW_NIU, SENTINEL_HMAC_KEY, SENTINEL_API_KEY]) {
      assert.ok(!output.includes(secret), `rendered output leaked ${secret}`);
    }
  });

  it('omits HMAC material and masked identifier digits', () => {
    const summary = summarizeIvsResponse(protectOnlyResponse());

    assert.ok(!('identifier_hmac' in summary), 'must not carry identifier_hmac');
    assert.ok(!('masked_value' in summary), 'must not carry masked_value');
    assert.ok(!('signature' in summary), 'must not carry signature');
  });

  it('never carries a signature field even when nested under data.claim', () => {
    const nested = {
      status: 'success',
      data: { claim: { verification_status: 'verified', signature: SENTINEL_JWT } },
    };
    const output = rendered(summarizeIvsResponse(nested));

    assert.ok(!output.includes(SENTINEL_JWT), 'nested claim signature leaked');
    assert.equal(summarizeIvsResponse(nested).verification_status, 'verified');
  });
});

describe('summarizeIvsResponse — operational fields preserved', () => {
  it('keeps the fields operators need to debug a verification', () => {
    const summary = summarizeIvsResponse(protectOnlyResponse(), {
      correlation_id: 'cvg-20260824-000001',
      verification_request_id: 'vreq-test-0001',
      signature_verified: true,
    });

    assert.equal(summary.correlation_id, 'cvg-20260824-000001');
    assert.equal(summary.verification_request_id, 'vreq-test-0001');
    assert.equal(summary.claim_type, 'IDENTIFIER_PROTECTED_ONLY');
    assert.equal(summary.verification_status, 'protected_only');
    assert.equal(summary.issuer, 'IVS-MTN-01');
    assert.equal(summary.signing_key_version, 'v1');
    assert.equal(summary.signature_verified, true);
    // Signature presence is still observable — just not its value.
    assert.equal(summary.signature_present, true);
    assert.equal(summary.identifier_type, 'NIU');
    assert.equal(summary.issuer_country, 'CG');
    assert.equal(summary.claim_id, 'ivs-4685e524-b260-4bfb-b946-e04bac770109');
  });

  it('resolves the issuer from verified_by on the /verify path', () => {
    const summary = summarizeIvsResponse({
      status: 'success',
      claim: {
        claim_type: 'IDENTITY_VERIFICATION',
        verification_status: 'verified',
        verified_by: 'IVS-MTN-01',
        signature: SENTINEL_JWT,
        signature_key_version: 'v2',
      },
    });

    assert.equal(summary.issuer, 'IVS-MTN-01');
    assert.equal(summary.signing_key_version, 'v2');
    assert.ok(!rendered(summary).includes(SENTINEL_JWT));
  });

  it('surfaces IVS error codes without dumping the response', () => {
    const summary = summarizeIvsResponse({
      error: 'UNAUTHORIZED',
      message: 'bad key',
      api_key: SENTINEL_API_KEY,
    });

    assert.equal(summary.error_code, 'UNAUTHORIZED');
    assert.ok(!rendered(summary).includes(SENTINEL_API_KEY));
  });

  it('omits signature_verified when the caller has not computed it yet', () => {
    const summary = summarizeIvsResponse(protectOnlyResponse(), {
      correlation_id: 'cvg-20260824-000001',
    });

    assert.ok(!('signature_verified' in summary));
  });

  it('tolerates a null or empty response without throwing', () => {
    assert.doesNotThrow(() => summarizeIvsResponse(null));
    assert.doesNotThrow(() => summarizeIvsResponse(undefined));
    assert.equal(summarizeIvsResponse(null).signature_present, false);
  });
});

describe('verification route log call sites', () => {
  it('never stringifies the whole IVS response', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const source = fs.readFileSync(
      path.join(__dirname, '..', 'routes', 'verification.js'),
      'utf8',
    );

    assert.ok(
      !/JSON\.stringify\(\s*ivsResponse\s*[,)]/.test(source),
      'verification.js must not JSON.stringify(ivsResponse) — use summarizeIvsResponse',
    );
  });
});
