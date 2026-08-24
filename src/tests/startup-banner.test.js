/**
 * Startup banner must never print credentials.
 *
 * CVG used to end its boot output with
 *
 *   [CVG] Login credentials: <username> / <password>
 *
 * so the admin password landed in stdout — and therefore in `docker logs`,
 * the host journal, and any log shipper attached to the container — on every
 * single start. Nothing about an operator reading the banner requires the
 * secret to be in it.
 *
 * This pins the invariant at the only place it can regress: the banner
 * builder. src/startup-banner.js has no dependencies beyond the config object
 * it is handed, so this runs on a bare checkout — no listener, no database,
 * no npm install.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const BANNER_PATH = path.join(__dirname, '..', 'startup-banner.js');

/**
 * A config shaped like the real one, with every credential slot filled by a
 * distinctive sentinel. A sentinel appearing in the banner is a leak.
 */
function configWithSentinels() {
  return {
    port: 3010,
    env: 'production',
    db: { path: '/app/data/cvg.db' },
    jwt: { secret: 'SENTINEL-JWT-SECRET', expiresIn: '1h' },
    session: { secret: 'SENTINEL-SESSION-SECRET', maxAge: 3600000 },
    admin: {
      username: 'SENTINEL-ADMIN-USERNAME',
      password: 'SENTINEL-ADMIN-PASSWORD',
    },
    hmac: { key: 'SENTINEL-HMAC-KEY', algorithm: 'sha256', keyVersion: 'v1' },
    signing: {
      algorithm: 'RS256',
      keyVersion: 'v1',
      privateKey: 'SENTINEL-SIGNING-PRIVATE-KEY',
      publicKey: null,
    },
    ivs: {
      baseUrl: 'http://ivs:3011',
      verifyPath: '/api/v1/identifiers/protect',
      claimVerifyPath: '/api/v1/claims/verify',
      apiKey: 'SENTINEL-IVS-API-KEY',
      signingKey: 'SENTINEL-IVS-SIGNING-KEY',
      claimVerifyMode: 'remote',
      timeout: 30000,
      instanceId: 'IVS-MTN-01',
      mode: 'external',
      healthCheckIntervalMs: 15000,
    },
    gateway: { id: 'CVG-CTI-01' },
    centralDit: {
      baseUrl: 'http://cti-api:8000',
      callbackPath: '/api/v1/verification/callbacks/ivs',
      timeout: 5000,
      authMode: 'api_key',
      apiKey: 'SENTINEL-CENTRAL-DIT-API-KEY',
    },
    queue: {
      enabled: true,
      defaultTtlHours: 48,
      retryScheduleMinutes: [1, 5],
      workerIntervalMs: 30000,
    },
    authorizedCallers: {
      'OBX-BGFI-01': { assujetti: 'BGFI', name: 'BGFI Congo', apiKey: 'SENTINEL-CALLER-KEY-BGFI' },
      'OBX-UBA-01': { assujetti: 'UBA', name: 'UBA Congo', apiKey: 'SENTINEL-CALLER-KEY-UBA' },
      'OBX-TEST-01': { assujetti: 'TEST', name: 'Test OneBox', apiKey: 'SENTINEL-CALLER-KEY-TEST' },
    },
  };
}

const SENTINELS = [
  'SENTINEL-JWT-SECRET',
  'SENTINEL-SESSION-SECRET',
  'SENTINEL-ADMIN-USERNAME',
  'SENTINEL-ADMIN-PASSWORD',
  'SENTINEL-HMAC-KEY',
  'SENTINEL-SIGNING-PRIVATE-KEY',
  'SENTINEL-IVS-API-KEY',
  'SENTINEL-IVS-SIGNING-KEY',
  'SENTINEL-CENTRAL-DIT-API-KEY',
  'SENTINEL-CALLER-KEY-BGFI',
  'SENTINEL-CALLER-KEY-UBA',
  'SENTINEL-CALLER-KEY-TEST',
];

describe('CVG startup banner', () => {
  const { startupBanner } = require(BANNER_PATH);
  const banner = startupBanner(configWithSentinels()).join('\n');

  it('exports a banner builder', () => {
    assert.equal(typeof startupBanner, 'function');
    assert.ok(banner.length > 0, 'banner should not be empty');
  });

  for (const sentinel of SENTINELS) {
    it(`does not print ${sentinel}`, () => {
      assert.ok(
        !banner.includes(sentinel),
        `startup banner leaked ${sentinel}:\n${banner}`
      );
    });
  }

  it('does not print a username / password pair', () => {
    assert.ok(
      !/login credentials/i.test(banner),
      'banner still advertises login credentials'
    );
    assert.ok(
      !/password/i.test(banner),
      'banner mentions a password'
    );
  });

  it('still reports that admin authentication is configured', () => {
    assert.match(banner, /admin authentication configured/);
  });

  it('still reports the non-sensitive operational facts', () => {
    assert.match(banner, /CVG-CTI-01/);          // gateway id
    assert.match(banner, /http:\/\/ivs:3011/);   // IVS base url
    assert.match(banner, /http:\/\/cti-api:8000/); // Central DIT base url
    // Caller ids are identities, not credentials — they stay.
    assert.match(banner, /OBX-BGFI-01/);
  });
});
