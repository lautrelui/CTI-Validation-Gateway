/**
 * Authorized-caller API key fallback safety.
 *
 * The dev-key-* values are published in src/config/index.js. They must be
 * usable in development only — in staging/production an unset caller variable
 * has to leave the slot unauthenticatable rather than live with a key anyone
 * can read out of the repository.
 *
 * No external dependencies: src/config/index.js only needs node builtins.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const CONFIG_PATH = path.join(__dirname, '..', 'config', 'index.js');
const CALLER_VARS = ['OBX_BGFI_API_KEY', 'OBX_UBA_API_KEY', 'OBX_TEST_API_KEY'];
const CALLER_IDS = ['OBX-BGFI-01', 'OBX-UBA-01', 'OBX-TEST-01'];
const DEV_FALLBACKS = ['dev-key-bgfi-01', 'dev-key-uba-01', 'dev-key-test-01'];

let savedEnv;

function loadConfig() {
  delete require.cache[require.resolve(CONFIG_PATH)];
  return require(CONFIG_PATH);
}

beforeEach(() => {
  savedEnv = { NODE_ENV: process.env.NODE_ENV };
  for (const v of CALLER_VARS) {
    savedEnv[v] = process.env[v];
    delete process.env[v];
  }
});

afterEach(() => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  delete require.cache[require.resolve(CONFIG_PATH)];
});

describe('caller API keys outside development', () => {
  for (const env of ['staging', 'production', 'test']) {
    it(`leaves every unset caller slot unusable in NODE_ENV=${env}`, () => {
      process.env.NODE_ENV = env;
      const config = loadConfig();

      for (const id of CALLER_IDS) {
        assert.equal(
          config.authorizedCallers[id].apiKey,
          null,
          `${id} must have no usable key in ${env}`
        );
      }
    });

    it(`never exposes a dev-key-* fallback in NODE_ENV=${env}`, () => {
      process.env.NODE_ENV = env;
      const config = loadConfig();
      const serialized = JSON.stringify(config.authorizedCallers);

      for (const fallback of DEV_FALLBACKS) {
        assert.ok(
          !serialized.includes(fallback),
          `${fallback} must not be reachable in ${env}`
        );
      }
    });
  }

  it('uses the explicitly provisioned key when one is supplied', () => {
    process.env.NODE_ENV = 'staging';
    process.env.OBX_BGFI_API_KEY = 'staging-provisioned-bgfi-key';
    const config = loadConfig();

    assert.equal(config.authorizedCallers['OBX-BGFI-01'].apiKey, 'staging-provisioned-bgfi-key');
    // Slots without an explicit key stay closed.
    assert.equal(config.authorizedCallers['OBX-UBA-01'].apiKey, null);
    assert.equal(config.authorizedCallers['OBX-TEST-01'].apiKey, null);
  });
});

describe('caller API keys in development', () => {
  it('keeps the local convenience fallbacks', () => {
    process.env.NODE_ENV = 'development';
    const config = loadConfig();

    CALLER_IDS.forEach((id, i) => {
      assert.equal(config.authorizedCallers[id].apiKey, DEV_FALLBACKS[i]);
    });
  });

  it('treats an unset NODE_ENV as development', () => {
    delete process.env.NODE_ENV;
    const config = loadConfig();
    assert.equal(config.authorizedCallers['OBX-TEST-01'].apiKey, 'dev-key-test-01');
  });
});

describe('authenticateOneBox rejects unprovisioned slots', () => {
  // src/middleware/auth.js cannot be required here: it pulls in
  // better-sqlite3 via src/audit. Mirror its guard, and assert below that the
  // real source still carries the same condition so the mirror cannot drift.
  function matches(caller, presentedKey) {
    return Boolean(caller && caller.apiKey && caller.apiKey === presentedKey);
  }

  it('mirrors the real middleware guard', () => {
    const source = require('node:fs').readFileSync(
      path.join(__dirname, '..', 'middleware', 'auth.js'),
      'utf8'
    );
    assert.ok(
      source.includes('!caller || !caller.apiKey || caller.apiKey !== apiKey'),
      'auth.js must reject callers whose apiKey is falsy'
    );
  });

  it('rejects the published dev key in staging', () => {
    process.env.NODE_ENV = 'staging';
    const config = loadConfig();

    CALLER_IDS.forEach((id, i) => {
      assert.equal(matches(config.authorizedCallers[id], DEV_FALLBACKS[i]), false);
    });
  });

  it('rejects a null/undefined presented key against a null slot', () => {
    process.env.NODE_ENV = 'staging';
    const config = loadConfig();
    const caller = config.authorizedCallers['OBX-UBA-01'];

    assert.equal(matches(caller, null), false);
    assert.equal(matches(caller, undefined), false);
    assert.equal(matches(caller, ''), false);
    assert.equal(matches(caller, 'null'), false);
  });

  it('accepts a correctly provisioned staging key', () => {
    process.env.NODE_ENV = 'staging';
    process.env.OBX_BGFI_API_KEY = 'a-real-staging-key';
    const config = loadConfig();

    assert.equal(matches(config.authorizedCallers['OBX-BGFI-01'], 'a-real-staging-key'), true);
  });
});
