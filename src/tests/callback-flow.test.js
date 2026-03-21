/**
 * CTI-CVG-014: Callback workflow tests.
 *
 * Tests the full Central DIT callback flow using the Express app
 * with an in-memory database and mocked Central DIT / IVS.
 */

const { describe, it, before, after, beforeEach, mock } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');

// --- Test helpers ---

/**
 * Start a tiny HTTP server that captures POSTs and responds.
 * Returns { server, port, calls, setResponse }.
 */
function createMockServer() {
  const state = { calls: [], response: { status: 200, body: { status: 'ok' } } };

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      state.calls.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: body ? JSON.parse(body) : null,
      });
      res.writeHead(state.response.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(state.response.body));
    });
  });

  return {
    server,
    calls: state.calls,
    setResponse(status, body) { state.response = { status, body }; },
    start() {
      return new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => {
          resolve(server.address().port);
        });
      });
    },
    stop() {
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

/**
 * Make an HTTP request to the CVG app.
 */
function request(app, { method = 'POST', path, body, headers = {} }) {
  return new Promise((resolve, reject) => {
    const addr = app.address();
    const payload = body ? JSON.stringify(body) : '';
    const opts = {
      hostname: '127.0.0.1',
      port: addr.port,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        ...headers,
      },
    };

    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// --- Test suite ---

describe('Central DIT Callback Flow', () => {
  let ditMock;
  let ditPort;
  let cvgServer;
  let originalEnv;

  before(async () => {
    // Save env
    originalEnv = { ...process.env };

    // Start mock Central DIT
    ditMock = createMockServer();
    ditPort = await ditMock.start();

    // Configure CVG to use simulator mode + our mock Central DIT
    process.env.IVS_MODE = 'simulator';
    process.env.CENTRAL_DIT_BASE_URL = `http://127.0.0.1:${ditPort}`;
    process.env.CENTRAL_DIT_API_KEY = 'test-dit-key';
    process.env.CVG_QUEUE_ENABLED = 'true';
    process.env.IVS_CLAIM_VERIFY_MODE = 'none'; // skip sig verification in tests (simulator uses RSA)
    process.env.CVG_DB_PATH = ':memory:';

    // Clear module cache to pick up new env
    for (const key of Object.keys(require.cache)) {
      if (key.includes('CTI-Validation-Gateway/src/')) {
        delete require.cache[key];
      }
    }

    // Now require the app fresh
    const { app, start } = require('../server');
    cvgServer = start();
  });

  after(async () => {
    if (cvgServer) cvgServer.close();
    await ditMock.stop();
    // Restore env
    Object.assign(process.env, originalEnv);
  });

  beforeEach(() => {
    ditMock.calls.length = 0;
    ditMock.setResponse(200, { status: 'ok' });
  });

  const verificationBody = {
    verification_request_id: 'vr-test-001',
    identifier: {
      identifier_type: 'NIU',
      raw_value: '1234567890123',
      issuer_country: 'CG',
    },
    request_context: {
      requesting_assujetti_id: 'TEST',
      onebox_id: 'OBX-TEST-01',
      purpose: 'kyc_verification',
    },
  };

  const authHeaders = {
    'X-Api-Key': 'dev-key-test-01',
    'X-OneBox-Id': 'OBX-TEST-01',
  };

  // Case 1: Success — IVS success, Central DIT reachable, callback delivered
  it('should deliver callback to Central DIT and return submitted status', async () => {
    const res = await request(cvgServer, {
      path: '/api/v1/verification/identifiers',
      body: verificationBody,
      headers: authHeaders,
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'submitted');
    assert.ok(res.body.verification_request_id);
    assert.ok(res.body.correlation_id);
    assert.ok(res.body.gateway_audit_ref);

    // Claim should NOT be in the response (Rule A)
    assert.equal(res.body.claim, undefined);

    // Central DIT should have received the callback
    assert.equal(ditMock.calls.length, 1);
    const ditCall = ditMock.calls[0];
    assert.equal(ditCall.method, 'POST');
    assert.ok(ditCall.url.includes('/callbacks/ivs'));
    assert.equal(ditCall.headers['x-api-key'], 'test-dit-key');
    assert.equal(ditCall.body.verification_request_id, 'vr-test-001');
    assert.ok(ditCall.body.claim);
    assert.ok(ditCall.body.correlation_id);
    assert.equal(ditCall.body.gateway_id, 'CVG-CTI-01');
  });

  // Case 2: Central DIT down — callback queued
  it('should queue callback when Central DIT is unreachable', async () => {
    ditMock.setResponse(503, { error: 'Service Unavailable' });

    const res = await request(cvgServer, {
      path: '/api/v1/verification/identifiers',
      body: { ...verificationBody, verification_request_id: 'vr-test-002' },
      headers: authHeaders,
    });

    assert.equal(res.status, 202);
    assert.equal(res.body.status, 'pending_callback_delivery');
    assert.ok(res.body.verification_request_id);
    assert.ok(res.body.correlation_id);

    // Claim should NOT be in the response
    assert.equal(res.body.claim, undefined);

    // Central DIT was called but failed
    assert.equal(ditMock.calls.length, 1);
  });

  // Case 4: Invalid request — missing verification_request_id
  it('should reject requests without verification_request_id', async () => {
    const { verification_request_id, ...bodyWithoutVrId } = verificationBody;

    const res = await request(cvgServer, {
      path: '/api/v1/verification/identifiers',
      body: bodyWithoutVrId,
      headers: authHeaders,
    });

    assert.equal(res.status, 400);
    assert.equal(res.body.error_code, 'INVALID_VERIFICATION_REQUEST_ID');
  });

  // Case: OneBox ID mismatch
  it('should reject requests where X-OneBox-Id does not match request_context.onebox_id', async () => {
    const res = await request(cvgServer, {
      path: '/api/v1/verification/identifiers',
      body: {
        ...verificationBody,
        request_context: {
          ...verificationBody.request_context,
          onebox_id: 'OBX-OTHER-01', // mismatch with header
        },
      },
      headers: authHeaders,
    });

    assert.equal(res.status, 403);
    assert.equal(res.body.error_code, 'ONEBOX_ID_MISMATCH');
  });

  // Health endpoint includes Central DIT
  it('should include Central DIT status in health check', async () => {
    const res = await request(cvgServer, {
      method: 'GET',
      path: '/api/v1/health',
      headers: {},
    });

    assert.equal(res.status === 200 || res.status === 503, true);
    assert.ok(res.body.central_dit);
    assert.equal(res.body.central_dit.configured, true);
    assert.ok(res.body.components.central_dit);
  });
});
