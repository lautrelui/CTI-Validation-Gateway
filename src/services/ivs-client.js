/**
 * IVS Client - routes verification requests to the correct backend.
 *
 * In "simulator" mode: calls the embedded processVerification() directly.
 * In "external" mode: POSTs to IVS_BASE_URL + config.ivs.verifyPath.
 */

const http = require('http');
const https = require('https');
const config = require('../config');
const { processVerification: simulatorProcess } = require('./ivs-simulator');

const isExternalMode = config.ivs.mode === 'external';

/**
 * Send a verification request to IVS.
 * Returns a Promise that resolves to the IVS response object.
 */
function sendVerification(ivsRequest) {
  if (!isExternalMode) {
    // Simulator mode: synchronous local call wrapped in a resolved promise
    return Promise.resolve(simulatorProcess(ivsRequest));
  }

  // External mode: HTTP POST to real IVS
  return postToIvs(config.ivs.verifyPath, ivsRequest);
}

/**
 * POST JSON to the real IVS and parse the response.
 */
function postToIvs(path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, config.ivs.baseUrl);
    const client = url.protocol === 'https:' ? https : http;
    const payload = JSON.stringify(body);

    const opts = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      timeout: config.ivs.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    };

    const req = client.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve(parsed);
        } catch (e) {
          reject(new Error(`IVS returned invalid JSON (HTTP ${res.statusCode}): ${data.slice(0, 200)}`));
        }
      });
    });

    req.on('error', (err) => {
      reject(new Error(`IVS connection failed: ${err.message}`));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`IVS request timed out after ${config.ivs.timeout}ms`));
    });

    req.write(payload);
    req.end();
  });
}

module.exports = { sendVerification };
