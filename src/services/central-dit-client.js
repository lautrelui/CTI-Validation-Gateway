/**
 * Central DIT Callback Client
 *
 * Posts verification results to the Central DIT endpoint.
 * Handles timeouts, errors, and returns clear success/failure.
 */

const http = require('http');
const https = require('https');
const config = require('../config');

// Track reachability for health check
let lastSuccess = null;
let lastFailure = null;

/**
 * POST a verification callback payload to Central DIT.
 * Returns { success: true } or { success: false, error, retryable }.
 */
async function postVerificationCallback(payload) {
  const { baseUrl, callbackPath, timeout, apiKey } = config.centralDit;

  if (!baseUrl) {
    return { success: false, error: 'CENTRAL_DIT_BASE_URL not configured', retryable: false };
  }

  return new Promise((resolve) => {
    try {
      const url = new URL(callbackPath, baseUrl);
      const client = url.protocol === 'https:' ? https : http;
      const body = JSON.stringify(payload);

      const opts = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        timeout,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          ...(apiKey ? { 'X-Api-Key': apiKey } : {}),
        },
      };

      const req = client.request(opts, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            lastSuccess = new Date().toISOString();
            resolve({ success: true });
          } else {
            lastFailure = new Date().toISOString();
            // 4xx = not retryable (except 429), 5xx = retryable
            const retryable = res.statusCode >= 500 || res.statusCode === 429;
            resolve({
              success: false,
              error: `HTTP ${res.statusCode}: ${data.slice(0, 200)}`,
              retryable,
            });
          }
        });
      });

      req.on('error', (err) => {
        lastFailure = new Date().toISOString();
        resolve({ success: false, error: `Connection failed: ${err.message}`, retryable: true });
      });

      req.on('timeout', () => {
        req.destroy();
        lastFailure = new Date().toISOString();
        resolve({ success: false, error: `Timeout after ${timeout}ms`, retryable: true });
      });

      req.write(body);
      req.end();
    } catch (err) {
      lastFailure = new Date().toISOString();
      resolve({ success: false, error: `Unexpected: ${err.message}`, retryable: false });
    }
  });
}

/**
 * Get Central DIT reachability status for health checks.
 */
function getCentralDitStatus() {
  return {
    configured: !!config.centralDit.baseUrl,
    last_success: lastSuccess,
    last_failure: lastFailure,
  };
}

module.exports = { postVerificationCallback, getCentralDitStatus };
