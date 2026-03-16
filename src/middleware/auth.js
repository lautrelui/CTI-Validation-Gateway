const config = require('../config');
const { recordAuditEvent, EventTypes } = require('../audit');

/**
 * Authenticate OneBox callers via API key (X-Api-Key + X-OneBox-Id headers).
 * In production, this would be mTLS + JWT. For dev, API key suffices.
 */
function authenticateOneBox(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  const oneboxId = req.headers['x-onebox-id'];

  if (!apiKey || !oneboxId) {
    return res.status(401).json({
      status: 'error',
      error_code: 'UNAUTHORIZED_CALLER',
      message: 'Missing X-Api-Key or X-OneBox-Id header',
    });
  }

  const caller = config.authorizedCallers[oneboxId];
  if (!caller || caller.apiKey !== apiKey) {
    return res.status(401).json({
      status: 'error',
      error_code: 'UNAUTHORIZED_CALLER',
      message: 'Invalid credentials or unknown OneBox identity',
    });
  }

  // Attach caller info to request
  req.caller = {
    oneboxId,
    assujetti: caller.assujetti,
    name: caller.name,
  };

  next();
}

/**
 * Protect admin/dashboard routes with session auth.
 */
function requireDashboardAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  // For API calls return 401, for browser redirect to login
  if (req.headers.accept && req.headers.accept.includes('text/html')) {
    return res.redirect('/login');
  }
  return res.status(401).json({ error: 'Authentication required' });
}

module.exports = { authenticateOneBox, requireDashboardAuth };
