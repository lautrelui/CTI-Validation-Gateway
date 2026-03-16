/**
 * Dashboard routes - serves the monitoring GUI.
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const config = require('../config');
const { requireDashboardAuth } = require('../middleware/auth');
const { getPublicKey } = require('../crypto');

/**
 * GET /login - Login page
 */
router.get('/login', (req, res) => {
  if (req.session && req.session.authenticated) {
    return res.redirect('/dashboard');
  }
  res.send(getLoginPage());
});

/**
 * POST /login - Process login
 */
router.post('/login', express.urlencoded({ extended: true }), (req, res) => {
  const { username, password } = req.body;

  if (username === config.admin.username && password === config.admin.password) {
    req.session.authenticated = true;
    req.session.username = username;
    return res.redirect('/dashboard');
  }

  res.send(getLoginPage('Invalid credentials'));
});

/**
 * GET /logout
 */
router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

/**
 * GET /dashboard - Main monitoring page
 */
router.get('/dashboard', requireDashboardAuth, (req, res) => {
  res.send(getDashboardPage());
});

/**
 * GET / - Redirect to dashboard
 */
router.get('/', (req, res) => {
  res.redirect('/dashboard');
});

/**
 * GET /api/v1/trust/public-key - Public key distribution
 */
router.get('/api/v1/trust/public-key', (req, res) => {
  res.json({
    public_key: getPublicKey(),
    key_version: config.signing.keyVersion,
    algorithm: config.signing.algorithm,
  });
});

function getLoginPage(error = null) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CVG - Login</title>
  <link rel="stylesheet" href="/css/dashboard.css">
  <style>
    /* Inline fallback so login always looks correct */
    *{margin:0;padding:0;box-sizing:border-box}
    body.login-body{font-family:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',Roboto,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#0f1117 0%,#161922 50%,#1a1040 100%);color:#e4e6f0;-webkit-font-smoothing:antialiased}
    .login-container{width:100%;max-width:400px;padding:40px;background:#1c1f2e;border-radius:14px;border:1px solid #2a2d3e;box-shadow:0 8px 30px rgba(0,0,0,.4)}
    .login-header{text-align:center;margin-bottom:32px}
    .login-header h1{font-size:22px;font-weight:700;color:#e4e6f0;letter-spacing:-.02em}
    .login-header .subtitle{font-size:14px;color:#8b8fa3;margin-top:4px}
    .logo-icon{display:inline-block;margin-bottom:16px}
    .error-banner{background:rgba(239,68,68,.1);color:#ef4444;padding:12px 16px;border-radius:6px;border:1px solid rgba(239,68,68,.2);margin-bottom:20px;font-size:13px}
    .login-form .form-group{margin-bottom:20px}
    .login-form label{display:block;font-size:13px;font-weight:500;color:#8b8fa3;margin-bottom:6px}
    .login-form input{width:100%;padding:10px 14px;background:#1c1f2e;border:1px solid #2a2d3e;border-radius:6px;color:#e4e6f0;font-size:14px;outline:none;transition:border-color .2s}
    .login-form input:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.15)}
    .login-form input::placeholder{color:#5f6375}
    .btn-primary{width:100%;padding:11px;background:linear-gradient(135deg,#6366f1,#818cf8);color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;transition:all .2s}
    .btn-primary:hover{opacity:.9;transform:translateY(-1px);box-shadow:0 4px 12px rgba(99,102,241,.4)}
    .login-footer{text-align:center;margin-top:24px;font-size:12px;color:#5f6375}
  </style>
</head>
<body class="login-body">
  <div class="login-container">
    <div class="login-header">
      <div class="logo-icon">
        <svg width="48" height="48" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect width="40" height="40" rx="10" fill="url(#grad1)"/>
          <path d="M12 20l5 5 11-11" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
          <defs><linearGradient id="grad1" x1="0" y1="0" x2="40" y2="40"><stop stop-color="#6366f1"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs>
        </svg>
      </div>
      <h1>CTI Verification Gateway</h1>
      <p class="subtitle">Monitoring Dashboard</p>
    </div>
    ${error ? `<div class="error-banner">${error}</div>` : ''}
    <form method="POST" action="/login" class="login-form">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required autofocus placeholder="Enter username">
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required placeholder="Enter password">
      </div>
      <button type="submit" class="btn-primary">Sign In</button>
    </form>
    <div class="login-footer">
      <p>CVG v1.0 &middot; Secure Access Required</p>
    </div>
  </div>
</body>
</html>`;
}

function getDashboardPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CVG - Monitoring Dashboard</title>
  <link rel="stylesheet" href="/css/dashboard.css">
</head>
<body>
  <div class="app-layout">
    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="sidebar-header">
        <div class="logo-icon-sm">
          <svg width="32" height="32" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="url(#g1)"/><path d="M10 16l4 4 8-8" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="g1" x1="0" y1="0" x2="32" y2="32"><stop stop-color="#6366f1"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs></svg>
        </div>
        <span class="sidebar-title">CVG Monitor</span>
      </div>
      <nav class="sidebar-nav">
        <a href="#" class="nav-item active" data-view="overview">
          <svg class="nav-icon" viewBox="0 0 20 20" fill="currentColor"><path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zm0 6a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zm10 0a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z"/></svg>
          Overview
        </a>
        <a href="#" class="nav-item" data-view="requests">
          <svg class="nav-icon" viewBox="0 0 20 20" fill="currentColor"><path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z"/><path fill-rule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z"/></svg>
          Requests
        </a>
        <a href="#" class="nav-item" data-view="queue">
          <svg class="nav-icon" viewBox="0 0 20 20" fill="currentColor"><path d="M5 3a2 2 0 00-2 2v2a2 2 0 002 2h2a2 2 0 002-2V5a2 2 0 00-2-2H5zm0 8a2 2 0 00-2 2v2a2 2 0 002 2h2a2 2 0 002-2v-2a2 2 0 00-2-2H5zm6-6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V5zm0 8a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>
          Queue
        </a>
        <a href="#" class="nav-item" data-view="audit">
          <svg class="nav-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z"/></svg>
          Audit Log
        </a>
        <a href="#" class="nav-item" data-view="test">
          <svg class="nav-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z"/></svg>
          Test Console
        </a>
      </nav>
      <div class="sidebar-footer">
        <a href="/logout" class="nav-item logout-btn">
          <svg class="nav-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 3a1 1 0 00-1 1v12a1 1 0 001 1h5a1 1 0 100-2H4V5h4a1 1 0 100-2H3zm10.293 3.293a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 01-1.414-1.414L14.586 11H7a1 1 0 110-2h7.586l-1.293-1.293a1 1 0 010-1.414z"/></svg>
          Logout
        </a>
      </div>
    </aside>

    <!-- Main Content -->
    <main class="main-content">
      <header class="content-header">
        <h2 id="view-title">Overview</h2>
        <div class="header-actions">
          <div class="ivs-status" id="ivs-status-badge">
            <span class="status-dot"></span>
            <span class="status-text">Checking...</span>
          </div>
          <button class="btn-outline" id="btn-refresh" title="Refresh data">
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16"><path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z"/></svg>
            Refresh
          </button>
          <span class="auto-refresh-label">Auto-refresh: <span id="countdown">30</span>s</span>
        </div>
      </header>

      <!-- Views -->
      <div id="view-overview" class="view active"></div>
      <div id="view-requests" class="view"></div>
      <div id="view-queue" class="view"></div>
      <div id="view-audit" class="view"></div>
      <div id="view-test" class="view"></div>
    </main>
  </div>
  <script src="/js/dashboard.js"></script>
</body>
</html>`;
}

module.exports = router;
