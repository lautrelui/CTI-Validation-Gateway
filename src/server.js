/**
 * CTI Verification Gateway (CVG) - Main Server
 *
 * Secure relay and control layer for identifier verification between
 * OneBox, CTI zone, and MTN IVS.
 */

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');

const config = require('./config');
const { startupBanner } = require('./startup-banner');
const { getDb, closeDb } = require('./database/db');
const { startQueueWorker, stopQueueWorker } = require('./queue/worker');
const { startIvsHealthCheck, stopIvsHealthCheck } = require('./services/ivs-simulator');

// Routes
const verificationRoutes = require('./routes/verification');
const healthRoutes = require('./routes/health');
const adminRoutes = require('./routes/admin');
const dashboardRoutes = require('./routes/dashboard');

const app = express();

// --- Security ---
app.use(helmet({
  contentSecurityPolicy: false, // CSP handled inline; dashboard is internal-only
  crossOriginEmbedderPolicy: false,
}));

// --- Rate limiting ---
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', error_code: 'RATE_LIMITED', message: 'Too many requests' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { status: 'error', message: 'Too many login attempts' },
});

// --- Middleware ---
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: config.session.secret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.CVG_COOKIE_SECURE === 'true',
    httpOnly: true,
    maxAge: config.session.maxAge,
    sameSite: 'lax',
  },
}));

// Static files for dashboard
app.use(express.static(path.join(__dirname, '..', 'public')));

// --- Routes ---

// Health (no auth, no rate limit)
app.use('/api/v1/health', healthRoutes);

// Verification API (OneBox auth + rate limit)
app.use('/api/v1/verification', apiLimiter, verificationRoutes);

// Admin API (dashboard auth + rate limit)
app.use('/api/v1/admin', apiLimiter, adminRoutes);

// Dashboard (session auth)
app.post('/login', authLimiter);
app.use('/', dashboardRoutes);

// --- Error handler ---
app.use((err, req, res, _next) => {
  console.error('[CVG] Unhandled error:', err.message);
  res.status(500).json({
    status: 'error',
    error_code: 'INTERNAL_ERROR',
    message: config.env === 'production' ? 'Internal server error' : err.message,
  });
});

// --- Startup ---
function start() {
  // Warn if Central DIT is not configured in external mode
  if (config.ivs.mode === 'external' && !config.centralDit.baseUrl) {
    console.warn('[CVG] WARNING: CENTRAL_DIT_BASE_URL is not set. Callbacks will be queued but cannot be delivered until configured.');
  }

  // Initialize database
  const db = getDb();
  console.log(`[CVG] Database initialized`);

  // Start IVS health checker (external mode only)
  startIvsHealthCheck();

  // Start queue worker
  if (config.queue.enabled) {
    startQueueWorker();
  }

  const server = app.listen(config.port, () => {
    for (const line of startupBanner(config)) console.log(line);
  });

  // Graceful shutdown
  const shutdown = () => {
    console.log('\n[CVG] Shutting down...');
    stopIvsHealthCheck();
    stopQueueWorker();
    closeDb();
    server.close(() => process.exit(0));
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return server;
}

if (require.main === module) {
  start();
}

module.exports = { app, start };
