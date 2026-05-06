const express = require('express');
const router = express.Router();
const { getDb } = require('../database/db');
const { isIvsAvailable, getIvsStatus } = require('../services/ivs-simulator');
const { getCentralDitStatus } = require('../services/central-dit-client');
const { getCallbackQueueStats } = require('../queue/worker');
const config = require('../config');

/**
 * GET /api/v1/health
 */
router.get('/', (req, res) => {
  const db = getDb();
  let dbOk = false;
  try {
    db.prepare('SELECT 1').get();
    dbOk = true;
  } catch (e) { /* db down */ }

  const ivsOk = isIvsAvailable();
  const ditStatus = getCentralDitStatus();
  const callbackStats = getCallbackQueueStats();

  // Central DIT is considered OK if configured and has no recent failures without any successes
  const ditConfigured = ditStatus.configured;
  const ditOk = !ditConfigured || !ditStatus.last_failure || (ditStatus.last_success && ditStatus.last_success >= ditStatus.last_failure);

  const overall = dbOk && ivsOk && ditOk ? 'healthy' : 'degraded';

  const ivsStatus = getIvsStatus();

  res.status(overall === 'healthy' ? 200 : 503).json({
    status: overall,
    gateway_id: config.gateway.id,
    timestamp: new Date().toISOString(),
    components: {
      database: dbOk ? 'ok' : 'error',
      ivs: ivsOk ? 'ok' : 'unavailable',
      central_dit: ditConfigured ? (ditOk ? 'ok' : 'degraded') : 'not_configured',
      queue: config.queue.enabled ? 'enabled' : 'disabled',
    },
    ivs_details: ivsStatus,
    central_dit: {
      configured: ditConfigured,
      reachable: ditOk,
      last_success: ditStatus.last_success,
      last_failure: ditStatus.last_failure,
      pending_callbacks: callbackStats.pending,
      failed_callbacks: callbackStats.failed,
    },
  });
});

/**
 * GET /api/v1/health/live
 *
 * Liveness probe — returns 200 if CVG can accept requests.
 * Only checks DB and IVS, NOT Central DIT reachability
 * (which can be transiently degraded without affecting CVG's ability to serve).
 */
router.get('/live', (req, res) => {
  const db = getDb();
  let dbOk = false;
  try {
    db.prepare('SELECT 1').get();
    dbOk = true;
  } catch (e) { /* db down */ }

  const ivsOk = isIvsAvailable();
  const ok = dbOk && ivsOk;

  res.status(ok ? 200 : 503).json({
    status: ok ? 'ok' : 'degraded',
    gateway_id: config.gateway.id,
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
