const express = require('express');
const router = express.Router();
const { getDb } = require('../database/db');
const { isIvsAvailable, getIvsStatus } = require('../services/ivs-simulator');
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
  const overall = dbOk && ivsOk ? 'healthy' : 'degraded';

  const ivsStatus = getIvsStatus();

  res.status(overall === 'healthy' ? 200 : 503).json({
    status: overall,
    gateway_id: config.gateway.id,
    timestamp: new Date().toISOString(),
    components: {
      database: dbOk ? 'ok' : 'error',
      ivs: ivsOk ? 'ok' : 'unavailable',
      queue: config.queue.enabled ? 'enabled' : 'disabled',
    },
    ivs_details: ivsStatus,
  });
});

module.exports = router;
