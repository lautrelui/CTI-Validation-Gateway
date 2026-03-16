/**
 * Admin API routes per spec section 3.5.
 * Protected by dashboard auth.
 */

const express = require('express');
const router = express.Router();
const { getDb } = require('../database/db');
const { requireDashboardAuth } = require('../middleware/auth');
const { getQueueStats, processQueue } = require('../queue/worker');
const { getAuditEvents, getAuditStats } = require('../audit');
const { isIvsAvailable, setIvsAvailable } = require('../services/ivs-simulator');

// All admin routes require auth
router.use(requireDashboardAuth);

/**
 * GET /api/v1/admin/verification-queue
 */
router.get('/verification-queue', (req, res) => {
  const db = getDb();
  const { status, limit = 50, offset = 0 } = req.query;

  let query = 'SELECT vq.*, vr.identifier_type, vr.masked_value_preview, vr.requesting_assujetti_id, vr.onebox_id FROM verification_queue vq JOIN verification_requests vr ON vq.correlation_id = vr.correlation_id WHERE 1=1';
  const params = [];

  if (status) {
    query += ' AND vq.status = ?';
    params.push(status);
  }

  query += ' ORDER BY vq.created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));

  const items = db.prepare(query).all(...params);
  const stats = getQueueStats();

  res.json({ items, stats });
});

/**
 * POST /api/v1/admin/verification-queue/retry
 */
router.post('/verification-queue/retry', (req, res) => {
  try {
    processQueue();
    res.json({ status: 'success', message: 'Queue processing triggered' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

/**
 * GET /api/v1/admin/stats
 */
router.get('/stats', (req, res) => {
  const db = getDb();

  const totalRequests = db.prepare('SELECT COUNT(*) as count FROM verification_requests').get();
  const byStatus = db.prepare('SELECT status, COUNT(*) as count FROM verification_requests GROUP BY status').all();
  const byType = db.prepare('SELECT identifier_type, COUNT(*) as count FROM verification_requests GROUP BY identifier_type').all();
  const byAssujetti = db.prepare('SELECT requesting_assujetti_id, COUNT(*) as count FROM verification_requests GROUP BY requesting_assujetti_id').all();
  const last24h = db.prepare("SELECT COUNT(*) as count FROM verification_requests WHERE created_at >= datetime('now', '-1 day')").get();
  const lastHour = db.prepare("SELECT COUNT(*) as count FROM verification_requests WHERE created_at >= datetime('now', '-1 hour')").get();

  const queueStats = getQueueStats();
  const auditStats = getAuditStats();

  // Recent requests
  const recentRequests = db.prepare(`
    SELECT vr.*, vres.verification_status as result_status, vres.ivs_signature_verified
    FROM verification_requests vr
    LEFT JOIN verification_results vres ON vr.correlation_id = vres.correlation_id
    ORDER BY vr.created_at DESC LIMIT 20
  `).all();

  // Hourly volume (last 24h)
  const hourlyVolume = db.prepare(`
    SELECT strftime('%Y-%m-%dT%H:00:00', created_at) as hour, COUNT(*) as count
    FROM verification_requests
    WHERE created_at >= datetime('now', '-1 day')
    GROUP BY hour ORDER BY hour
  `).all();

  res.json({
    overview: {
      total_requests: totalRequests.count,
      last_24h: last24h.count,
      last_hour: lastHour.count,
      ivs_status: isIvsAvailable() ? 'available' : 'unavailable',
    },
    byStatus,
    byType,
    byAssujetti,
    queue: queueStats,
    audit: auditStats,
    recentRequests,
    hourlyVolume,
  });
});

/**
 * GET /api/v1/admin/audit
 */
router.get('/audit', (req, res) => {
  const { correlation_id, event_type, limit = 100, offset = 0 } = req.query;
  const events = getAuditEvents({
    correlationId: correlation_id,
    eventType: event_type,
    limit: parseInt(limit),
    offset: parseInt(offset),
  });
  res.json({ events });
});

/**
 * GET /api/v1/admin/requests
 */
router.get('/requests', (req, res) => {
  const db = getDb();
  const { status, limit = 50, offset = 0 } = req.query;

  let query = `
    SELECT vr.*, vres.verification_status as result_status, vres.ivs_signature_verified,
      vres.claim_json
    FROM verification_requests vr
    LEFT JOIN verification_results vres ON vr.correlation_id = vres.correlation_id
    WHERE 1=1`;
  const params = [];

  if (status) {
    query += ' AND vr.status = ?';
    params.push(status);
  }

  query += ' ORDER BY vr.created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));

  const items = db.prepare(query).all(...params);
  res.json({ items });
});

/**
 * POST /api/v1/admin/ivs/toggle
 * Toggle IVS availability (simulator only).
 */
router.post('/ivs/toggle', (req, res) => {
  const current = isIvsAvailable();
  setIvsAvailable(!current);
  res.json({ ivs_available: !current });
});

module.exports = router;
