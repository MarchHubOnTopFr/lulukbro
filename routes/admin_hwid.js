/**
 * routes/admin_hwid.js — Admin endpoints for HWID/fingerprint management.
 *
 * Mount in server.js:
 *   const adminHwidRoutes = require('./routes/admin_hwid');
 *   app.use('/admin/hwid', adminHwidRoutes);
 *
 * All routes require admin JWT via requireAdmin middleware.
 */

'use strict';

const express = require('express');
const Joi     = require('express');
const JoiLib  = require('joi');
const { query }        = require('../db');
const { requireAdmin } = require('../middlewares/auth');
const { logAction }    = require('../middlewares/audit');
const { deriveHWID }   = require('../hwid');

const router = express.Router();
router.use(requireAdmin);

// ── Pagination helper (same as admin.js) ──────────────────────────────────────
function paginate(q) {
  const page   = Math.max(1, parseInt(q.page  || '1'));
  const limit  = Math.min(100, Math.max(1, parseInt(q.limit || '50')));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

// ── GET /admin/hwid/logs — fingerprint attempt history ────────────────────────
// Query params: user_id, ip, verdict, page, limit
router.get('/logs', async (req, res, next) => {
  const { page, limit, offset } = paginate(req.query);
  const userId  = req.query.user_id || null;
  const ip      = req.query.ip      || null;
  const verdict = req.query.verdict || null;

  try {
    const [logs, count] = await Promise.all([
      query(
        `SELECT fl.id, fl.key_id, fl.user_id, fl.username, fl.client_id,
                fl.ip, fl.device_type, fl.score, fl.verdict, fl.created_at,
                uk.key
         FROM fingerprint_logs fl
         LEFT JOIN user_keys uk ON uk.id = fl.key_id
         WHERE ($1::text IS NULL OR fl.user_id  = $1)
           AND ($2::text IS NULL OR fl.ip        = $2)
           AND ($3::text IS NULL OR fl.verdict   = $3)
         ORDER BY fl.created_at DESC
         LIMIT $4 OFFSET $5;`,
        [userId, ip, verdict, limit, offset]
      ),
      query(
        `SELECT COUNT(*)::int AS c FROM fingerprint_logs
         WHERE ($1::text IS NULL OR user_id = $1)
           AND ($2::text IS NULL OR ip      = $2)
           AND ($3::text IS NULL OR verdict = $3);`,
        [userId, ip, verdict]
      ),
    ]);

    return res.json({ success: true, logs: logs.rows, total: count.rows[0].c, page, limit });
  } catch (err) { next(err); }
});

// ── GET /admin/hwid/stats — aggregate breakdown ───────────────────────────────
router.get('/stats', async (req, res, next) => {
  try {
    const { rows: [s] } = await query(`
      SELECT
        COUNT(*)::int                                              AS total_attempts,
        COUNT(*) FILTER (WHERE verdict = 'pass')::int             AS passed,
        COUNT(*) FILTER (WHERE verdict = 'bind')::int             AS bound,
        COUNT(*) FILTER (WHERE verdict = 'fail')::int             AS failed,
        COUNT(*) FILTER (WHERE verdict = 'anomaly')::int          AS anomaly_blocked,
        COUNT(*) FILTER (WHERE verdict = 'identity_fail')::int    AS identity_failures,
        COUNT(*) FILTER (WHERE verdict = 'userid_mismatch')::int  AS userid_mismatches,
        ROUND(AVG(score)::numeric, 3)::float                      AS avg_score,
        COUNT(DISTINCT ip)::int                                   AS unique_ips,
        COUNT(DISTINCT user_id)::int                              AS unique_user_ids
      FROM fingerprint_logs
      WHERE created_at > NOW() - INTERVAL '24 hours';
    `);
    return res.json({ success: true, stats: s, window: '24h' });
  } catch (err) { next(err); }
});

// ── GET /admin/hwid/suspicious — IPs / userIds with high failure rate ─────────
router.get('/suspicious', async (req, res, next) => {
  try {
    const [byIp, byUser] = await Promise.all([
      query(`
        SELECT ip,
               COUNT(*)::int                                      AS total,
               COUNT(*) FILTER (WHERE verdict != 'pass' AND verdict != 'bind')::int AS failures,
               ROUND((COUNT(*) FILTER (WHERE verdict != 'pass' AND verdict != 'bind'))::numeric
                     / NULLIF(COUNT(*),0) * 100, 1)::float        AS failure_pct,
               MAX(created_at)                                    AS last_seen
        FROM fingerprint_logs
        WHERE created_at > NOW() - INTERVAL '1 hour'
        GROUP BY ip
        HAVING COUNT(*) > 3
        ORDER BY failure_pct DESC, total DESC
        LIMIT 30;
      `),
      query(`
        SELECT user_id, username,
               COUNT(*)::int                                      AS total,
               COUNT(*) FILTER (WHERE verdict NOT IN ('pass','bind'))::int AS failures,
               COUNT(DISTINCT ip)::int                            AS distinct_ips,
               MAX(created_at)                                    AS last_seen
        FROM fingerprint_logs
        WHERE created_at > NOW() - INTERVAL '1 hour'
        GROUP BY user_id, username
        HAVING COUNT(*) > 3
        ORDER BY failures DESC, distinct_ips DESC
        LIMIT 30;
      `),
    ]);

    return res.json({
      success: true,
      suspicious_ips:   byIp.rows,
      suspicious_users: byUser.rows,
    });
  } catch (err) { next(err); }
});

// ── DELETE /admin/hwid/logs/purge — delete logs older than N days ─────────────
router.delete('/logs/purge', async (req, res, next) => {
  const days = Math.max(1, parseInt(req.query.days || '30'));
  try {
    const { rowCount } = await query(
      `DELETE FROM fingerprint_logs WHERE created_at < NOW() - ($1 || ' days')::INTERVAL;`,
      [days]
    );
    logAction(req.user.username, 'ADMIN_HWID_LOGS_PURGE', null, req.ip, { days, deleted: rowCount });
    return res.json({ success: true, deleted: rowCount });
  } catch (err) { next(err); }
});

// ── POST /admin/hwid/derive — show what HWID a userId+clientId would produce ──
router.post('/derive', async (req, res, next) => {
  const { userId, clientId } = req.body;
  if (!userId || !clientId)
    return res.status(400).json({ success: false, message: 'userId and clientId required' });

  const hwid = deriveHWID(userId, clientId);
  return res.json({ success: true, hwid });
});

// ── GET /admin/hwid/key-baseline?key=<uuid> — show stored fingerprint baseline ─
router.get('/key-baseline', async (req, res, next) => {
  const { key } = req.query;
  if (!key) return res.status(400).json({ success: false, message: 'key required' });

  try {
    const { rows } = await query('SELECT hwid FROM user_keys WHERE key = $1;', [key]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Key not found' });

    let baseline = rows[0].hwid;
    let parsed = null;
    try { parsed = JSON.parse(baseline); } catch { /* legacy plain HWID */ }

    return res.json({ success: true, raw: baseline, parsed });
  } catch (err) { next(err); }
});

module.exports = router;
