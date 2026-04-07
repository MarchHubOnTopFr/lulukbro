const express = require('express');
const Joi     = require('joi');
const { v4: uuidv4 } = require('uuid');
const { query }        = require('../db');
const { requireAdmin } = require('../middlewares/auth');
const { logAction }    = require('../middlewares/audit');

const router = express.Router();
router.use(requireAdmin);

// ── Schemas ───────────────────────────────────────────────────────────────────
const keySchema = Joi.object({ key: Joi.string().uuid().required() });

const usernameSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
});

const createKeySchema = Joi.object({
  username:   Joi.string().alphanum().min(3).max(30).required(),
  note:       Joi.string().max(100).allow('').default(''),
  expires_in: Joi.number().integer().min(1).max(3650).optional(),
});

const roleSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  role:     Joi.string().valid('admin', 'user').required(),
});

// ── Pagination helper ─────────────────────────────────────────────────────────
function paginate(q) {
  const page   = Math.max(1, parseInt(q.page  || '1'));
  const limit  = Math.min(100, Math.max(1, parseInt(q.limit || '50')));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

// ── GET /admin/stats ──────────────────────────────────────────────────────────
// All 6+ counts in ONE query using conditional aggregation — was 6 round-trips.
router.get('/stats', async (_req, res, next) => {
  try {
    const { rows: [s] } = await query(`
      SELECT
        (SELECT COUNT(*)::int FROM users)                                              AS total_users,
        COUNT(*)::int                                                                  AS total_keys,
        COUNT(*) FILTER (WHERE status = 'active')::int                                AS active_keys,
        COUNT(*) FILTER (WHERE status = 'disabled')::int                              AS disabled_keys,
        COUNT(*) FILTER (WHERE hwid IS NOT NULL)::int                                 AS bound_keys,
        COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at < NOW())::int    AS expired_keys,
        (SELECT COUNT(*)::int FROM audit_logs)                                         AS total_log_entries
      FROM user_keys;
    `);
    return res.json({ success: true, stats: s });
  } catch (err) { next(err); }
});

// ── GET /admin/users ──────────────────────────────────────────────────────────
router.get('/users', async (req, res, next) => {
  const { page, limit, offset } = paginate(req.query);
  const search = req.query.search ? `%${req.query.search}%` : null;
  try {
    const [usersResult, countResult] = await Promise.all([
      query(
        `SELECT u.username, u.role, u.created_at,
           COUNT(k.id)::int                                   AS total_keys,
           COUNT(k.id) FILTER (WHERE k.status='active')::int AS active_keys
         FROM users u
         LEFT JOIN user_keys k ON k.username = u.username
         WHERE ($1::text IS NULL OR u.username ILIKE $1)
         GROUP BY u.username, u.role, u.created_at
         ORDER BY u.created_at DESC
         LIMIT $2 OFFSET $3;`,
        [search, limit, offset]
      ),
      query(
        `SELECT COUNT(*)::int AS c FROM users WHERE ($1::text IS NULL OR username ILIKE $1);`,
        [search]
      ),
    ]);
    return res.json({ success: true, users: usersResult.rows, total: countResult.rows[0].c, page, limit });
  } catch (err) { next(err); }
});

// ── DELETE /admin/users/delete ────────────────────────────────────────────────
router.delete('/users/delete', async (req, res, next) => {
  const { error, value } = usernameSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { username } = value;
  if (username === req.user.username)
    return res.status(400).json({ success: false, message: 'You cannot delete your own account' });
  try {
    const { rowCount } = await query('DELETE FROM users WHERE username = $1;', [username]);
    if (!rowCount) return res.status(404).json({ success: false, message: 'User not found' });
    logAction(req.user.username, 'ADMIN_DELETE_USER', null, req.ip, { target: username });
    return res.json({ success: true, message: 'User deleted' });
  } catch (err) { next(err); }
});

// ── PATCH /admin/users/role ───────────────────────────────────────────────────
router.patch('/users/role', async (req, res, next) => {
  const { error, value } = roleSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { username, role } = value;
  if (username === req.user.username && role === 'user')
    return res.status(400).json({ success: false, message: 'Cannot demote yourself' });
  try {
    const { rowCount } = await query('UPDATE users SET role = $1 WHERE username = $2;', [role, username]);
    if (!rowCount) return res.status(404).json({ success: false, message: 'User not found' });
    logAction(req.user.username, 'ADMIN_SET_ROLE', null, req.ip, { target: username, role });
    return res.json({ success: true, message: `Role set to ${role}` });
  } catch (err) { next(err); }
});

// ── GET /admin/keys ───────────────────────────────────────────────────────────
router.get('/keys', async (req, res, next) => {
  const { page, limit, offset } = paginate(req.query);
  const search = req.query.search ? `%${req.query.search}%` : null;
  try {
    const [keysResult, countResult] = await Promise.all([
      query(
        `SELECT k.id, k.username, k.key, k.hwid, k.status, k.note,
                k.expires_at, k.last_used_at, k.hwid_reset_count, k.created_at,
                (k.expires_at IS NOT NULL AND k.expires_at < NOW()) AS is_expired
         FROM user_keys k
         WHERE ($1::text IS NULL OR k.username ILIKE $1 OR k.key ILIKE $1 OR k.note ILIKE $1)
         ORDER BY k.created_at DESC
         LIMIT $2 OFFSET $3;`,
        [search, limit, offset]
      ),
      query(
        `SELECT COUNT(*)::int AS c FROM user_keys
         WHERE ($1::text IS NULL OR username ILIKE $1 OR key ILIKE $1 OR note ILIKE $1);`,
        [search]
      ),
    ]);
    return res.json({ success: true, keys: keysResult.rows, total: countResult.rows[0].c, page, limit });
  } catch (err) { next(err); }
});

// ── POST /admin/keys/create ───────────────────────────────────────────────────
router.post('/keys/create', async (req, res, next) => {
  const { error, value } = createKeySchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { username, note, expires_in } = value;
  try {
    const { rows: u } = await query('SELECT username FROM users WHERE username = $1;', [username]);
    if (!u.length) return res.status(404).json({ success: false, message: 'User not found' });

    const newKey    = uuidv4();
    const expiresAt = expires_in ? new Date(Date.now() + expires_in * 86_400_000) : null;
    const { rows }  = await query(
      `INSERT INTO user_keys (username, key, note, expires_at)
       VALUES ($1,$2,$3,$4) RETURNING *;`,
      [username, newKey, note, expiresAt]
    );
    logAction(req.user.username, 'ADMIN_KEY_CREATE', rows[0].id, req.ip, { target: username, note });
    return res.status(201).json({ success: true, key: rows[0] });
  } catch (err) { next(err); }
});

// ── PATCH /admin/keys/toggle ──────────────────────────────────────────────────
router.patch('/keys/toggle', async (req, res, next) => {
  const { error, value } = keySchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { key } = value;
  try {
    const { rows } = await query(
      `UPDATE user_keys
       SET status = CASE WHEN status = 'active' THEN 'disabled' ELSE 'active' END
       WHERE key = $1
       RETURNING id, status, username;`,
      [key]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Key not found' });
    logAction(req.user.username, `ADMIN_KEY_${rows[0].status.toUpperCase()}`, rows[0].id, req.ip, { target: rows[0].username });
    return res.json({ success: true, status: rows[0].status });
  } catch (err) { next(err); }
});

// ── PATCH /admin/keys/hwid/reset ─────────────────────────────────────────────
router.patch('/keys/hwid/reset', async (req, res, next) => {
  const { error, value } = keySchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { key } = value;
  try {
    const { rows } = await query(
      `UPDATE user_keys
       SET hwid = NULL, hwid_reset_at = NOW(), hwid_reset_count = hwid_reset_count + 1
       WHERE key = $1
       RETURNING id, username;`,
      [key]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Key not found' });
    logAction(req.user.username, 'ADMIN_HWID_RESET', rows[0].id, req.ip, { target: rows[0].username });
    return res.json({ success: true, message: 'HWID reset' });
  } catch (err) { next(err); }
});

// ── DELETE /admin/keys/delete ─────────────────────────────────────────────────
router.delete('/keys/delete', async (req, res, next) => {
  const { error, value } = keySchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { key } = value;
  try {
    const { rows } = await query(
      'DELETE FROM user_keys WHERE key = $1 RETURNING id, username;',
      [key]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Key not found' });
    logAction(req.user.username, 'ADMIN_KEY_DELETE', rows[0].id, req.ip, { target: rows[0].username });
    return res.json({ success: true, message: 'Key deleted' });
  } catch (err) { next(err); }
});

// ── GET /admin/logs ───────────────────────────────────────────────────────────
router.get('/logs', async (req, res, next) => {
  const { page, limit, offset } = paginate(req.query);
  const action   = req.query.action   || null;
  const username = req.query.username || null;
  try {
    const [logsResult, countResult] = await Promise.all([
      query(
        `SELECT id, username, action, key_id, ip, metadata, created_at
         FROM audit_logs
         WHERE ($1::text IS NULL OR username = $1)
           AND ($2::text IS NULL OR action   = $2)
         ORDER BY created_at DESC LIMIT $3 OFFSET $4;`,
        [username, action, limit, offset]
      ),
      query(
        `SELECT COUNT(*)::int AS c FROM audit_logs
         WHERE ($1::text IS NULL OR username = $1)
           AND ($2::text IS NULL OR action   = $2);`,
        [username, action]
      ),
    ]);
    return res.json({ success: true, logs: logsResult.rows, total: countResult.rows[0].c, page, limit });
  } catch (err) { next(err); }
});

module.exports = router;
