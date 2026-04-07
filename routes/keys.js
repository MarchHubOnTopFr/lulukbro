const express   = require('express');
const Joi       = require('joi');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { query }        = require('../db');
const { authenticate } = require('../middlewares/auth');
const { logAction }    = require('../middlewares/audit');

const router = express.Router();
router.use(authenticate);

const keyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 60,
  standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Too many requests — try again later.' },
});
router.use(keyLimiter);

const MAX_KEYS            = parseInt(process.env.MAX_KEYS_PER_USER        || '10');
const HWID_COOLDOWN_HOURS = parseInt(process.env.HWID_RESET_COOLDOWN_HOURS || '24');

// ── Schemas ───────────────────────────────────────────────────────────────────
const keySchema = Joi.object({ key: Joi.string().uuid().required() });

const generateSchema = Joi.object({
  note:       Joi.string().max(100).allow('').default(''),
  expires_in: Joi.number().integer().min(1).max(3650).optional(), // days
});

const hwidSchema = Joi.object({
  key:  Joi.string().uuid().required(),
  hwid: Joi.string().min(1).max(512).required(),
});

const noteSchema = Joi.object({
  key:  Joi.string().uuid().required(),
  note: Joi.string().max(100).allow('').required(),
});

// ── POST /keys/generate ───────────────────────────────────────────────────────
router.post('/generate', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = generateSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });

  const { note, expires_in } = value;
  try {
    // Count + Insert in one round-trip using a CTE with guard
    const newKey    = uuidv4();
    const expiresAt = expires_in ? new Date(Date.now() + expires_in * 86_400_000) : null;

    // Guard: only insert if under the key limit
    const { rows } = await query(
      `WITH guard AS (
         SELECT COUNT(*)::int AS c FROM user_keys WHERE username = $1
       )
       INSERT INTO user_keys (username, key, note, expires_at)
       SELECT $1, $2, $3, $4
       FROM guard WHERE c < $5
       RETURNING id, key, note, expires_at, status, hwid, created_at;`,
      [username, newKey, note, expiresAt, MAX_KEYS]
    );

    if (!rows.length) {
      return res.status(429).json({
        success: false,
        message: `Key limit reached (${MAX_KEYS} max). Delete unused keys first.`,
      });
    }

    logAction(username, 'KEY_GENERATE', rows[0].id, req.ip, { note, expires_in });
    return res.status(201).json({ success: true, key: rows[0] });
  } catch (err) { next(err); }
});

// ── GET /keys/list ────────────────────────────────────────────────────────────
router.get('/list', async (req, res, next) => {
  const { username } = req.user;
  try {
    const { rows } = await query(
      `SELECT id, key, hwid, status, note, expires_at,
              last_used_at, hwid_reset_count, hwid_reset_at, created_at,
              (expires_at IS NOT NULL AND expires_at < NOW()) AS is_expired
       FROM user_keys WHERE username = $1
       ORDER BY created_at DESC;`,
      [username]
    );
    return res.json({ success: true, keys: rows, max_keys: MAX_KEYS });
  } catch (err) { next(err); }
});

// ── GET /keys/raw  (Lua-compatible whitelist output) ──────────────────────────
// Returns a plain Lua table mapping key → HWID for active, non-expired keys.
router.get('/raw', async (req, res, next) => {
  const { username } = req.user;
  try {
    const { rows } = await query(
      `SELECT key, hwid FROM user_keys
       WHERE username = $1 AND status = 'active'
         AND (expires_at IS NULL OR expires_at > NOW());`,
      [username]
    );
    const lua =
      `local KeysAndHwid = {\n` +
      rows.map(r => `    ["${r.key}"] = ${r.hwid ? `"${r.hwid}"` : 'nil'},`).join('\n') +
      `\n}\n\nreturn KeysAndHwid`;

    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    return res.type('text/plain').send(lua);
  } catch (err) { next(err); }
});

// ── PATCH /keys/note ──────────────────────────────────────────────────────────
router.patch('/note', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = noteSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { key, note } = value;
  try {
    const { rowCount } = await query(
      'UPDATE user_keys SET note = $1 WHERE username = $2 AND key = $3;',
      [note, username, key]
    );
    if (!rowCount) return res.status(404).json({ success: false, message: 'Key not found' });
    return res.json({ success: true, message: 'Note updated' });
  } catch (err) { next(err); }
});

// ── PATCH /keys/hwid  (manual bind) ──────────────────────────────────────────
router.patch('/hwid', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = hwidSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { key, hwid } = value;
  try {
    // Atomic: only bind if currently unbound (hwid IS NULL)
    const { rows } = await query(
      `UPDATE user_keys
       SET hwid = $1
       WHERE username = $2 AND key = $3 AND hwid IS NULL
       RETURNING id;`,
      [hwid, username, key]
    );

    if (!rows.length) {
      // Distinguish "not found" from "already bound"
      const { rows: existing } = await query(
        'SELECT id FROM user_keys WHERE username = $1 AND key = $2;',
        [username, key]
      );
      if (!existing.length)
        return res.status(404).json({ success: false, message: 'Key not found' });
      return res.status(409).json({ success: false, message: 'HWID already bound. Reset it first.' });
    }

    logAction(username, 'HWID_BIND', rows[0].id, req.ip, { hwid });
    return res.json({ success: true, message: 'HWID bound' });
  } catch (err) { next(err); }
});

// ── PATCH /keys/hwid/reset ────────────────────────────────────────────────────
router.patch('/hwid/reset', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = keySchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { key } = value;
  try {
    const { rows } = await query(
      'SELECT id, hwid_reset_at, hwid_reset_count FROM user_keys WHERE username = $1 AND key = $2;',
      [username, key]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Key not found' });

    const { id, hwid_reset_at, hwid_reset_count } = rows[0];
    if (hwid_reset_at) {
      const cooldownMs  = HWID_COOLDOWN_HOURS * 3_600_000;
      const elapsed     = Date.now() - new Date(hwid_reset_at).getTime();
      if (elapsed < cooldownMs) {
        const remainHours = Math.ceil((cooldownMs - elapsed) / 3_600_000);
        return res.status(429).json({
          success: false,
          message: `HWID reset on cooldown. Try again in ~${remainHours}h.`,
          retry_after_hours: remainHours,
        });
      }
    }

    await query(
      `UPDATE user_keys
       SET hwid = NULL, hwid_reset_at = NOW(), hwid_reset_count = hwid_reset_count + 1
       WHERE id = $1;`,
      [id]
    );
    logAction(username, 'HWID_RESET', id, req.ip, { total_resets: hwid_reset_count + 1 });
    return res.json({ success: true, message: 'HWID reset' });
  } catch (err) { next(err); }
});

// ── PATCH /keys/toggle  (enable ↔ disable) ───────────────────────────────────
router.patch('/toggle', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = keySchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { key } = value;
  try {
    // Atomic toggle with CTE — one round-trip
    const { rows } = await query(
      `UPDATE user_keys
       SET status = CASE WHEN status = 'active' THEN 'disabled' ELSE 'active' END
       WHERE username = $1 AND key = $2
       RETURNING id, status;`,
      [username, key]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Key not found' });

    logAction(username, `KEY_${rows[0].status.toUpperCase()}`, rows[0].id, req.ip);
    return res.json({ success: true, status: rows[0].status });
  } catch (err) { next(err); }
});

// ── DELETE /keys/delete ───────────────────────────────────────────────────────
router.delete('/delete', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = keySchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  const { key } = value;
  try {
    // Atomic ownership-checked delete — one round-trip
    const { rows } = await query(
      `DELETE FROM user_keys WHERE username = $1 AND key = $2 RETURNING id;`,
      [username, key]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Key not found' });

    logAction(username, 'KEY_DELETE', rows[0].id, req.ip);
    return res.json({ success: true, message: 'Key deleted' });
  } catch (err) { next(err); }
});

module.exports = router;

