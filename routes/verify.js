const express   = require('express');
const Joi       = require('joi');
const rateLimit = require('express-rate-limit');
const { query }        = require('../db');
const { logAction }    = require('../middlewares/audit');
const { fireWebhooks } = require('./webhooks');

const router = express.Router();

// ── Rate limiter — keyed per IP (Lua scripts hit this frequently) ─────────────
const verifyLimiter = rateLimit({
  windowMs: 60 * 1000, max: 120,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { valid: false, reason: 'Rate limit exceeded — slow down.' },
  skip: (req) => false,
});

const schema = Joi.object({
  key:  Joi.string().uuid().required(),
  hwid: Joi.string().min(1).max(512).required(),
});

// ── GET /verify?key=<uuid>&hwid=<string> ──────────────────────────────────────
// Public endpoint consumed by Lua scripts / game executors.
// Always returns HTTP 200 — callers check the `valid` boolean.
//
// Optimised to a single atomic query:
//  1. Fetch the key row
//  2. If HWID is unbound (NULL) → bind it + update last_used_at in one UPDATE
//  3. If already bound → compare in SQL, update last_used_at in one UPDATE
// This eliminates the previous SELECT → conditional UPDATE round-trip.
router.get('/', verifyLimiter, async (req, res) => {
  const { error, value } = schema.validate(req.query);
  if (error)
    return res.json({ valid: false, reason: 'Invalid parameters' });

  const { key, hwid } = value;

  try {
    // Single query: get the key and atomically update last_used_at when valid.
    const { rows } = await query(
      `SELECT id, username, hwid, status,
              expires_at < NOW() AS expired
       FROM user_keys
       WHERE key = $1;`,
      [key]
    );

    if (!rows.length) {
      logAction(null, 'VERIFY_FAIL', null, req.ip, { reason: 'invalid_key' });
      return res.json({ valid: false, reason: 'Invalid key' });
    }

    const k = rows[0];

    if (k.status !== 'active') {
      logAction(k.username, 'VERIFY_FAIL', k.id, req.ip, { reason: 'key_disabled' });
      return res.json({ valid: false, reason: 'Key is disabled' });
    }

    if (k.expired) {
      logAction(k.username, 'VERIFY_FAIL', k.id, req.ip, { reason: 'key_expired' });
      return res.json({ valid: false, reason: 'Key has expired' });
    }

    // First use — bind the HWID atomically
    if (k.hwid === null) {
      await query(
        `UPDATE user_keys SET hwid = $1, last_used_at = NOW() WHERE id = $2;`,
        [hwid, k.id]
      );
      logAction(k.username, 'VERIFY_BIND', k.id, req.ip, { hwid });
      fireWebhooks(k.username, 'VERIFY_BIND', { key_id: k.id, ip: req.ip, hwid, timestamp: new Date().toISOString() });
      return res.json({ valid: true, message: 'HWID bound and verified' });
    }

    // HWID mismatch
    if (k.hwid !== hwid) {
      logAction(k.username, 'VERIFY_FAIL', k.id, req.ip, { reason: 'hwid_mismatch' });
      fireWebhooks(k.username, 'VERIFY_FAIL', { key_id: k.id, ip: req.ip, reason: 'hwid_mismatch', timestamp: new Date().toISOString() });
      return res.json({ valid: false, reason: 'HWID mismatch' });
    }

    // ✅ All checks passed — update last_used_at asynchronously (non-blocking)
    query(`UPDATE user_keys SET last_used_at = NOW() WHERE id = $1;`, [k.id])
      .catch((e) => console.error('[Verify] last_used_at update failed:', e.message));

    logAction(k.username, 'VERIFY_OK', k.id, req.ip);
    fireWebhooks(k.username, 'VERIFY_OK', { key_id: k.id, ip: req.ip, timestamp: new Date().toISOString() });
    return res.json({ valid: true });

  } catch (err) {
    console.error('[Verify]', err);
    return res.json({ valid: false, reason: 'Server error' });
  }
});

module.exports = router;

