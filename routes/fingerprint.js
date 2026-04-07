/**
 * routes/fingerprint.js — Multi-factor HWID verify + script delivery.
 *
 * Endpoints
 * ──────────
 *   POST /fingerprint/verify
 *     Body: { key, fingerprint: { userId, username, displayName,
 *                                  accountAge, deviceType, clientId,
 *                                  timestamp }, script? }
 *     Response: { valid, reason?, source? }
 *
 * This replaces the simple GET /verify?key=&hwid= endpoint with a
 * richer pipeline that uses the validateHWID() engine.
 *
 * Security notes
 * ──────────────
 * • The route is POST-only so fingerprint data never appears in logs/URLs.
 * • All responses are HTTP 200 — callers check `valid` boolean.
 * • Source is delivered only after all checks pass.
 * • Per-IP rate limiter is tighter than the global one.
 */

'use strict';

const express   = require('express');
const Joi       = require('joi');
const rateLimit = require('express-rate-limit');
const { query }        = require('../db');
const { logAction }    = require('../middlewares/audit');
const { fireWebhooks } = require('./webhooks');
const {
  validateHWID,
  deriveHWID,
} = require('../hwid');

const router = express.Router();

// ── Rate limiter — 60 requests / minute per IP ────────────────────────────────
const verifyLimiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (_req, res) => res.json({ valid: false, reason: 'Rate limit exceeded — slow down.' }),
});

// ── Joi schema ────────────────────────────────────────────────────────────────
const fingerprintSchema = Joi.object({
  userId:      Joi.string().pattern(/^\d{3,12}$/).required(),
  username:    Joi.string().min(3).max(32).required(),
  displayName: Joi.string().max(64).allow('').default(''),
  accountAge:  Joi.number().integer().min(0).required(),
  deviceType:  Joi.string().max(32).required(),
  clientId:    Joi.string().min(8).max(128).required(),
  timestamp:   Joi.number().required(),
});

const verifySchema = Joi.object({
  key:         Joi.string().uuid().required(),
  fingerprint: fingerprintSchema.required(),
  script:      Joi.string().alphanum().max(60).optional(), // optional: request specific script
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /fingerprint/verify
// ─────────────────────────────────────────────────────────────────────────────
router.post('/verify', verifyLimiter, async (req, res) => {
  const { error, value } = verifySchema.validate(req.body, { abortEarly: true });
  if (error) {
    return res.json({ valid: false, reason: `Bad request: ${error.details[0].message}` });
  }

  const { key, fingerprint, script: scriptName } = value;
  const ip = req.ip;

  try {
    // ── 1. Look up the key ──────────────────────────────────────────────────
    const { rows } = await query(
      `SELECT id, username, hwid, status,
              (expires_at IS NOT NULL AND expires_at < NOW()) AS expired
       FROM user_keys WHERE key = $1;`,
      [key]
    );

    if (!rows.length) {
      logAction(null, 'FP_VERIFY_FAIL', null, ip, { reason: 'invalid_key' });
      return res.json({ valid: false, reason: 'Invalid key' });
    }

    const keyRow = rows[0];

    if (keyRow.status !== 'active') {
      logAction(keyRow.username, 'FP_VERIFY_FAIL', keyRow.id, ip, { reason: 'key_disabled' });
      return res.json({ valid: false, reason: 'Key is disabled' });
    }

    if (keyRow.expired) {
      logAction(keyRow.username, 'FP_VERIFY_FAIL', keyRow.id, ip, { reason: 'key_expired' });
      return res.json({ valid: false, reason: 'Key has expired' });
    }

    // ── 2. Run HWID validation pipeline ────────────────────────────────────
    const result = await validateHWID(fingerprint, keyRow, ip);

    if (!result.valid) {
      logAction(keyRow.username, 'FP_VERIFY_FAIL', keyRow.id, ip, {
        reason: result.reason,
        score:  result.score,
      });
      fireWebhooks(keyRow.username, 'VERIFY_FAIL', {
        key_id: keyRow.id, ip, reason: result.reason, timestamp: new Date().toISOString(),
      });
      return res.json({ valid: false, reason: result.reason });
    }

    // ── 3. First use — bind the composite HWID ──────────────────────────────
    if (result.action === 'bind') {
      await query(
        `UPDATE user_keys SET hwid = $1, last_used_at = NOW() WHERE id = $2;`,
        [result.hwid, keyRow.id]
      );
      logAction(keyRow.username, 'FP_BIND', keyRow.id, ip, {
        userId:   fingerprint.userId,
        username: fingerprint.username,
        hwid:     result.derivedHWID,
      });
      fireWebhooks(keyRow.username, 'VERIFY_BIND', {
        key_id: keyRow.id, ip, hwid: result.derivedHWID, timestamp: new Date().toISOString(),
      });
    } else {
      // Non-blocking last_used_at update
      query(`UPDATE user_keys SET last_used_at = NOW() WHERE id = $1;`, [keyRow.id])
        .catch((e) => console.error('[FP] last_used_at update failed:', e.message));
      logAction(keyRow.username, 'FP_VERIFY_OK', keyRow.id, ip, { score: result.score });
      fireWebhooks(keyRow.username, 'VERIFY_OK', {
        key_id: keyRow.id, ip, score: result.score, timestamp: new Date().toISOString(),
      });
    }

    // ── 4. Script delivery (optional) ──────────────────────────────────────
    if (scriptName) {
      const { rows: scriptRows } = await query(
        `SELECT s.source, s.enabled
         FROM scripts s
         JOIN key_scripts ks ON ks.script_id = s.id
         WHERE ks.key_id = $1 AND s.name = $2;`,
        [keyRow.id, scriptName]
      );

      if (!scriptRows.length) {
        return res.json({ valid: true, reason: 'Script not assigned to this key' });
      }
      if (!scriptRows[0].enabled) {
        return res.json({ valid: true, reason: 'Script is currently disabled' });
      }

      logAction(keyRow.username, 'FP_LOAD_OK', keyRow.id, ip, { script: scriptName });
      fireWebhooks(keyRow.username, 'LOAD_OK', {
        key_id: keyRow.id, ip, script: scriptName, timestamp: new Date().toISOString(),
      });

      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      return res.json({
        valid:   true,
        source:  scriptRows[0].source,
        score:   result.score,
      });
    }

    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    return res.json({ valid: true, score: result.score });

  } catch (err) {
    console.error('[FP Verify]', err);
    return res.json({ valid: false, reason: 'Server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /fingerprint/score — debug/admin: score an incoming fingerprint
// against the stored baseline without actually validating or updating.
// Requires admin JWT.
// ─────────────────────────────────────────────────────────────────────────────
const { requireAdmin } = require('../middlewares/auth');
const { scoreFingerprint } = require('../hwid');

router.post('/score', requireAdmin, async (req, res) => {
  const { key, fingerprint } = req.body;
  if (!key || !fingerprint) return res.status(400).json({ success: false, message: 'key and fingerprint required' });

  const { rows } = await query('SELECT hwid FROM user_keys WHERE key = $1;', [key]);
  if (!rows.length) return res.status(404).json({ success: false, message: 'Key not found' });

  let stored;
  try { stored = JSON.parse(rows[0].hwid); }
  catch { return res.json({ success: false, message: 'Stored HWID is not a scored baseline (legacy)' }); }

  const { score, breakdown } = scoreFingerprint(stored, fingerprint);
  return res.json({ success: true, score, breakdown, threshold: parseFloat(process.env.HWID_ACCEPT_THRESHOLD || '0.80') });
});

module.exports = router;
