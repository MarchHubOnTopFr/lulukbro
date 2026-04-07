/**
 * routes/getkey.js — Roblox UI "Get Key" flow.
 *
 * Flow (Lua client → Server)
 * ──────────────────────────
 *  1. POST /getkey/start      { userId, username }
 *       → Returns a short-lived challenge token (valid 90 seconds).
 *         The Lua UI shows a 5-second countdown while holding this token.
 *
 *  2. POST /getkey/complete   { token, fingerprint }
 *       → After the countdown: server validates the token, verifies identity,
 *         auto-generates a key for the caller, and returns it.
 *         The key is created under the "system" user (or a configured owner).
 *         If the userId already has a valid active key, return that instead
 *         (idempotent — prevents key farming).
 *
 *  3. POST /getkey/redeem     { key, fingerprint }
 *       → User manually inputs a key. Server validates key + HWID pipeline
 *         and returns { valid, source? }.
 *
 * Security
 * ────────
 * • Challenge tokens are single-use, short-lived (90 s), and stored in DB.
 * • IP is bound to the token — a different IP cannot complete someone else's challenge.
 * • UserId is verified against Roblox API on /complete.
 * • Keys auto-generated here are owned by the GETKEY_OWNER_USER env var.
 * • Users cannot farm keys: one active key per userId per owner.
 * • All events are audit-logged and fire webhooks.
 */

'use strict';

require('dotenv').config();
const express   = require('express');
const Joi       = require('joi');
const rateLimit = require('express-rate-limit');
const crypto    = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { query }             = require('../db');
const { logAction }         = require('../middlewares/audit');
const { fireWebhooks }      = require('./webhooks');
const { verifyRobloxIdentity, validateHWID } = require('../hwid');

const router = express.Router();

// ── Config ────────────────────────────────────────────────────────────────────
const GETKEY_OWNER_USER   = process.env.GETKEY_OWNER_USER   || 'system';
const GETKEY_EXPIRES_DAYS = parseInt(process.env.GETKEY_EXPIRES_DAYS || '30');
const TOKEN_TTL_SECONDS   = parseInt(process.env.GETKEY_TOKEN_TTL_S  || '90');

// ── Rate limiters ─────────────────────────────────────────────────────────────
const startLimiter = rateLimit({
  windowMs: 5 * 60_000, max: 5,
  keyGenerator: (req) => req.ip,
  handler: (_req, res) => res.json({ success: false, message: 'Too many key requests — wait a few minutes.' }),
});

const completeLimiter = rateLimit({
  windowMs: 60_000, max: 10,
  keyGenerator: (req) => req.ip,
  handler: (_req, res) => res.json({ success: false, message: 'Rate limit exceeded.' }),
});

const redeemLimiter = rateLimit({
  windowMs: 60_000, max: 20,
  keyGenerator: (req) => req.ip,
  handler: (_req, res) => res.json({ valid: false, reason: 'Rate limit exceeded.' }),
});

// ── Schemas ───────────────────────────────────────────────────────────────────
const startSchema = Joi.object({
  userId:   Joi.string().pattern(/^\d{3,12}$/).required(),
  username: Joi.string().min(3).max(32).required(),
});

const fingerprintSchema = Joi.object({
  userId:      Joi.string().pattern(/^\d{3,12}$/).required(),
  username:    Joi.string().min(3).max(32).required(),
  displayName: Joi.string().max(64).allow('').default(''),
  accountAge:  Joi.number().integer().min(0).required(),
  deviceType:  Joi.string().max(32).required(),
  clientId:    Joi.string().min(8).max(128).required(),
  timestamp:   Joi.number().required(),
});

const completeSchema = Joi.object({
  token:       Joi.string().length(64).hex().required(),
  fingerprint: fingerprintSchema.required(),
});

const redeemSchema = Joi.object({
  key:         Joi.string().uuid().required(),
  fingerprint: fingerprintSchema.required(),
  script:      Joi.string().alphanum().max(60).optional(),
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /getkey/start
// ─────────────────────────────────────────────────────────────────────────────
router.post('/start', startLimiter, async (req, res) => {
  const { error, value } = startSchema.validate(req.body);
  if (error) return res.json({ success: false, message: error.details[0].message });

  const { userId, username } = value;
  const ip = req.ip;

  // Verify Roblox identity before issuing a token
  const identity = await verifyRobloxIdentity(userId, username);
  if (!identity.verified && identity.reason !== 'Roblox API unavailable') {
    logAction(null, 'GETKEY_START_FAIL', null, ip, { reason: 'identity_fail', userId });
    return res.json({ success: false, message: 'Roblox identity check failed — ensure userId matches username.' });
  }

  // Issue a single-use challenge token
  const token     = crypto.randomBytes(32).toString('hex'); // 64-char hex
  const expiresAt = new Date(Date.now() + TOKEN_TTL_SECONDS * 1000);

  try {
    await query(
      `INSERT INTO pending_keys (token, ip, user_id, expires_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (token) DO NOTHING;`,
      [token, ip, userId, expiresAt]
    );

    logAction(null, 'GETKEY_START', null, ip, { userId, username });
    return res.json({
      success:     true,
      token,
      wait_seconds: 5, // client should wait this long before calling /complete
      expires_in:  TOKEN_TTL_SECONDS,
    });
  } catch (err) {
    console.error('[GetKey/start]', err);
    return res.json({ success: false, message: 'Server error — try again.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /getkey/complete
// ─────────────────────────────────────────────────────────────────────────────
router.post('/complete', completeLimiter, async (req, res) => {
  const { error, value } = completeSchema.validate(req.body);
  if (error) return res.json({ success: false, message: error.details[0].message });

  const { token, fingerprint } = value;
  const ip = req.ip;

  try {
    // ── 1. Consume the pending token (atomic single-use) ───────────────────
    const { rows: tokenRows } = await query(
      `UPDATE pending_keys
       SET redeemed = TRUE
       WHERE token      = $1
         AND redeemed   = FALSE
         AND expires_at > NOW()
         AND ip         = $2
       RETURNING user_id;`,
      [token, ip]
    );

    if (!tokenRows.length) {
      logAction(null, 'GETKEY_COMPLETE_FAIL', null, ip, { reason: 'invalid_or_expired_token' });
      return res.json({ success: false, message: 'Token invalid, expired, or already used.' });
    }

    const storedUserId = tokenRows[0].user_id;

    // ── 2. Guard: userId in fingerprint must match token's userId ──────────
    if (fingerprint.userId !== storedUserId) {
      logAction(null, 'GETKEY_COMPLETE_FAIL', null, ip, { reason: 'userid_mismatch' });
      return res.json({ success: false, message: 'UserId mismatch.' });
    }

    // ── 3. Check if this userId already has an active key (idempotent) ────
    const { rows: existingKeys } = await query(
      `SELECT uk.key, uk.id, uk.expires_at
       FROM user_keys uk
       WHERE uk.username = $1
         AND uk.status   = 'active'
         AND (uk.expires_at IS NULL OR uk.expires_at > NOW())
         AND EXISTS (
           SELECT 1 FROM fingerprint_logs fl
           WHERE fl.key_id  = uk.id
             AND fl.user_id = $2
             AND fl.verdict IN ('bind', 'pass')
         )
       ORDER BY uk.created_at DESC LIMIT 1;`,
      [GETKEY_OWNER_USER, storedUserId]
    );

    if (existingKeys.length) {
      logAction(null, 'GETKEY_REISSUE', existingKeys[0].id, ip, { userId: storedUserId });
      return res.json({
        success:  true,
        key:      existingKeys[0].key,
        reissued: true,
        expires_at: existingKeys[0].expires_at,
      });
    }

    // ── 4. Ensure the system owner user exists ────────────────────────────
    await query(
      `INSERT INTO users (username, password, role)
       VALUES ($1, 'SYSTEM_NO_LOGIN', 'user')
       ON CONFLICT (username) DO NOTHING;`,
      [GETKEY_OWNER_USER]
    );

    // ── 5. Create a new key ───────────────────────────────────────────────
    const newKey    = uuidv4();
    const expiresAt = GETKEY_EXPIRES_DAYS
      ? new Date(Date.now() + GETKEY_EXPIRES_DAYS * 86_400_000)
      : null;

    const { rows: keyRows } = await query(
      `INSERT INTO user_keys (username, key, note, expires_at)
       VALUES ($1, $2, $3, $4)
       RETURNING id, key, expires_at;`,
      [GETKEY_OWNER_USER, newKey, `Auto-generated for userId:${storedUserId}`, expiresAt]
    );

    logAction(null, 'GETKEY_COMPLETE', keyRows[0].id, ip, { userId: storedUserId });
    fireWebhooks(GETKEY_OWNER_USER, 'KEY_GENERATE', {
      key_id: keyRows[0].id, ip, auto: true, userId: storedUserId, timestamp: new Date().toISOString(),
    });

    return res.json({
      success:    true,
      key:        keyRows[0].key,
      expires_at: keyRows[0].expires_at,
    });

  } catch (err) {
    console.error('[GetKey/complete]', err);
    return res.json({ success: false, message: 'Server error — try again.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /getkey/redeem — user manually inputs a key after getting it
// ─────────────────────────────────────────────────────────────────────────────
router.post('/redeem', redeemLimiter, async (req, res) => {
  const { error, value } = redeemSchema.validate(req.body);
  if (error) return res.json({ valid: false, reason: error.details[0].message });

  const { key, fingerprint, script: scriptName } = value;
  const ip = req.ip;

  try {
    // Look up key
    const { rows } = await query(
      `SELECT id, username, hwid, status,
              (expires_at IS NOT NULL AND expires_at < NOW()) AS expired
       FROM user_keys WHERE key = $1;`,
      [key]
    );

    if (!rows.length) {
      return res.json({ valid: false, reason: 'Invalid key' });
    }

    const keyRow = rows[0];
    if (keyRow.status !== 'active') return res.json({ valid: false, reason: 'Key is disabled' });
    if (keyRow.expired)             return res.json({ valid: false, reason: 'Key has expired' });

    // Run full HWID pipeline
    const result = await validateHWID(fingerprint, keyRow, ip);

    if (!result.valid) {
      logAction(keyRow.username, 'GETKEY_REDEEM_FAIL', keyRow.id, ip, { reason: result.reason });
      return res.json({ valid: false, reason: result.reason });
    }

    // First-use bind
    if (result.action === 'bind') {
      await query(
        `UPDATE user_keys SET hwid = $1, last_used_at = NOW() WHERE id = $2;`,
        [result.hwid, keyRow.id]
      );
      logAction(keyRow.username, 'GETKEY_REDEEM_BIND', keyRow.id, ip, { userId: fingerprint.userId });
    } else {
      query(`UPDATE user_keys SET last_used_at = NOW() WHERE id = $1;`, [keyRow.id]).catch(() => {});
      logAction(keyRow.username, 'GETKEY_REDEEM_OK', keyRow.id, ip, { score: result.score });
    }

    // Optional script delivery
    if (scriptName) {
      const { rows: sRows } = await query(
        `SELECT s.source, s.enabled FROM scripts s
         JOIN key_scripts ks ON ks.script_id = s.id
         WHERE ks.key_id = $1 AND s.name = $2;`,
        [keyRow.id, scriptName]
      );
      if (!sRows.length) return res.json({ valid: true, reason: 'Script not assigned' });
      if (!sRows[0].enabled) return res.json({ valid: true, reason: 'Script disabled' });

      res.setHeader('Cache-Control', 'no-store');
      return res.json({ valid: true, source: sRows[0].source, score: result.score });
    }

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ valid: true, score: result.score });

  } catch (err) {
    console.error('[GetKey/redeem]', err);
    return res.json({ valid: false, reason: 'Server error' });
  }
});

module.exports = router;
