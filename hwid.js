/**
 * hwid.js — Multi-factor HWID engine for the Synthia key system.
 *
 * Architecture
 * ─────────────
 * The client (Lua) sends a raw fingerprint bundle:
 *   { userId, username, displayName, accountAge, deviceType, clientId, timestamp, sig }
 *
 * The server:
 *   1. Validates every component structurally (schema guard).
 *   2. Verifies UserId ↔ Username via the Roblox Users API (rate-cached).
 *   3. Scores the fingerprint against the stored baseline.
 *   4. Accepts if weighted score ≥ ACCEPT_THRESHOLD (default 0.80).
 *   5. Derives a stable hashed HWID from the anchor fields (userId + clientId).
 *
 * Design goals
 * ─────────────
 * • UserId is the primary, immutable anchor — it never changes for an account.
 * • ClientId is the secondary anchor — device-level, stable across sessions.
 * • Username / DisplayName / AccountAge are soft signals used only in scoring,
 *   not in the stored HWID hash, so renames / display-name changes don't lock
 *   the player out.
 * • A small Hamming-distance tolerance on clientId handles minor executor noise.
 * • The Roblox API check is cached per userId for 5 minutes to avoid hammering
 *   the external API on every script load.
 */

'use strict';

require('dotenv').config();
const crypto = require('crypto');
const https  = require('https');
const { query } = require('./db');
const { log }   = require('./utils');

// ── Constants ─────────────────────────────────────────────────────────────────
const HWID_SECRET        = process.env.HWID_SECRET        || 'change-me-hwid-secret-32-chars!!';
const ACCEPT_THRESHOLD   = parseFloat(process.env.HWID_ACCEPT_THRESHOLD || '0.80');
const ROBLOX_CACHE_TTL   = parseInt(process.env.ROBLOX_CACHE_TTL_MS     || '300000'); // 5 min
const MAX_CLIENTID_DRIFT = parseInt(process.env.MAX_CLIENTID_DRIFT       || '3');     // Hamming
const ANOMALY_WINDOW_MIN = parseInt(process.env.ANOMALY_WINDOW_MIN       || '10');    // minutes
const ANOMALY_IP_LIMIT   = parseInt(process.env.ANOMALY_IP_LIMIT         || '15');    // max verify per window per IP
const ANOMALY_UID_LIMIT  = parseInt(process.env.ANOMALY_UID_LIMIT        || '8');     // max verify per window per userId

// ── Roblox API cache ──────────────────────────────────────────────────────────
const robloxCache = new Map(); // userId → { username, expiresAt }

// ── Component weights (must sum to 1.0) ───────────────────────────────────────
const WEIGHTS = {
  userId:      0.50,   // immutable — exact match only
  clientId:    0.28,   // device-level — small drift tolerated
  username:    0.10,   // can change (Roblox allows renames)
  accountAge:  0.07,   // grows monotonically — ±10 day window
  deviceType:  0.05,   // broad category — exact match preferred
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. FINGERPRINT SCHEMA VALIDATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validates the raw fingerprint object sent by the Lua client.
 * Returns { valid: bool, error?: string }.
 */
function validateFingerprint(fp) {
  if (!fp || typeof fp !== 'object') return { valid: false, error: 'Fingerprint missing' };

  const checks = [
    [typeof fp.userId      === 'string' && /^\d{3,12}$/.test(fp.userId),     'userId must be a numeric string'],
    [typeof fp.username    === 'string' && fp.username.length >= 3 && fp.username.length <= 32, 'username invalid'],
    [typeof fp.displayName === 'string' && fp.displayName.length <= 64,       'displayName invalid'],
    [typeof fp.accountAge  === 'number' && fp.accountAge >= 0,                'accountAge must be a non-negative number'],
    [typeof fp.deviceType  === 'string' && fp.deviceType.length <= 32,        'deviceType invalid'],
    [typeof fp.clientId    === 'string' && fp.clientId.length >= 8 && fp.clientId.length <= 128, 'clientId invalid'],
    [typeof fp.timestamp   === 'number' && Math.abs(Date.now() / 1000 - fp.timestamp) < 120,    'timestamp drift > 2 min'],
  ];

  for (const [cond, msg] of checks) {
    if (!cond) return { valid: false, error: msg };
  }
  return { valid: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. ROBLOX API IDENTITY VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetches Roblox user info for a userId, with an in-memory TTL cache.
 * @returns {Promise<{username:string, displayName:string}|null>}
 */
function fetchRobloxUser(userId) {
  const cached = robloxCache.get(userId);
  if (cached && cached.expiresAt > Date.now()) return Promise.resolve(cached.data);

  return new Promise((resolve) => {
    const req = https.get(
      `https://users.roblox.com/v1/users/${userId}`,
      { timeout: 5000 },
      (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try {
            const json = JSON.parse(body);
            if (json.id) {
              const data = { username: json.name, displayName: json.displayName };
              robloxCache.set(userId, { data, expiresAt: Date.now() + ROBLOX_CACHE_TTL });
              resolve(data);
            } else {
              resolve(null);
            }
          } catch {
            resolve(null);
          }
        });
      }
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

/**
 * Verifies that the claimed userId actually owns the claimed username.
 * Soft failure: if the Roblox API is unreachable, we warn but don't reject —
 * the score will still be reduced because username won't match.
 */
async function verifyRobloxIdentity(userId, claimedUsername) {
  try {
    const robloxUser = await fetchRobloxUser(userId);
    if (!robloxUser) return { verified: false, reason: 'Roblox API unavailable' };

    const match = robloxUser.username.toLowerCase() === claimedUsername.toLowerCase();
    return { verified: match, robloxUsername: robloxUser.username, robloxDisplayName: robloxUser.displayName };
  } catch (err) {
    log('warn', '[HWID] Roblox API error', { err: err.message });
    return { verified: false, reason: 'Roblox API error' };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. COMPONENT SCORING
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Hamming distance between two strings (pad shorter to same length).
 */
function hammingDistance(a, b) {
  const len = Math.max(a.length, b.length);
  const pa  = a.padEnd(len, '\0');
  const pb  = b.padEnd(len, '\0');
  let dist  = 0;
  for (let i = 0; i < len; i++) if (pa[i] !== pb[i]) dist++;
  return dist;
}

/**
 * Score a single clientId against the stored one.
 * Full score if exact match, partial if within drift threshold, zero beyond.
 */
function scoreClientId(stored, incoming) {
  if (stored === incoming) return 1.0;
  const dist = hammingDistance(stored, incoming);
  if (dist <= MAX_CLIENTID_DRIFT) return 1 - (dist / (MAX_CLIENTID_DRIFT + 1));
  return 0.0;
}

/**
 * Score the incoming fingerprint against the stored baseline.
 * Returns a weighted score in [0, 1].
 *
 * @param {object} stored   — The stored fingerprint components (from DB)
 * @param {object} incoming — The raw fingerprint sent by the Lua client
 * @returns {{ score: number, breakdown: object }}
 */
function scoreFingerprint(stored, incoming) {
  const breakdown = {};

  // userId — must be exact
  breakdown.userId = stored.userId === incoming.userId ? 1.0 : 0.0;

  // clientId — Hamming distance tolerance
  breakdown.clientId = scoreClientId(stored.clientId, incoming.clientId);

  // username — exact (case-insensitive), 0 if mismatch
  breakdown.username = stored.username.toLowerCase() === incoming.username.toLowerCase() ? 1.0 : 0.0;

  // accountAge — monotonically increasing; allow ±10 days drift
  const ageDelta = Math.abs((stored.accountAge || 0) - (incoming.accountAge || 0));
  breakdown.accountAge = ageDelta <= 10 ? 1.0 - (ageDelta / 100) : Math.max(0, 1 - ageDelta / 30);

  // deviceType — exact match preferred
  breakdown.deviceType = stored.deviceType === incoming.deviceType ? 1.0 : 0.3;

  const score = Object.keys(WEIGHTS).reduce(
    (sum, key) => sum + WEIGHTS[key] * (breakdown[key] ?? 0), 0
  );

  return { score: parseFloat(score.toFixed(4)), breakdown };
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. STABLE HWID HASH
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Derives a stable, server-secret HWID from the two immutable anchors.
 * The hash never changes unless userId or clientId changes.
 * Using HMAC-SHA256 with the server secret prevents precomputation.
 */
function deriveHWID(userId, clientId) {
  return crypto
    .createHmac('sha256', HWID_SECRET)
    .update(`${userId}:${clientId}`)
    .digest('hex');
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ANOMALY DETECTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check if an IP or userId is hitting the verify endpoint too frequently.
 * Uses a sliding window stored in the fingerprint_logs table.
 * Returns { flagged: bool, reason?: string }.
 */
async function detectAnomaly(ip, userId) {
  const windowStart = new Date(Date.now() - ANOMALY_WINDOW_MIN * 60_000);

  const [ipResult, uidResult] = await Promise.all([
    query(
      `SELECT COUNT(*)::int AS c FROM fingerprint_logs
       WHERE ip = $1 AND created_at > $2;`,
      [ip, windowStart]
    ),
    query(
      `SELECT COUNT(*)::int AS c FROM fingerprint_logs
       WHERE user_id = $1 AND created_at > $2;`,
      [userId, windowStart]
    ),
  ]);

  const ipCount  = ipResult.rows[0]?.c  || 0;
  const uidCount = uidResult.rows[0]?.c || 0;

  if (ipCount  >= ANOMALY_IP_LIMIT)  return { flagged: true, reason: `IP rate exceeded (${ipCount}/${ANOMALY_WINDOW_MIN}m)` };
  if (uidCount >= ANOMALY_UID_LIMIT) return { flagged: true, reason: `User rate exceeded (${uidCount}/${ANOMALY_WINDOW_MIN}m)` };

  return { flagged: false };
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. FINGERPRINT LOG (audit trail)
// ─────────────────────────────────────────────────────────────────────────────

async function logFingerprintAttempt({ keyId, userId, username, clientId, ip, deviceType, score, verdict }) {
  try {
    await query(
      `INSERT INTO fingerprint_logs
         (key_id, user_id, username, client_id, ip, device_type, score, verdict)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8);`,
      [keyId, userId, username, clientId, ip, deviceType, score, verdict]
    );
  } catch (err) {
    log('warn', '[HWID] Failed to write fingerprint log', { err: err.message });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. MASTER VALIDATE FUNCTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Full HWID validation pipeline.
 *
 * @param {object} fingerprint  — Raw object from Lua client
 * @param {object} keyRow       — Row from user_keys (id, hwid, username, status, expired)
 * @param {string} ip           — Requester's IP address
 *
 * @returns {Promise<{
 *   valid: boolean,
 *   reason?: string,
 *   hwid?: string,
 *   score?: number,
 *   breakdown?: object,
 *   action?: 'bind' | 'pass' | 'fail'
 * }>}
 */
async function validateHWID(fingerprint, keyRow, ip) {
  // ── Step 1: Schema ──────────────────────────────────────────────────────────
  const schemaCheck = validateFingerprint(fingerprint);
  if (!schemaCheck.valid) {
    return { valid: false, reason: `Bad fingerprint: ${schemaCheck.error}`, action: 'fail' };
  }

  // ── Step 2: Anomaly detection ──────────────────────────────────────────────
  const anomaly = await detectAnomaly(ip, fingerprint.userId);
  if (anomaly.flagged) {
    await logFingerprintAttempt({
      keyId: keyRow.id, userId: fingerprint.userId, username: fingerprint.username,
      clientId: fingerprint.clientId, ip, deviceType: fingerprint.deviceType,
      score: 0, verdict: 'anomaly',
    });
    return { valid: false, reason: 'Too many attempts — try again later', action: 'fail' };
  }

  // ── Step 3: Roblox identity check ─────────────────────────────────────────
  const identity = await verifyRobloxIdentity(fingerprint.userId, fingerprint.username);
  // Non-fatal: if Roblox API is down we continue, but score will reflect mismatch.
  if (!identity.verified && identity.reason !== 'Roblox API unavailable') {
    await logFingerprintAttempt({
      keyId: keyRow.id, userId: fingerprint.userId, username: fingerprint.username,
      clientId: fingerprint.clientId, ip, deviceType: fingerprint.deviceType,
      score: 0, verdict: 'identity_fail',
    });
    return { valid: false, reason: 'Roblox identity mismatch (userId ↔ username)', action: 'fail' };
  }

  // ── Step 4: First use — bind the HWID ─────────────────────────────────────
  const derivedHWID = deriveHWID(fingerprint.userId, fingerprint.clientId);

  if (keyRow.hwid === null) {
    // Store the fingerprint baseline as JSON in the hwid column
    const baseline = JSON.stringify({
      userId:      fingerprint.userId,
      username:    fingerprint.username,
      accountAge:  fingerprint.accountAge,
      deviceType:  fingerprint.deviceType,
      clientId:    fingerprint.clientId,
      hwid:        derivedHWID,
    });

    await logFingerprintAttempt({
      keyId: keyRow.id, userId: fingerprint.userId, username: fingerprint.username,
      clientId: fingerprint.clientId, ip, deviceType: fingerprint.deviceType,
      score: 1.0, verdict: 'bind',
    });

    return { valid: true, hwid: baseline, derivedHWID, score: 1.0, action: 'bind' };
  }

  // ── Step 5: Parse stored baseline ─────────────────────────────────────────
  let stored;
  try {
    stored = JSON.parse(keyRow.hwid);
  } catch {
    // Legacy plain-string HWID — treat as exact match required
    const match = keyRow.hwid === derivedHWID;
    await logFingerprintAttempt({
      keyId: keyRow.id, userId: fingerprint.userId, username: fingerprint.username,
      clientId: fingerprint.clientId, ip, deviceType: fingerprint.deviceType,
      score: match ? 1 : 0, verdict: match ? 'pass' : 'fail',
    });
    return match
      ? { valid: true, score: 1.0, action: 'pass' }
      : { valid: false, reason: 'HWID mismatch', action: 'fail' };
  }

  // ── Step 6: Score the fingerprint ─────────────────────────────────────────
  const { score, breakdown } = scoreFingerprint(stored, fingerprint);

  // userId is load-bearing — hard fail if it doesn't match
  if (breakdown.userId === 0) {
    await logFingerprintAttempt({
      keyId: keyRow.id, userId: fingerprint.userId, username: fingerprint.username,
      clientId: fingerprint.clientId, ip, deviceType: fingerprint.deviceType,
      score, verdict: 'userid_mismatch',
    });
    return { valid: false, reason: 'UserId mismatch', score, breakdown, action: 'fail' };
  }

  const passed = score >= ACCEPT_THRESHOLD;
  const verdict = passed ? 'pass' : 'fail';

  await logFingerprintAttempt({
    keyId: keyRow.id, userId: fingerprint.userId, username: fingerprint.username,
    clientId: fingerprint.clientId, ip, deviceType: fingerprint.deviceType,
    score, verdict,
  });

  if (!passed) {
    return {
      valid: false,
      reason: `HWID score too low (${score.toFixed(2)} < ${ACCEPT_THRESHOLD})`,
      score,
      breakdown,
      action: 'fail',
    };
  }

  return { valid: true, score, breakdown, action: 'pass' };
}

// ─────────────────────────────────────────────────────────────────────────────
// DB additions needed by this module (call from initializeDB)
// ─────────────────────────────────────────────────────────────────────────────

async function initializeHWIDTables() {
  await query(`
    CREATE TABLE IF NOT EXISTS fingerprint_logs (
      id          BIGSERIAL   PRIMARY KEY,
      key_id      INT         REFERENCES user_keys(id) ON DELETE SET NULL,
      user_id     TEXT        NOT NULL,
      username    TEXT        NOT NULL,
      client_id   TEXT,
      ip          TEXT        NOT NULL,
      device_type TEXT,
      score       FLOAT,
      verdict     TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS pending_keys (
      id          SERIAL      PRIMARY KEY,
      token       TEXT        NOT NULL UNIQUE,
      ip          TEXT        NOT NULL,
      user_id     TEXT,
      expires_at  TIMESTAMPTZ NOT NULL,
      redeemed    BOOLEAN     NOT NULL DEFAULT FALSE,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  const indexes = [
    `CREATE INDEX IF NOT EXISTS idx_fplogs_userid    ON fingerprint_logs(user_id);`,
    `CREATE INDEX IF NOT EXISTS idx_fplogs_ip        ON fingerprint_logs(ip);`,
    `CREATE INDEX IF NOT EXISTS idx_fplogs_created   ON fingerprint_logs(created_at DESC);`,
    `CREATE INDEX IF NOT EXISTS idx_fplogs_verdict   ON fingerprint_logs(verdict);`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_token ON pending_keys(token);`,
    `CREATE INDEX IF NOT EXISTS idx_pending_ip       ON pending_keys(ip);`,
  ];
  for (const sql of indexes) {
    try { await query(sql); } catch { /* already exists */ }
  }
}

module.exports = {
  validateFingerprint,
  verifyRobloxIdentity,
  scoreFingerprint,
  deriveHWID,
  detectAnomaly,
  validateHWID,
  initializeHWIDTables,
};
