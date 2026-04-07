/**
 * /scripts — Luarmor-alternative: server-side Lua script storage & serving.
 *
 * Flow:
 *  1. User creates a "script" (uploads Lua source, stored in DB).
 *  2. User assigns keys to the script (key_scripts table).
 *  3. Lua executor calls GET /scripts/load?key=<uuid>&hwid=<hwid>&script=<name>
 *     → server verifies key+HWID, then returns the Lua source.
 *  4. User can generate a "loader" snippet for any script — drop it in their executor.
 */

const express   = require('express');
const Joi       = require('joi');
const rateLimit = require('express-rate-limit');
const { query }        = require('../db');
const { authenticate } = require('../middlewares/auth');
const { logAction }    = require('../middlewares/audit');
const { fireWebhooks } = require('./webhooks');

const router = express.Router();

// ── Rate limiter for the loader endpoint (hot path) ───────────────────────────
const loadLimiter = rateLimit({
  windowMs: 60_000, max: 200,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: 'Rate limit exceeded.',
});

// ── Schemas ───────────────────────────────────────────────────────────────────
const createSchema = Joi.object({
  name:        Joi.string().alphanum().min(1).max(60).required(),
  description: Joi.string().max(300).allow('').default(''),
  source:      Joi.string().max(512_000).allow('').default(''), // ~500 KB max
  version:     Joi.string().max(20).default('1.0.0'),
});

const updateSchema = Joi.object({
  name:        Joi.string().alphanum().min(1).max(60).required(), // identifies the script
  description: Joi.string().max(300).allow('').optional(),
  source:      Joi.string().max(512_000).allow('').optional(),
  version:     Joi.string().max(20).optional(),
  enabled:     Joi.boolean().optional(),
});

const nameSchema = Joi.object({
  name: Joi.string().alphanum().min(1).max(60).required(),
});

const assignSchema = Joi.object({
  name: Joi.string().alphanum().min(1).max(60).required(),
  key:  Joi.string().uuid().required(),
});

// ── Load schema (public — validated from query string) ────────────────────────
const loadSchema = Joi.object({
  key:    Joi.string().uuid().required(),
  hwid:   Joi.string().min(1).max(512).required(),
  script: Joi.string().alphanum().min(1).max(60).required(),
});

// ═══════════════════════════════════════════════════════════════════════════════
// AUTHENTICATED ROUTES
// ═══════════════════════════════════════════════════════════════════════════════
router.use('/manage', authenticate);

// ── GET /scripts/manage/list ─────────────────────────────────────────────────
router.get('/manage/list', async (req, res, next) => {
  const { username } = req.user;
  try {
    const { rows } = await query(
      `SELECT s.id, s.name, s.description, s.version, s.enabled, s.created_at, s.updated_at,
              COUNT(ks.key_id)::int AS assigned_keys
       FROM scripts s
       LEFT JOIN key_scripts ks ON ks.script_id = s.id
       WHERE s.username = $1
       GROUP BY s.id
       ORDER BY s.created_at DESC;`,
      [username]
    );
    return res.json({ success: true, scripts: rows });
  } catch (err) { next(err); }
});

// ── GET /scripts/manage/source?name=<name> ───────────────────────────────────
router.get('/manage/source', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = nameSchema.validate(req.query);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  try {
    const { rows } = await query(
      'SELECT name, source, version, updated_at FROM scripts WHERE username = $1 AND name = $2;',
      [username, value.name]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Script not found' });
    return res.json({ success: true, script: rows[0] });
  } catch (err) { next(err); }
});

// ── POST /scripts/manage/create ───────────────────────────────────────────────
router.post('/manage/create', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = createSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  try {
    const { rows } = await query(
      `INSERT INTO scripts (username, name, description, source, version)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, description, version, enabled, created_at;`,
      [username, value.name, value.description, value.source, value.version]
    );
    logAction(username, 'SCRIPT_CREATE', null, req.ip, { name: value.name });
    return res.status(201).json({ success: true, script: rows[0] });
  } catch (err) { next(err); }
});

// ── PATCH /scripts/manage/update ─────────────────────────────────────────────
router.patch('/manage/update', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = updateSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });

  const { name, ...fields } = value;
  if (!Object.keys(fields).length)
    return res.status(400).json({ success: false, message: 'No fields to update' });

  // Build dynamic SET clause (only provided fields)
  const setClauses = [];
  const params     = [];
  if (fields.description !== undefined) { params.push(fields.description); setClauses.push(`description = $${params.length}`); }
  if (fields.source      !== undefined) { params.push(fields.source);      setClauses.push(`source = $${params.length}`); }
  if (fields.version     !== undefined) { params.push(fields.version);     setClauses.push(`version = $${params.length}`); }
  if (fields.enabled     !== undefined) { params.push(fields.enabled);     setClauses.push(`enabled = $${params.length}`); }
  setClauses.push(`updated_at = NOW()`);

  params.push(username); params.push(name);
  try {
    const { rowCount } = await query(
      `UPDATE scripts SET ${setClauses.join(', ')}
       WHERE username = $${params.length - 1} AND name = $${params.length};`,
      params
    );
    if (!rowCount) return res.status(404).json({ success: false, message: 'Script not found' });
    logAction(username, 'SCRIPT_UPDATE', null, req.ip, { name, fields: Object.keys(fields) });
    return res.json({ success: true, message: 'Script updated' });
  } catch (err) { next(err); }
});

// ── DELETE /scripts/manage/delete ─────────────────────────────────────────────
router.delete('/manage/delete', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = nameSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  try {
    const { rowCount } = await query(
      'DELETE FROM scripts WHERE username = $1 AND name = $2;',
      [username, value.name]
    );
    if (!rowCount) return res.status(404).json({ success: false, message: 'Script not found' });
    logAction(username, 'SCRIPT_DELETE', null, req.ip, { name: value.name });
    return res.json({ success: true, message: 'Script deleted' });
  } catch (err) { next(err); }
});

// ── POST /scripts/manage/assign — link a key to a script ─────────────────────
router.post('/manage/assign', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = assignSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  try {
    // Verify ownership of both script and key
    const [{ rows: sRows }, { rows: kRows }] = await Promise.all([
      query('SELECT id FROM scripts   WHERE username = $1 AND name = $2;', [username, value.name]),
      query('SELECT id FROM user_keys WHERE username = $1 AND key  = $2;', [username, value.key]),
    ]);
    if (!sRows.length) return res.status(404).json({ success: false, message: 'Script not found' });
    if (!kRows.length) return res.status(404).json({ success: false, message: 'Key not found' });

    await query(
      `INSERT INTO key_scripts (key_id, script_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;`,
      [kRows[0].id, sRows[0].id]
    );
    logAction(username, 'SCRIPT_ASSIGN', kRows[0].id, req.ip, { name: value.name });
    return res.json({ success: true, message: 'Key assigned to script' });
  } catch (err) { next(err); }
});

// ── DELETE /scripts/manage/unassign — unlink a key from a script ──────────────
router.delete('/manage/unassign', async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = assignSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });
  try {
    const [{ rows: sRows }, { rows: kRows }] = await Promise.all([
      query('SELECT id FROM scripts   WHERE username = $1 AND name = $2;', [username, value.name]),
      query('SELECT id FROM user_keys WHERE username = $1 AND key  = $2;', [username, value.key]),
    ]);
    if (!sRows.length) return res.status(404).json({ success: false, message: 'Script not found' });
    if (!kRows.length) return res.status(404).json({ success: false, message: 'Key not found' });

    await query(
      'DELETE FROM key_scripts WHERE key_id = $1 AND script_id = $2;',
      [kRows[0].id, sRows[0].id]
    );
    logAction(username, 'SCRIPT_UNASSIGN', kRows[0].id, req.ip, { name: value.name });
    return res.json({ success: true, message: 'Key unassigned from script' });
  } catch (err) { next(err); }
});

// ── GET /scripts/manage/loader?name=<name> ───────────────────────────────────
// Returns a ready-to-use Lua loader snippet the user can paste into their executor.
router.get('/manage/loader', authenticate, async (req, res, next) => {
  const { username } = req.user;
  const { error, value } = nameSchema.validate(req.query);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });

  const { rows } = await query(
    'SELECT name FROM scripts WHERE username = $1 AND name = $2;',
    [username, value.name]
  ).catch(next);
  if (!rows || !rows.length)
    return res.status(404).json({ success: false, message: 'Script not found' });

  const baseUrl = process.env.PUBLIC_URL || `http://localhost:${process.env.PORT || 18635}`;
  const loader  = generateLoader(baseUrl, value.name);

  res.setHeader('Cache-Control', 'no-store');
  return res.type('text/plain').send(loader);
});

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC LOAD ENDPOINT  (called by Lua scripts in the executor)
// ═══════════════════════════════════════════════════════════════════════════════

// ── GET /scripts/load?key=<uuid>&hwid=<hwid>&script=<name> ────────────────────
// Verifies key + HWID, then returns the raw Lua source.
// Always HTTP 200 — callers check `valid` boolean.
router.get('/load', loadLimiter, async (req, res) => {
  const { error, value } = loadSchema.validate(req.query);
  if (error) return res.json({ valid: false, reason: 'Invalid parameters' });

  const { key, hwid, script: scriptName } = value;

  try {
    // Single query: join key → key_scripts → script, checking all conditions at once
    const { rows } = await query(
      `SELECT
         uk.id        AS key_id,
         uk.username,
         uk.hwid,
         uk.status,
         (uk.expires_at IS NOT NULL AND uk.expires_at < NOW()) AS expired,
         s.source,
         s.enabled    AS script_enabled
       FROM user_keys uk
       JOIN key_scripts ks  ON ks.key_id    = uk.id
       JOIN scripts     s   ON s.id         = ks.script_id
       WHERE uk.key = $1 AND s.name = $2;`,
      [key, scriptName]
    );

    if (!rows.length) {
      logAction(null, 'LOAD_FAIL', null, req.ip, { reason: 'invalid_key_or_script', script: scriptName });
      return res.json({ valid: false, reason: 'Invalid key or script not assigned' });
    }

    const r = rows[0];

    if (r.status !== 'active') {
      logAction(r.username, 'LOAD_FAIL', r.key_id, req.ip, { reason: 'key_disabled', script: scriptName });
      return res.json({ valid: false, reason: 'Key is disabled' });
    }
    if (r.expired) {
      logAction(r.username, 'LOAD_FAIL', r.key_id, req.ip, { reason: 'key_expired', script: scriptName });
      return res.json({ valid: false, reason: 'Key has expired' });
    }
    if (!r.script_enabled) {
      logAction(r.username, 'LOAD_FAIL', r.key_id, req.ip, { reason: 'script_disabled', script: scriptName });
      return res.json({ valid: false, reason: 'Script is currently disabled' });
    }

    // First use — bind HWID
    if (r.hwid === null) {
      await query(
        'UPDATE user_keys SET hwid = $1, last_used_at = NOW() WHERE id = $2;',
        [hwid, r.key_id]
      );
      logAction(r.username, 'LOAD_BIND', r.key_id, req.ip, { hwid, script: scriptName });
      fireWebhooks(r.username, 'VERIFY_BIND', { key_id: r.key_id, ip: req.ip, hwid, script: scriptName, timestamp: new Date().toISOString() });
      res.setHeader('Cache-Control', 'no-store');
      return res.json({ valid: true, source: r.source, message: 'HWID bound' });
    }

    // HWID mismatch
    if (r.hwid !== hwid) {
      logAction(r.username, 'LOAD_FAIL', r.key_id, req.ip, { reason: 'hwid_mismatch', script: scriptName });
      fireWebhooks(r.username, 'LOAD_FAIL', { key_id: r.key_id, ip: req.ip, reason: 'hwid_mismatch', script: scriptName, timestamp: new Date().toISOString() });
      return res.json({ valid: false, reason: 'HWID mismatch' });
    }

    // ✅ All checks passed — update last_used_at non-blocking
    query('UPDATE user_keys SET last_used_at = NOW() WHERE id = $1;', [r.key_id])
      .catch((e) => console.error('[Load] last_used_at update failed:', e.message));

    logAction(r.username, 'LOAD_OK', r.key_id, req.ip, { script: scriptName });
    fireWebhooks(r.username, 'LOAD_OK', { key_id: r.key_id, ip: req.ip, script: scriptName, timestamp: new Date().toISOString() });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ valid: true, source: r.source });

  } catch (err) {
    console.error('[Load]', err);
    return res.json({ valid: false, reason: 'Server error' });
  }
});

// ── generateLoader — Lua snippet that loads a protected script from Synthia ───
function generateLoader(baseUrl, scriptName) {
  return `-- Synthia Loader — generated automatically
-- Drop this in your executor. It will verify your key and load the script.
local HttpService = game:GetService("HttpService")

local KEY  = "YOUR_KEY_HERE"   -- replace with your actual key
local HWID = game:GetService("RbxAnalyticsService"):GetClientId()  -- or use your executor's HWID function

local url  = "${baseUrl}/scripts/load"
  .. "?key="    .. KEY
  .. "&hwid="   .. HWID
  .. "&script=" .. "${scriptName}"

local ok, response = pcall(function()
  return HttpService:GetAsync(url, true)
end)

if not ok then
  warn("[Synthia] Connection failed: " .. tostring(response))
  return
end

local data = HttpService:JSONDecode(response)

if not data.valid then
  warn("[Synthia] Rejected: " .. (data.reason or "unknown"))
  return
end

-- Execute the protected script
local fn, err = loadstring(data.source)
if not fn then
  warn("[Synthia] Script error: " .. tostring(err))
  return
end
fn()
`;
}

module.exports = router;
