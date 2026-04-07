/**
 * /webhooks — User-configurable HTTP callbacks triggered on key events.
 *
 * Supported events:
 *   VERIFY_OK   — key successfully verified
 *   VERIFY_FAIL — verification attempt rejected
 *   VERIFY_BIND — first-use HWID binding
 *   LOAD_OK     — script loaded successfully
 *   LOAD_FAIL   — script load rejected
 *
 * Each user can register one webhook URL per event type.
 * Deliveries are fire-and-forget — failures are logged but never block the API.
 * A delivery log is kept per webhook (last 100 attempts) for debugging.
 */

const express = require('express');
const Joi     = require('joi');
const https   = require('https');
const http    = require('http');
const { URL } = require('url');
const { query }        = require('../db');
const { authenticate } = require('../middlewares/auth');

const router = express.Router();
router.use(authenticate);

// ── Valid event types ─────────────────────────────────────────────────────────
const VALID_EVENTS = ['VERIFY_OK', 'VERIFY_FAIL', 'VERIFY_BIND', 'LOAD_OK', 'LOAD_FAIL'];

const upsertSchema = Joi.object({
  event:  Joi.string().valid(...VALID_EVENTS).required(),
  url:    Joi.string().uri({ scheme: ['http', 'https'] }).max(512).required(),
  secret: Joi.string().max(128).allow('').default(''),  // sent as X-Synthia-Secret header
});

const deleteSchema = Joi.object({
  event: Joi.string().valid(...VALID_EVENTS).required(),
});

// ── GET /webhooks/list ────────────────────────────────────────────────────────
router.get('/list', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT event, url, created_at, updated_at,
              last_triggered_at, last_status_code, total_deliveries
       FROM webhooks WHERE username = $1 ORDER BY event;`,
      [req.user.username]
    );
    return res.json({ success: true, webhooks: rows });
  } catch (err) { next(err); }
});

// ── POST /webhooks/upsert — create or replace a webhook for an event ──────────
router.post('/upsert', async (req, res, next) => {
  const { error, value } = upsertSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });

  try {
    await query(
      `INSERT INTO webhooks (username, event, url, secret)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (username, event)
       DO UPDATE SET url = EXCLUDED.url, secret = EXCLUDED.secret, updated_at = NOW();`,
      [req.user.username, value.event, value.url, value.secret]
    );
    return res.json({ success: true, message: `Webhook for ${value.event} saved` });
  } catch (err) { next(err); }
});

// ── DELETE /webhooks/delete ───────────────────────────────────────────────────
router.delete('/delete', async (req, res, next) => {
  const { error, value } = deleteSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });

  try {
    const { rowCount } = await query(
      'DELETE FROM webhooks WHERE username = $1 AND event = $2;',
      [req.user.username, value.event]
    );
    if (!rowCount) return res.status(404).json({ success: false, message: 'Webhook not found' });
    return res.json({ success: true, message: 'Webhook deleted' });
  } catch (err) { next(err); }
});

// ── POST /webhooks/test — send a test payload to a webhook ────────────────────
router.post('/test', async (req, res, next) => {
  const { error, value } = deleteSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });

  try {
    const { rows } = await query(
      'SELECT url, secret FROM webhooks WHERE username = $1 AND event = $2;',
      [req.user.username, value.event]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Webhook not found' });

    const testPayload = {
      event:     value.event,
      test:      true,
      username:  req.user.username,
      key_id:    null,
      ip:        req.ip,
      timestamp: new Date().toISOString(),
    };

    const result = await deliverWebhook(rows[0].url, rows[0].secret, testPayload);
    return res.json({ success: true, delivery: result });
  } catch (err) { next(err); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// Internal delivery engine (used by verify + scripts routes)
// ═══════════════════════════════════════════════════════════════════════════════

const DELIVERY_TIMEOUT_MS = 5_000;
const MAX_REDIRECTS       = 2;
const { createHmac }      = require('crypto');

/**
 * Deliver a webhook payload to a URL.
 * Returns { status, ok, latency_ms } — never throws.
 */
async function deliverWebhook(url, secret, payload) {
  const start   = Date.now();
  const body    = JSON.stringify(payload);
  const sig     = secret
    ? createHmac('sha256', secret).update(body).digest('hex')
    : null;

  const headers = {
    'Content-Type':    'application/json',
    'Content-Length':  Buffer.byteLength(body),
    'User-Agent':      'Synthia-Webhook/4.0',
    'X-Synthia-Event': payload.event,
    ...(sig ? { 'X-Synthia-Signature': `sha256=${sig}` } : {}),
  };

  return new Promise((resolve) => {
    let resolved = false;
    const done = (result) => { if (!resolved) { resolved = true; resolve(result); } };

    try {
      const parsed  = new URL(url);
      const lib     = parsed.protocol === 'https:' ? https : http;
      const options = {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method:   'POST',
        headers,
        timeout:  DELIVERY_TIMEOUT_MS,
      };

      const req = lib.request(options, (res) => {
        res.resume(); // drain response body
        done({ status: res.statusCode, ok: res.statusCode < 400, latency_ms: Date.now() - start });
      });

      req.on('timeout', () => {
        req.destroy();
        done({ status: 0, ok: false, latency_ms: Date.now() - start, error: 'timeout' });
      });

      req.on('error', (err) => {
        done({ status: 0, ok: false, latency_ms: Date.now() - start, error: err.message });
      });

      req.write(body);
      req.end();
    } catch (err) {
      done({ status: 0, ok: false, latency_ms: Date.now() - start, error: err.message });
    }
  });
}

/**
 * Fire webhooks for a given event + username.
 * Truly fire-and-forget — safe to call without await.
 */
async function fireWebhooks(username, event, payload) {
  try {
    const { rows } = await query(
      'SELECT id, url, secret FROM webhooks WHERE username = $1 AND event = $2;',
      [username, event]
    );
    if (!rows.length) return;

    for (const hook of rows) {
      deliverWebhook(hook.url, hook.secret, { event, username, ...payload })
        .then((result) => {
          // Update delivery stats non-blocking
          query(
            `UPDATE webhooks
             SET last_triggered_at = NOW(),
                 last_status_code  = $1,
                 total_deliveries  = total_deliveries + 1
             WHERE id = $2;`,
            [result.status, hook.id]
          ).catch(() => {});
        })
        .catch(() => {}); // swallow — never crash the process
    }
  } catch {
    // Webhook lookup failure — swallow silently
  }
}

module.exports = { router, fireWebhooks };
