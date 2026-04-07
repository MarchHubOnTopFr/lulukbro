/**
 * cron.js — Scheduled maintenance tasks.
 *
 * Run standalone via PM2 or cron:
 *   node cron.js              (runs all tasks once then exits)
 *   node cron.js expire-keys
 *   node cron.js prune-logs
 *
 * Or import startCron() in server.js to run on an interval inside the main process.
 */
require('dotenv').config();
const { query, initializeDB, closePool } = require('./db');
const { log } = require('./utils');

const LOG_RETENTION_DAYS = parseInt(process.env.AUDIT_LOG_RETENTION_DAYS || '90');
const CRON_INTERVAL_MS   = parseInt(process.env.CRON_INTERVAL_MS || String(6 * 60 * 60 * 1000)); // 6 h

// ── Task: disable expired keys ────────────────────────────────────────────────
async function expireKeys() {
  const { rowCount } = await query(
    `UPDATE user_keys
     SET status = 'disabled'
     WHERE status = 'active'
       AND expires_at IS NOT NULL
       AND expires_at < NOW();`
  );
  if (rowCount > 0) log('info', '[Cron] expire-keys', { disabled: rowCount });
  return rowCount;
}

// ── Task: prune old audit logs ────────────────────────────────────────────────
async function pruneLogs() {
  const { rowCount } = await query(
    `DELETE FROM audit_logs
     WHERE created_at < NOW() - ($1 || ' days')::INTERVAL;`,
    [LOG_RETENTION_DAYS]
  );
  if (rowCount > 0) log('info', '[Cron] prune-logs', { deleted: rowCount, retention_days: LOG_RETENTION_DAYS });
  return rowCount;
}


// ── Task: prune old fingerprint logs ─────────────────────────────────────────
async function pruneFingerprints() {
  const { rowCount } = await query(
    `DELETE FROM fingerprint_logs WHERE created_at < NOW() - INTERVAL '30 days';`
  );
  if (rowCount > 0) log('info', '[Cron] prune-fingerprints', { deleted: rowCount });
  return rowCount;
}

// ── Task: expire consumed / stale pending key tokens ─────────────────────────
async function expirePendingTokens() {
  const { rowCount } = await query(
    `DELETE FROM pending_keys WHERE expires_at < NOW() - INTERVAL '10 minutes';`
  );
  if (rowCount > 0) log('info', '[Cron] expire-pending-tokens', { deleted: rowCount });
  return rowCount;
}

// ── Task: prune stale webhook delivery stats (reset counters older than 30 d) ─
async function resetWebhookStats() {
  const { rowCount } = await query(
    `UPDATE webhooks
     SET total_deliveries = 0,
         last_triggered_at = NULL,
         last_status_code  = NULL
     WHERE last_triggered_at IS NOT NULL
       AND last_triggered_at < NOW() - INTERVAL '30 days';`
  );
  if (rowCount > 0) log('info', '[Cron] reset-webhook-stats', { reset: rowCount });
  return rowCount;
}

// ── Run all tasks once ────────────────────────────────────────────────────────
async function runAll() {
  const results = {};
  results.expired_keys   = await expireKeys().catch(err => { log('error', '[Cron] expire-keys failed', { err: err.message }); return 0; });
  results.pruned_logs    = await pruneLogs().catch(err  => { log('error', '[Cron] prune-logs failed',  { err: err.message }); return 0; });
  results.pruned_fingerprints = await pruneFingerprints().catch(err  => { log('error', '[Cron] prune-fingerprints failed', { err: err.message }); return 0; });
  results.expired_tokens      = await expirePendingTokens().catch(err => { log('error', '[Cron] expire-tokens failed', { err: err.message }); return 0; });
  results.reset_webhooks = await resetWebhookStats().catch(err => { log('error', '[Cron] reset-webhook-stats failed', { err: err.message }); return 0; });
  log('info', '[Cron] cycle complete', results);
  return results;
}

// ── Embedded interval (call from server.js) ───────────────────────────────────
let cronTimer = null;
function startCron() {
  if (cronTimer) return;
  // Run immediately on boot, then on interval
  runAll().catch(() => {});
  cronTimer = setInterval(() => runAll().catch(() => {}), CRON_INTERVAL_MS);
  cronTimer.unref(); // don't prevent process exit
  log('info', `[Cron] Started — interval ${CRON_INTERVAL_MS / 1000}s, log retention ${LOG_RETENTION_DAYS}d`);
}

function stopCron() {
  if (cronTimer) { clearInterval(cronTimer); cronTimer = null; }
}

// ── Standalone execution ──────────────────────────────────────────────────────
if (require.main === module) {
  const task = process.argv[2];
  const tasks = { 'expire-keys': expireKeys, 'prune-logs': pruneLogs };

  (async () => {
    await initializeDB();
    if (task && tasks[task]) {
      const n = await tasks[task]();
      console.log(`Done: ${n} row(s) affected.`);
    } else {
      await runAll();
    }
    await closePool();
  })().catch(err => { console.error(err.message); process.exit(1); });
}

module.exports = { startCron, stopCron, expireKeys, pruneLogs };
