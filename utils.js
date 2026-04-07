const os      = require('os');
const process = require('process');

const MEMORY_THRESHOLD = parseFloat(process.env.MEMORY_THRESHOLD     || '85');
const UPTIME_LIMIT     = parseInt(process.env.UPTIME_LIMIT_HOURS      || '48') * 3600;
const MONITOR_INTERVAL = parseInt(process.env.MONITOR_INTERVAL_MS     || '300000');

let monitorTimer = null;

// ── Structured log helpers ────────────────────────────────────────────────────
// Always emit JSON when NODE_ENV=production so log aggregators (Datadog, Loki,
// CloudWatch) can parse fields. In dev, emit readable text.
const IS_PROD = process.env.NODE_ENV === 'production';

function log(level, message, meta = {}) {
  if (IS_PROD) {
    process.stdout.write(JSON.stringify({
      ts: new Date().toISOString(),
      level,
      message,
      pid: process.pid,
      ...meta,
    }) + '\n');
  } else {
    const prefix = level === 'error' ? '❌' : level === 'warn' ? '⚠️' : 'ℹ️';
    const extra  = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
    console[level === 'info' ? 'log' : level](`${prefix}  ${message}${extra}`);
  }
}

// ── Process health snapshot ───────────────────────────────────────────────────
function getHealthSnapshot() {
  const memUsed = process.memoryUsage();
  const sysMem  = os.totalmem();
  const freeMem = os.freemem();
  return {
    uptime_s:      Math.floor(process.uptime()),
    sys_mem_pct:   (((sysMem - freeMem) / sysMem) * 100).toFixed(1),
    heap_used_mb:  (memUsed.heapUsed  / 1_048_576).toFixed(1),
    heap_total_mb: (memUsed.heapTotal / 1_048_576).toFixed(1),
    rss_mb:        (memUsed.rss       / 1_048_576).toFixed(1),
    load_avg:      os.loadavg().map(n => n.toFixed(2)),
  };
}

// ── Graceful shutdown ─────────────────────────────────────────────────────────
let shuttingDown = false;
function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log('info', `${signal} received — shutting down gracefully`);
  if (monitorTimer) clearInterval(monitorTimer);

  const { closePool } = require('./db');
  closePool()
    .catch((e) => log('error', 'Pool close error during shutdown', { err: e.message }))
    .finally(() => {
      log('info', 'Shutdown complete');
      setTimeout(() => process.exit(0), 300);
    });
}

// ── Monitor loop ──────────────────────────────────────────────────────────────
function startMonitor() {
  if (monitorTimer) return;

  monitorTimer = setInterval(() => {
    const snap  = getHealthSnapshot();
    const memPct = parseFloat(snap.sys_mem_pct);

    // Always log health in production for observability
    if (IS_PROD) log('info', 'health_tick', snap);

    if (memPct > MEMORY_THRESHOLD)
      log('warn', `High system memory: ${snap.sys_mem_pct}%`, snap);

    if (snap.uptime_s > UPTIME_LIMIT) {
      log('info', `Uptime limit (${UPTIME_LIMIT / 3600}h) reached — restarting`);
      gracefulShutdown('UPTIME_LIMIT');
    }
  }, MONITOR_INTERVAL);

  // Unref so the timer doesn't prevent process exit
  monitorTimer.unref();
}

// ── Signal handlers ───────────────────────────────────────────────────────────
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

// Catch unhandled promise rejections — log and stay alive (don't crash on transient errors)
process.on('unhandledRejection', (reason) => {
  log('error', 'Unhandled promise rejection', { reason: String(reason) });
});

// Catch uncaught exceptions — log then exit (PM2 will restart)
process.on('uncaughtException', (err) => {
  log('error', 'Uncaught exception — forcing restart', { err: err.message, stack: err.stack });
  gracefulShutdown('uncaughtException');
});

module.exports = { startMonitor, getHealthSnapshot, log };
