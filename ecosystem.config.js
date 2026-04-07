module.exports = {
  apps: [{
    name:             'synthia-api',
    script:           'server.js',
    instances:        'max',       // one worker per CPU core
    exec_mode:        'cluster',
    watch:            false,
    max_memory_restart: '512M',

    // ── Environment ────────────────────────────────────────────────────────────
    env: {
      NODE_ENV: 'production',
    },
    env_development: {
      NODE_ENV: 'development',
      instances: 1,
      exec_mode: 'fork',
    },

    // ── Logging ────────────────────────────────────────────────────────────────
    error_file:      './logs/err.log',
    out_file:        './logs/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs:      true,       // merge cluster worker logs into one file

    // ── Restart policy ─────────────────────────────────────────────────────────
    autorestart:        true,
    restart_delay:      2000,    // wait 2 s before restarting to avoid hammering DB
    max_restarts:       10,
    min_uptime:         '5s',    // must stay up 5 s to count as a successful start
    exp_backoff_restart_delay: 100,

    // ── Graceful shutdown ──────────────────────────────────────────────────────
    kill_timeout:  5000,         // ms to wait for graceful SIGTERM before SIGKILL
    listen_timeout: 8000,        // ms to wait for app to start listening
  }],
};
