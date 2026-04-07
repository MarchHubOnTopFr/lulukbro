require('dotenv').config();
const { Pool } = require('pg');

// ── Pool configuration ────────────────────────────────────────────────────────
const pool = new Pool({
  user:                    process.env.DB_USER     || 'koku',
  host:                    process.env.DB_HOST     || 'localhost',
  database:                process.env.DB_NAME     || 'dtb',
  password:                process.env.DB_PASSWORD,
  port:                    parseInt(process.env.DB_PORT || '5432'),
  max:                     parseInt(process.env.DB_POOL_MAX || '20'),
  min:                     parseInt(process.env.DB_POOL_MIN || '2'),
  idleTimeoutMillis:       30_000,
  connectionTimeoutMillis: 5_000,
  statement_timeout:       10_000,  // Kill runaway queries after 10 s
});

pool.on('error', (err) => console.error('[DB] Pool error:', err.message));
pool.on('connect', ()  => { /* optional: set search_path, timezone, etc. */ });

// ── query — uses pool directly (no manual acquire/release overhead) ───────────
async function query(sql, params = []) {
  try {
    const result = await pool.query(sql, params);
    return { rows: result.rows, rowCount: result.rowCount };
  } catch (err) {
    console.error(`[DB] Error: ${err.message} | SQL: ${sql.slice(0, 100)}`);
    throw err;
  }
}

// ── transaction — wraps multiple queries in a single ACID transaction ─────────
async function transaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ── closePool — for graceful shutdown ─────────────────────────────────────────
async function closePool() {
  await pool.end();
}

// ── initializeDB ─────────────────────────────────────────────────────────────
async function initializeDB() {
  // ── Core tables ─────────────────────────────────────────────────────────────
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      username   TEXT PRIMARY KEY,
      password   TEXT NOT NULL,
      role       TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS user_keys (
      id               SERIAL PRIMARY KEY,
      username         TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      key              TEXT NOT NULL UNIQUE,
      hwid             TEXT,                            -- NULL = unbound (replaces 'Nil' string)
      status           TEXT NOT NULL DEFAULT 'active',
      note             TEXT NOT NULL DEFAULT '',
      expires_at       TIMESTAMPTZ,
      last_used_at     TIMESTAMPTZ,
      hwid_reset_count INT  NOT NULL DEFAULT 0,
      hwid_reset_at    TIMESTAMPTZ,
      created_at       TIMESTAMPTZ DEFAULT NOW(),
      CONSTRAINT chk_status CHECK (status IN ('active', 'disabled'))
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id         BIGSERIAL PRIMARY KEY,
      username   TEXT,
      action     TEXT NOT NULL,
      key_id     INT,
      ip         TEXT,
      metadata   JSONB DEFAULT '{}',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // ── scripts table — Luarmor-style: protected Lua scripts tied to a user ─────
  await query(`
    CREATE TABLE IF NOT EXISTS scripts (
      id          SERIAL PRIMARY KEY,
      username    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      source      TEXT NOT NULL DEFAULT '',          -- raw Lua source stored server-side
      version     TEXT NOT NULL DEFAULT '1.0.0',
      enabled     BOOLEAN NOT NULL DEFAULT TRUE,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      updated_at  TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (username, name)
    );
  `);

  // ── key_scripts — many-to-many: which keys can load which scripts ───────────
  await query(`
    CREATE TABLE IF NOT EXISTS key_scripts (
      key_id    INT NOT NULL REFERENCES user_keys(id) ON DELETE CASCADE,
      script_id INT NOT NULL REFERENCES scripts(id)  ON DELETE CASCADE,
      PRIMARY KEY (key_id, script_id)
    );
  `);

  // ── webhooks table
  await query(`
    CREATE TABLE IF NOT EXISTS webhooks (
      id                SERIAL PRIMARY KEY,
      username          TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      event             TEXT NOT NULL,
      url               TEXT NOT NULL,
      secret            TEXT NOT NULL DEFAULT '',
      total_deliveries  INT  NOT NULL DEFAULT 0,
      last_triggered_at TIMESTAMPTZ,
      last_status_code  INT,
      created_at        TIMESTAMPTZ DEFAULT NOW(),
      updated_at        TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (username, event)
    );
  `);

  // ── Safe migrations (idempotent) ────────────────────────────────────────────
  const migrations = [
    `ALTER TABLE users     ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';`,
    `ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS status           TEXT NOT NULL DEFAULT 'active';`,
    `ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS note             TEXT NOT NULL DEFAULT '';`,
    `ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS expires_at       TIMESTAMPTZ;`,
    `ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS last_used_at     TIMESTAMPTZ;`,
    `ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS hwid_reset_count INT  NOT NULL DEFAULT 0;`,
    `ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS hwid_reset_at    TIMESTAMPTZ;`,
    // Migrate legacy 'Nil' string HWIDs to proper NULL
    `UPDATE user_keys SET hwid = NULL WHERE hwid = 'Nil';`,
    // Allow hwid to be nullable if it was previously NOT NULL
    `ALTER TABLE user_keys ALTER COLUMN hwid DROP NOT NULL;`,
    `ALTER TABLE user_keys ALTER COLUMN hwid DROP DEFAULT;`,
  ];
  for (const sql of migrations) {
    try { await query(sql); } catch { /* column already correct — skip */ }
  }

  // ── Indexes ──────────────────────────────────────────────────────────────────
  const indexes = [
    // Primary lookup: verify hot-path (key lookup by value)
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_ukeys_key         ON user_keys(key);`,
    // User's key list
    `CREATE        INDEX IF NOT EXISTS idx_ukeys_username    ON user_keys(username);`,
    // Composite: user + key (ownership checks in one index scan)
    `CREATE        INDEX IF NOT EXISTS idx_ukeys_user_key    ON user_keys(username, key);`,
    // Status filter
    `CREATE        INDEX IF NOT EXISTS idx_ukeys_status      ON user_keys(status);`,
    // Expiry sweep
    `CREATE        INDEX IF NOT EXISTS idx_ukeys_expires     ON user_keys(expires_at) WHERE expires_at IS NOT NULL;`,
    // Audit log queries
    `CREATE        INDEX IF NOT EXISTS idx_alogs_username    ON audit_logs(username);`,
    `CREATE        INDEX IF NOT EXISTS idx_alogs_created     ON audit_logs(created_at DESC);`,
    `CREATE        INDEX IF NOT EXISTS idx_alogs_action      ON audit_logs(action);`,
    // Script lookups
    `CREATE        INDEX IF NOT EXISTS idx_scripts_username  ON scripts(username);`,
  ];
  for (const sql of indexes) await query(sql);

  console.log('[DB] ✅  Database ready.');
}

module.exports = { query, transaction, closePool, initializeDB };
