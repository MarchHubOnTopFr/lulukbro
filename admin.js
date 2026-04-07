#!/usr/bin/env node
/**
 * Synthia Admin CLI — run once to seed the first admin account.
 *
 * Usage:
 *   node admin.js create-admin <username> <password>
 *   node admin.js list-admins
 *   node admin.js promote <username>
 *   node admin.js expire-keys
 *   node admin.js stats
 */
require('dotenv').config();
const bcrypt = require('bcryptjs');
const { query, initializeDB, closePool } = require('./db');

const [,, command, ...args] = process.argv;

const COMMANDS = {
  'create-admin': createAdmin,
  'list-admins':  listAdmins,
  'promote':      promoteUser,
  'expire-keys':  expireKeys,
  'stats':        printStats,
};

async function run() {
  if (!command || !COMMANDS[command]) {
    console.log('Synthia Admin CLI\n\nAvailable commands:');
    Object.keys(COMMANDS).forEach(c => console.log('  node admin.js', c));
    process.exit(0);
  }
  try {
    await initializeDB();
    await COMMANDS[command](...args);
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  } finally {
    await closePool();
  }
}

async function createAdmin(username, password) {
  if (!username || !password) {
    console.error('Usage: node admin.js create-admin <username> <password>');
    process.exit(1);
  }
  if (password.length < 6) { console.error('Password must be >= 6 chars.'); process.exit(1); }
  const hash = await bcrypt.hash(password, 12);
  await query(
    `INSERT INTO users (username, password, role) VALUES ($1, $2, 'admin')
     ON CONFLICT (username) DO UPDATE SET role = 'admin', password = EXCLUDED.password;`,
    [username, hash]
  );
  console.log(`Admin '${username}' created/updated.`);
}

async function listAdmins() {
  const { rows } = await query(
    `SELECT username, created_at FROM users WHERE role = 'admin' ORDER BY created_at;`
  );
  if (!rows.length) { console.log('No admin accounts.'); return; }
  rows.forEach(r => console.log(`  ${r.username}  (${r.created_at.toISOString()})`));
}

async function promoteUser(username) {
  if (!username) { console.error('Usage: node admin.js promote <username>'); process.exit(1); }
  const { rowCount } = await query(`UPDATE users SET role = 'admin' WHERE username = $1;`, [username]);
  if (!rowCount) { console.error(`User '${username}' not found.`); process.exit(1); }
  console.log(`'${username}' promoted to admin.`);
}

async function expireKeys() {
  const { rowCount } = await query(
    `UPDATE user_keys SET status = 'disabled'
     WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < NOW();`
  );
  console.log(`${rowCount} expired key(s) disabled.`);
}

async function printStats() {
  const { rows: [s] } = await query(`
    SELECT
      (SELECT COUNT(*)::int FROM users)                                           AS total_users,
      (SELECT COUNT(*)::int FROM users WHERE role = 'admin')                      AS admin_users,
      COUNT(*)::int                                                               AS total_keys,
      COUNT(*) FILTER (WHERE status = 'active')::int                             AS active_keys,
      COUNT(*) FILTER (WHERE status = 'disabled')::int                           AS disabled_keys,
      COUNT(*) FILTER (WHERE hwid IS NOT NULL)::int                              AS bound_keys,
      COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at < NOW())::int AS expired_keys,
      (SELECT COUNT(*)::int FROM audit_logs)                                      AS total_audit_logs,
      (SELECT COUNT(*)::int FROM scripts)                                         AS total_scripts,
      (SELECT COUNT(*)::int FROM webhooks)                                        AS total_webhooks
    FROM user_keys;
  `);
  console.log('\nSynthia System Stats\n' + '─'.repeat(30));
  Object.entries(s).forEach(([k, v]) => console.log(`  ${k.padEnd(22)} ${v}`));
}

run();
