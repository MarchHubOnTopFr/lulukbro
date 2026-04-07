const { query } = require('../db');

// ── logAction — true fire-and-forget ─────────────────────────────────────────
// Deliberately NOT awaited so audit writes never add latency to API responses.
// Callers: drop the `await` keyword — just call `logAction(...)`.
function logAction(username, action, keyId = null, ip = null, metadata = {}) {
  // Intentionally un-awaited — runs in the background
  query(
    `INSERT INTO audit_logs (username, action, key_id, ip, metadata)
     VALUES ($1, $2, $3, $4, $5);`,
    [username || null, action, keyId || null, ip || null, JSON.stringify(metadata)]
  ).catch((err) => console.error('[Audit] Write failed:', err.message));
}

module.exports = { logAction };
