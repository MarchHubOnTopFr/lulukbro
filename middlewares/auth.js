const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;
const TOKEN_EXPIRY = process.env.JWT_EXPIRY || '7d';

if (!SECRET) {
  console.error('[Auth] ❌  JWT_SECRET is not set — refusing to start with an empty secret.');
  process.exit(1);
}
if (SECRET.length < 32) {
  console.warn('[Auth] ⚠️  JWT_SECRET is very short — use at least 32 random characters.');
}

// ── Token extraction — header only (query-string tokens leak in logs/proxies) ─
function extractToken(req) {
  const header = req.headers['authorization'] || '';
  if (header.startsWith('Bearer ')) return header.slice(7).trim();
  return null;
}

// ── authenticate — verifies JWT, attaches req.user ───────────────────────────
function authenticate(req, res, next) {
  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ success: false, message: 'Missing Authorization header' });
  }
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token has expired — please log in again' });
    }
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

// ── requireAdmin — authenticate + role guard ──────────────────────────────────
function requireAdmin(req, res, next) {
  authenticate(req, res, () => {
    if (req.user?.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    next();
  });
}

// ── signToken — always uses the env secret ────────────────────────────────────
function signToken(payload, expiresIn = TOKEN_EXPIRY) {
  return jwt.sign(payload, SECRET, { expiresIn });
}

module.exports = { authenticate, requireAdmin, signToken };
