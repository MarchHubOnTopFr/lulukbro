const express  = require('express');
const bcrypt   = require('bcryptjs');
const Joi      = require('joi');
const { query, transaction } = require('../db');
const { signToken, authenticate } = require('../middlewares/auth');

const router = express.Router();

const credSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(50).required(),
  password: Joi.string().min(6).max(255).required(),
});

// ── GET /auth/me ──────────────────────────────────────────────────────────────
router.get('/me', authenticate, async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT username, role, created_at FROM users WHERE username = $1;',
      [req.user.username]
    );
    if (!rows.length)
      return res.status(404).json({ success: false, message: 'User not found' });
    return res.json({ success: true, user: rows[0] });
  } catch (err) { next(err); }
});

// ── POST /auth/signup ─────────────────────────────────────────────────────────
router.post('/signup', async (req, res, next) => {
  const { error, value } = credSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });

  const { username, password } = value;
  try {
    const hash = await bcrypt.hash(password, 12);

    // Atomic transaction: insert user → fail fast on duplicate
    const user = await transaction(async (client) => {
      const { rows } = await client.query(
        'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING username, role;',
        [username, hash]
      );
      return rows[0];
    });

    const token = signToken({ username: user.username, role: user.role });
    return res.status(201).json({ success: true, token, role: user.role });
  } catch (err) {
    // PostgreSQL unique violation on username
    if (err.code === '23505') {
      return res.status(409).json({ success: false, message: 'Username already taken' });
    }
    next(err);
  }
});

// ── POST /auth/login ──────────────────────────────────────────────────────────
router.post('/login', async (req, res, next) => {
  const { error, value } = credSchema.validate(req.body);
  if (error) return res.status(400).json({ success: false, message: error.details[0].message });

  const { username, password } = value;
  try {
    const { rows } = await query(
      'SELECT password, role FROM users WHERE username = $1;',
      [username]
    );
    // Use constant-time compare even on "not found" to avoid timing oracle
    const hash  = rows[0]?.password || '$2a$12$invalidhashpadding000000000000000000000000000000000000';
    const valid = await bcrypt.compare(password, hash);

    if (!rows.length || !valid)
      return res.status(401).json({ success: false, message: 'Invalid username or password' });

    const token = signToken({ username, role: rows[0].role });
    return res.json({ success: true, token, role: rows[0].role });
  } catch (err) { next(err); }
});

module.exports = router;

