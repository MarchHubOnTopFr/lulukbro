require('dotenv').config();
const express   = require('express');
const morgan    = require('morgan');
const cors      = require('cors');
const helmet    = require('helmet');
const path      = require('path');
const rateLimit = require('express-rate-limit');

const { initializeDB, closePool } = require('./db');
const { startMonitor }            = require('./utils');
const { startCron }               = require('./cron');
const { checkServerReady, setServerReady } = require('./middlewares/ready');
const { requestId }   = require('./middlewares/requestId');
const { errorHandler } = require('./middlewares/errorHandler');

const authRoutes    = require('./routes/auth');
const keyRoutes     = require('./routes/keys');
const verifyRoutes  = require('./routes/verify');
const adminRoutes   = require('./routes/admin');
const scriptRoutes  = require('./routes/scripts');
const { router: webhookRoutes } = require('./routes/webhooks');
const fingerprintRoutes = require('./routes/fingerprint');
const getKeyRoutes      = require('./routes/getkey');
const adminHwidRoutes   = require('./routes/admin_hwid');
const { initializeHWIDTables } = require('./hwid');

const app  = express();
const PORT = process.env.PORT || 18635;

// ── Trust proxy (nginx / PM2 / Docker) ───────────────────────────────────────
app.set('trust proxy', 1);

// ── Request ID (correlation) ──────────────────────────────────────────────────
app.use(requestId);

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:             ["'self'"],
      scriptSrc:              ["'self'", "'unsafe-inline'"],
      scriptSrcAttr:          ["'unsafe-inline'"],
      styleSrc:               ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:                ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:                 ["'self'", 'data:'],
      connectSrc:             ["'self'"],
      upgradeInsecureRequests: null,
    },
  },
}));

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use(cors({
  origin:  process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── Body parsing (tight limit) ────────────────────────────────────────────────
app.use(express.json({ limit: '64kb' }));

// ── HTTP logging (skip health pings to keep logs clean) ───────────────────────
app.use(morgan('combined', {
  skip: (req) => req.path === '/health',
}));

// ── Global rate limiter (generous baseline; routes add their own tighter ones) ─
app.use(rateLimit({
  windowMs: 60_000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { success: false, message: 'Too many requests — slow down.' },
}));

// ── Strict rate limiter for auth endpoints (brute-force protection) ───────────
const authLimiter = rateLimit({
  windowMs: 15 * 60_000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { success: false, message: 'Too many auth attempts — try again later.' },
});

// ── Static dashboard ──────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── Health (always available — bypasses warm-up gate) ────────────────────────
app.get('/health', (_req, res) => {
  const { getHealthSnapshot } = require('./utils');
  const pkg = require('./package.json');
  res.json({
    status:  'ok',
    version: pkg.version,
    env:     process.env.NODE_ENV || 'production',
    ...getHealthSnapshot(),
  });
});

// ── Warm-up gate ──────────────────────────────────────────────────────────────
app.use(checkServerReady);

// ── API Routes ────────────────────────────────────────────────────────────────
app.use('/auth',     authLimiter, authRoutes);
app.use('/keys',     keyRoutes);
app.use('/verify',   verifyRoutes);
app.use('/admin',    adminRoutes);
app.use('/scripts',  scriptRoutes);
app.use('/webhooks',     webhookRoutes);
app.use('/fingerprint',  fingerprintRoutes);
app.use('/getkey',       getKeyRoutes);
app.use('/admin/hwid',   adminHwidRoutes);

// ── SPA fallback (only for non-API browser navigation) ───────────────────────
const API_PREFIX = /^\/(auth|keys|verify|admin|scripts|webhooks|fingerprint|getkey)(\/|$)/;
app.get('*', (req, res) => {
  if (API_PREFIX.test(req.path))
    return res.status(404).json({ success: false, message: 'Route not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── 404 catch-all (non-GET API) ───────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ success: false, message: 'Route not found' }));

// ── Global error handler (must be last) ──────────────────────────────────────
app.use(errorHandler);

// ── Boot ──────────────────────────────────────────────────────────────────────
(async () => {
  try {
    await initializeDB();
    await initializeHWIDTables();
    startMonitor();
    startCron();
    app.listen(PORT, () => {
      console.log(`✅  Synthia API v${require('./package.json').version} → http://localhost:${PORT}`);
      setServerReady(true);
    });
  } catch (err) {
    console.error('❌  Startup failed:', err.message);
    process.exit(1);
  }
})();
