/**
 * Centralised error handler — must be registered LAST with app.use().
 * Catches errors thrown/passed via next(err) from any route.
 */
function errorHandler(err, req, res, _next) {
  const reqId = req.id || '-';

  // Joi validation errors forwarded via next(err)
  if (err.isJoi) {
    return res.status(400).json({
      success: false,
      message: err.details[0].message,
    });
  }

  // PostgreSQL unique-violation (code 23505)
  if (err.code === '23505') {
    return res.status(409).json({
      success: false,
      message: 'A record with that value already exists.',
    });
  }

  // PostgreSQL foreign-key violation (code 23503)
  if (err.code === '23503') {
    return res.status(404).json({
      success: false,
      message: 'Referenced resource not found.',
    });
  }

  // Generic server error — never leak internals
  console.error(`[Error] reqId=${reqId} ${err.stack || err.message}`);
  return res.status(500).json({
    success: false,
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' ? { detail: err.message } : {}),
  });
}

module.exports = { errorHandler };
