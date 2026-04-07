/**
 * Central error-handling middleware.
 * Must be registered LAST with app.use() — Express identifies it by the 4-arg signature.
 *
 * Catches:
 *  - Errors thrown inside async route handlers (when passed via next(err))
 *  - Errors passed explicitly via next(err)
 *  - JSON body-parser syntax errors
 */
function errorHandler(err, req, res, _next) {
  // ── JSON body parse error ────────────────────────────────────────────────────
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, message: 'Invalid JSON body' });
  }

  // ── Payload too large ────────────────────────────────────────────────────────
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, message: 'Request body too large' });
  }

  // ── Known operational errors (thrown deliberately) ───────────────────────────
  if (err.isOperational) {
    return res.status(err.statusCode || 400).json({ success: false, message: err.message });
  }

  // ── Unexpected errors — log full stack, return generic message ───────────────
  const reqId = req.id || '-';
  console.error(`[${reqId}] Unhandled error on ${req.method} ${req.path}:`, err);

  res.status(500).json({ success: false, message: 'Internal server error' });
}

module.exports = { errorHandler };
