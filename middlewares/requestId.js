const { randomBytes } = require('crypto');

/**
 * Attaches a short unique ID to every request.
 * Returned in the X-Request-Id response header so clients/logs can correlate.
 */
function requestId(req, res, next) {
  req.id = randomBytes(8).toString('hex');
  res.setHeader('X-Request-Id', req.id);
  next();
}

module.exports = { requestId };
