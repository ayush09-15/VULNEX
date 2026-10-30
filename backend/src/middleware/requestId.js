const crypto = require('crypto');

/**
 * Middleware: Request ID Generator & Tracing
 * Assigns or propagates unique request IDs across the API boundary.
 */
function requestId(req, res, next) {
  // Check for incoming client tracing header or generate new one
  const incomingId = req.headers['x-request-id'];
  const id = (typeof incomingId === 'string' && incomingId.trim())
    ? incomingId.trim()
    : `req_${crypto.randomUUID().replace(/-/g, '')}`;

  req.id = id;
  res.locals.requestId = id;
  res.setHeader('X-Request-ID', id);

  next();
}

module.exports = requestId;
