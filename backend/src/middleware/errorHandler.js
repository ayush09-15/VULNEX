const apiResponse = require('../utils/apiResponse');

/**
 * Centralized Error Handling Middleware
 * Intercepts uncaught exceptions and rejected promises.
 * Never leaks stack traces, secrets, or internal paths to clients.
 */
function errorHandler(err, req, res, next) {
  // If response headers already sent, delegate to default express handler
  if (res.headersSent) {
    return next(err);
  }

  const statusCode = (typeof err.statusCode === 'number' && err.statusCode >= 400 && err.statusCode < 600)
    ? err.statusCode
    : (typeof err.status === 'number' && err.status >= 400 && err.status < 600)
      ? err.status
      : 500;

  const code = err.code || (statusCode === 404 ? 'RESOURCE_NOT_FOUND' : 'INTERNAL_SERVER_ERROR');

  // Provide safe human-readable message without leaking internal exceptions or stack traces
  const message = (statusCode < 500 && err.message)
    ? err.message
    : 'An unexpected internal server error occurred.';

  // Server-side logging only
  console.error(`[Error] [${req.id || 'no-request-id'}] ${req.method} ${req.originalUrl || req.url}:`, err.message || err);

  return apiResponse.error(
    res,
    {
      code,
      message,
      details: err.details || undefined
    },
    statusCode
  );
}

module.exports = errorHandler;
