const apiResponse = require('../utils/apiResponse');
const { redactString, redactDeep, safeLogger } = require('../utils/secretRedactor');

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

  // Provide safe human-readable message without leaking internal exceptions, stack traces, or credentials
  const rawMessage = (statusCode < 500 && err.message)
    ? err.message
    : 'An unexpected internal server error occurred.';
  const message = redactString(rawMessage);

  // Redacted server-side logging
  const safePath = redactString(req.originalUrl || req.url || '');
  const safeErrLog = err.message ? redactString(err.message) : err;
  safeLogger.error(`[Error] [${req.id || 'no-request-id'}] ${req.method} ${safePath}:`, safeErrLog);

  return apiResponse.error(
    res,
    {
      code,
      message,
      details: err.details ? redactDeep(err.details) : undefined
    },
    statusCode
  );
}

module.exports = errorHandler;

