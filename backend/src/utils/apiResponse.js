/**
 * Standard VULNEX API Response Utilities
 * Enforces canonical success and error envelope contracts.
 */

/**
 * Send standard success envelope
 * @param {import('express').Response} res
 * @param {Object|Array|null} [data={}]
 * @param {number} [statusCode=200]
 */
function success(res, data = {}, statusCode = 200) {
  const requestId = res.req?.id || res.locals?.requestId || 'req_unknown';

  return res.status(statusCode).json({
    success: true,
    data,
    requestId
  });
}

/**
 * Send standard error envelope
 * Never exposes stack traces or internal secrets to clients
 * @param {import('express').Response} res
 * @param {Object} errorParams
 * @param {string} [errorParams.code='INTERNAL_SERVER_ERROR'] Machine-readable error code
 * @param {string} [errorParams.message='An unexpected error occurred.'] Client-safe message
 * @param {Array|Object} [errorParams.details] Non-sensitive validation or context details
 * @param {number} [statusCode=500]
 */
function error(res, { code = 'INTERNAL_SERVER_ERROR', message = 'An unexpected error occurred.', details }, statusCode = 500) {
  const requestId = res.req?.id || res.locals?.requestId || 'req_unknown';

  const errorPayload = {
    code: String(code).toUpperCase(),
    message: String(message)
  };

  if (details !== undefined && details !== null) {
    errorPayload.details = details;
  }

  return res.status(statusCode).json({
    success: false,
    error: errorPayload,
    requestId
  });
}

module.exports = {
  success,
  error
};
