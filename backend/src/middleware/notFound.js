const apiResponse = require('../utils/apiResponse');

/**
 * Middleware: 404 Not Found Handler
 * Catches all unmatched requests and returns canonical error envelope.
 */
function notFound(req, res, next) {
  return apiResponse.error(
    res,
    {
      code: 'RESOURCE_NOT_FOUND',
      message: `The requested endpoint ${req.method} ${req.originalUrl || req.url} does not exist.`
    },
    404
  );
}

module.exports = notFound;
