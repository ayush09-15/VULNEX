const express = require('express');
const router = express.Router();
const apiResponse = require('../utils/apiResponse');

/**
 * GET /api/health
 * Lightweight health check endpoint verifying service liveness
 */
router.get('/', (req, res) => {
  try {
    return apiResponse.success(res, {
      status: 'healthy',
      service: 'vulnex-api'
    }, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'HEALTH_CHECK_FAILED',
      message: err.message || 'Health check encountered an internal failure'
    }, 500);
  }
});

module.exports = router;

