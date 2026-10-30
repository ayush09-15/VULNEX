const express = require('express');
const router = express.Router();
const apiResponse = require('../utils/apiResponse');

/**
 * GET /api/health
 * Lightweight health check endpoint verifying service liveness
 */
router.get('/', (req, res) => {
  return apiResponse.success(res, {
    status: 'healthy',
    service: 'vulnex-api'
  }, 200);
});

module.exports = router;
