const express = require('express');
const router = express.Router();
const apiResponse = require('../utils/apiResponse');
const { scanOrchestrator } = require('../orchestrator/scanOrchestrator');
const { validateCreateScan } = require('../validators/canonical.schema');
const repositoryService = require('../services/repository.service');
const reportService = require('../services/report.service');

/**
 * ============================================================================
 * VULNEX Scan Endpoints
 * 
 * Canonical contracts:
 * - docs/API_CONTRACTS.md (Section 3.2: Scan Execution & Timeline Management)
 * - Bible Part IV Section 4.7
 * ============================================================================
 */

/**
 * GET /api/scans
 * List all scan execution records
 */
router.get('/', (req, res) => {
  try {
    const scans = scanOrchestrator.listScans();
    return apiResponse.success(res, scans, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'INTERNAL_SERVER_ERROR',
      message: err.message
    }, 500);
  }
});

/**
 * POST /api/scans
 * Initiate a new security scan
 */
router.post('/', async (req, res) => {
  try {
    const { repositoryId, ref, scanners, repositoryPath } = req.body;

    if (!repositoryId) {
      return apiResponse.error(res, {
        code: 'INVALID_INPUT',
        message: 'Missing required field: "repositoryId".'
      }, 400);
    }

    // Determine target workspace path
    let targetPath = repositoryPath;
    if (!targetPath && repositoryId) {
      const repo = repositoryService.getRepositoryById(repositoryId);
      if (repo && repo.workspacePath) {
        targetPath = repo.workspacePath;
      }
    }

    // Default to local workspace or fixture if not specified
    if (!targetPath) {
      targetPath = './';
    }

    const validation = validateCreateScan({
      repositoryId,
      ref: ref || 'main',
      scanners: Array.isArray(scanners) ? scanners : undefined
    });

    if (!validation.success) {
      return apiResponse.error(res, {
        code: 'INVALID_INPUT',
        message: validation.error.issues[0]?.message || 'Invalid scan request parameters.',
        details: validation.error.issues
      }, 400);
    }

    const scanRecord = await scanOrchestrator.startScan({
      repositoryId,
      repositoryPath: targetPath,
      ref: validation.data.ref,
      scanners: validation.data.scanners
    });

    return apiResponse.success(res, scanRecord, 201);
  } catch (err) {
    const clientCodes = ['INVALID_INPUT', 'WORKSPACE_ERROR', 'BAD_REQUEST'];
    const statusCode = clientCodes.includes(err.code) ? 400 : 500;
    return apiResponse.error(res, {
      code: err.code || 'SCAN_INITIATION_FAILED',
      message: err.message
    }, statusCode);
  }
});

/**
 * GET /api/scans/:id
 * Retrieve specific scan details with real stage and summary
 */
router.get('/:id', (req, res) => {
  try {
    const scan = scanOrchestrator.getScan(req.params.id);
    if (!scan) {
      return apiResponse.error(res, {
        code: 'RESOURCE_NOT_FOUND',
        message: `Scan not found: ${req.params.id}`
      }, 404);
    }

    return apiResponse.success(res, scan, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'INTERNAL_SERVER_ERROR',
      message: err.message
    }, 500);
  }
});

/**
 * GET /api/scans/:id/events
 * Expose real stage event timeline API for progress tracking
 */
router.get('/:id/events', (req, res) => {
  try {
    const scan = scanOrchestrator.getScan(req.params.id);
    if (!scan) {
      return apiResponse.error(res, {
        code: 'RESOURCE_NOT_FOUND',
        message: `Scan not found: ${req.params.id}`
      }, 404);
    }

    const events = scanOrchestrator.getScanEvents(req.params.id);
    return apiResponse.success(res, events || [], 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'INTERNAL_SERVER_ERROR',
      message: err.message
    }, 500);
  }
});

/**
 * GET /api/scans/:id/findings
 * Retrieve normalized findings for a specific scan with optional filters
 */
router.get('/:id/findings', (req, res) => {
  try {
    const scan = scanOrchestrator.getScan(req.params.id);
    if (!scan) {
      return apiResponse.error(res, {
        code: 'RESOURCE_NOT_FOUND',
        message: `Scan not found: ${req.params.id}`
      }, 404);
    }

    const { severity, category, scanner, status } = req.query;
    const findings = scanOrchestrator.getScanFindings(req.params.id, {
      severity,
      category,
      scanner,
      status
    });

    return apiResponse.success(res, findings, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'INTERNAL_SERVER_ERROR',
      message: err.message
    }, 500);
  }
});

/**
 * GET /api/scans/:id/report
 * Retrieve consolidated, evidence-backed security scan report (Commit 41)
 * Acceptance Gate: Tools, findings, AI, patch and checks.
 */
router.get('/:id/report', (req, res) => {
  try {
    const report = reportService.generateScanReport(req.params.id, {
      format: req.query.format || 'json'
    });
    return apiResponse.success(res, report, 200);
  } catch (err) {
    const statusCode = err.statusCode || (err.code === 'RESOURCE_NOT_FOUND' ? 404 : 500);
    return apiResponse.error(res, {
      code: err.code || 'REPORT_GENERATION_FAILED',
      message: err.message
    }, statusCode);
  }
});

/**
 * POST /api/scans/:id/cancel
 * Cancel an active in-flight scan
 */
router.post('/:id/cancel', (req, res) => {
  try {
    const { reason } = req.body || {};
    const scan = scanOrchestrator.getScan(req.params.id);

    if (!scan) {
      return apiResponse.error(res, {
        code: 'RESOURCE_NOT_FOUND',
        message: `Scan not found: ${req.params.id}`
      }, 404);
    }

    const updatedScan = scanOrchestrator.cancelScan(req.params.id, reason);
    return apiResponse.success(res, updatedScan, 200);
  } catch (err) {
    const statusCode = err.statusCode || (err.code === 'INVALID_STATE_TRANSITION' ? 409 : 500);
    return apiResponse.error(res, {
      code: err.code || 'CANCEL_FAILED',
      message: err.message
    }, statusCode);
  }
});

/**
 * DELETE /api/scans/:id
 * Remove a scan and its associated findings
 */
router.delete('/:id', (req, res) => {
  try {
    const deleted = scanOrchestrator.deleteScan(req.params.id);
    if (!deleted) {
      return apiResponse.error(res, {
        code: 'RESOURCE_NOT_FOUND',
        message: `Scan not found: ${req.params.id}`
      }, 404);
    }

    return apiResponse.success(res, { deleted: true, id: req.params.id }, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'INTERNAL_SERVER_ERROR',
      message: err.message
    }, 500);
  }
});

module.exports = router;
