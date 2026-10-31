/**
 * VULNEX Patches & Human Review State HTTP Routes
 *
 * Implements:
 * - Master Antigravity Execution Bible Section 4.7 & Section 8.7
 * - docs/API_CONTRACTS.md Section 2.4 (Patch APIs)
 *   * GET  /api/patches - List patches with optional filters
 *   * GET  /api/patches/:id - Retrieve patch proposal & review state
 *   * POST /api/patches/:id/approve - Explicit human approval
 *   * POST /api/patches/:id/reject - Explicit human rejection
 *   * POST /api/patches/:id/apply - Apply approved patch to disposable workspace ONLY
 *   * POST /api/patches/:id/rollback - Rollback patch in disposable workspace
 *   * POST /api/patches/:id/verify - Verify patch inside disposable workspace
 * - Commit 34 Gate: "No apply without explicit confirmation and valid state."
 * - Commit 37 Gate: "State transition and audit event tests"
 * - Commit 38 Gate: "Tool version, command, exit code and output"
 */

const express = require('express');
const router = express.Router();
const apiResponse = require('../utils/apiResponse');
const patchService = require('../services/patch.service');
const verificationService = require('../services/verification.service');

// ----------------------------------------------------------------------------
// GET /api/patches - List patches with optional filters
// ----------------------------------------------------------------------------
router.get('/', (req, res) => {
  try {
    const { findingId, status, reviewState } = req.query;
    const patches = patchService.listPatches({ findingId, status, reviewState });
    return apiResponse.success(res, patches, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'PATCH_LIST_FAILED',
      message: err.message || 'Failed to list patches.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// GET /api/patches/:id - Retrieve patch by ID
// ----------------------------------------------------------------------------
router.get('/:id', (req, res) => {
  try {
    const patchId = req.params.id;
    const patch = patchService.getPatchById(patchId);

    if (!patch) {
      return apiResponse.error(res, {
        code: 'RESOURCE_NOT_FOUND',
        message: `Patch with ID '${patchId}' does not exist.`
      }, 404);
    }

    return apiResponse.success(res, patch, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'PATCH_FETCH_FAILED',
      message: err.message || 'Failed to fetch patch.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// POST /api/patches/:id/approve - Explicit human approval transition
// ----------------------------------------------------------------------------
router.post('/:id/approve', (req, res) => {
  try {
    const patchId = req.params.id;
    const { comments, approverComments, reviewedBy } = req.body || {};

    const updated = patchService.approvePatch(patchId, {
      reviewedBy: reviewedBy || 'security_lead',
      comments: approverComments || comments || 'Explicitly approved via Security Console'
    });

    return apiResponse.success(res, updated, 200);
  } catch (err) {
    if (err.name === 'PatchNotFoundError' || err.statusCode === 404 || err.code === 'PATCH_NOT_FOUND') {
      return apiResponse.error(res, {
        code: 'RESOURCE_NOT_FOUND',
        message: err.message
      }, 404);
    }
    if (err.name === 'InvalidReviewStateTransitionError' || err.statusCode === 409 || err.code === 'INVALID_STATE_TRANSITION') {
      return apiResponse.error(res, {
        code: 'INVALID_STATE_TRANSITION',
        message: err.message
      }, 409);
    }
    return apiResponse.error(res, {
      code: 'PATCH_APPROVAL_FAILED',
      message: err.message || 'Failed to approve patch.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// POST /api/patches/:id/reject - Explicit human rejection transition
// ----------------------------------------------------------------------------
router.post('/:id/reject', (req, res) => {
  try {
    const patchId = req.params.id;
    const { reason, reviewerComments, reviewedBy } = req.body || {};

    const updated = patchService.rejectPatch(patchId, {
      reviewedBy: reviewedBy || 'security_lead',
      reason: reason || reviewerComments || 'Rejected during security review'
    });

    return apiResponse.success(res, updated, 200);
  } catch (err) {
    if (err.name === 'PatchNotFoundError' || err.statusCode === 404 || err.code === 'PATCH_NOT_FOUND') {
      return apiResponse.error(res, {
        code: 'RESOURCE_NOT_FOUND',
        message: err.message
      }, 404);
    }
    if (err.name === 'InvalidReviewStateTransitionError' || err.statusCode === 409 || err.code === 'INVALID_STATE_TRANSITION') {
      return apiResponse.error(res, {
        code: 'INVALID_STATE_TRANSITION',
        message: err.message
      }, 409);
    }
    return apiResponse.error(res, {
      code: 'PATCH_REJECTION_FAILED',
      message: err.message || 'Failed to reject patch.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// POST /api/patches/:id/apply - Apply patch to disposable temporary workspace
// ----------------------------------------------------------------------------
router.post('/:id/apply', async (req, res) => {
  try {
    const patchId = req.params.id;
    const { approved, confirm, approverComments, workspacePath } = req.body || {};

    // 1. Explicit Human Approval Confirmation Gate
    const isApproved = (approved === true) || (confirm === true);
    if (!isApproved) {
      const statusCode = (req.body && req.body.approved === false) ? 403 : 400;
      const code = statusCode === 403 ? 'APPROVAL_REQUIRED' : 'CONFIRMATION_REQUIRED';
      return apiResponse.error(res, {
        code,
        message: 'Patch application requires explicit user approval (approved: true or confirm: true).'
      }, statusCode);
    }

    // 2. Apply in disposable workspace
    const result = await patchService.applyPatchToDisposableWorkspace({
      patchId,
      approved,
      confirm,
      approverComments,
      workspacePath
    });

    return apiResponse.success(res, result, 200);
  } catch (err) {
    if (err.name === 'ApprovalRequiredError' || err.code === 'APPROVAL_REQUIRED' || err.code === 'CONFIRMATION_REQUIRED') {
      const statusCode = err.statusCode || (err.code === 'APPROVAL_REQUIRED' ? 403 : 400);
      return apiResponse.error(res, {
        code: err.code || 'APPROVAL_REQUIRED',
        message: err.message
      }, statusCode);
    }
    if (err.name === 'PatchNotFoundError' || err.code === 'PATCH_NOT_FOUND' || err.code === 'RESOURCE_NOT_FOUND' || err.statusCode === 404) {
      return apiResponse.error(res, {
        code: err.code || 'RESOURCE_NOT_FOUND',
        message: err.message
      }, 404);
    }
    if (err.name === 'InvalidPatchStateError' || err.code === 'INVALID_STATE_TRANSITION' || err.statusCode === 409) {
      return apiResponse.error(res, {
        code: 'INVALID_STATE_TRANSITION',
        message: err.message
      }, 409);
    }
    if (err.code === 'PATCH_VALIDATION_FAILED' || err.statusCode === 400) {
      return apiResponse.error(res, {
        code: 'PATCH_VALIDATION_FAILED',
        message: err.message,
        details: err.details || []
      }, 400);
    }

    return apiResponse.error(res, {
      code: err.code || 'PATCH_APPLICATION_FAILED',
      message: err.message || 'Failed to apply patch to temporary workspace.'
    }, err.statusCode || 500);
  }
});

// ----------------------------------------------------------------------------
// POST /api/patches/:id/rollback - Rollback patch in disposable workspace
// ----------------------------------------------------------------------------
router.post('/:id/rollback', async (req, res) => {
  try {
    const patchId = req.params.id;
    const result = await patchService.rollbackPatch(patchId);
    return apiResponse.success(res, result, 200);
  } catch (err) {
    if (err.code === 'PATCH_NOT_FOUND' || err.statusCode === 404) {
      return apiResponse.error(res, {
        code: 'PATCH_NOT_FOUND',
        message: err.message
      }, 404);
    }
    if (err.code === 'INVALID_PATCH_STATE' || err.statusCode === 400) {
      return apiResponse.error(res, {
        code: 'INVALID_PATCH_STATE',
        message: err.message
      }, 400);
    }
    return apiResponse.error(res, {
      code: 'PATCH_ROLLBACK_FAILED',
      message: err.message || 'Failed to rollback patch.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// POST /api/patches/:id/verify - Verify patch in disposable workspace
// ----------------------------------------------------------------------------
router.post('/:id/verify', async (req, res) => {
  try {
    const patchId = req.params.id;
    const { testFile, command, options } = req.body || {};
    const requestId = req.id || req.headers?.['x-request-id'] || 'req_verify';

    const result = await verificationService.verifyPatch({
      ...options,
      patchId,
      testFile: testFile !== undefined ? testFile : options?.testFile,
      command: command !== undefined ? command : options?.command || 'node',
      requestId,
      actor: req.user?.id || options?.actor || 'security_operator',
      ...(req.body?.testResults ? { testResults: req.body.testResults } : {}),
      ...(req.body?.failingTests !== undefined ? { failingTests: req.body.failingTests } : {}),
      ...(req.body?.scannerUnavailable !== undefined ? { scannerUnavailable: req.body.scannerUnavailable } : {}),
      ...(req.body?.partial !== undefined ? { partial: req.body.partial } : {})
    });

    return apiResponse.success(res, result.verification || result, 200);
  } catch (err) {
    if (err.name === 'InvalidStateTransitionError' || err.code === 'INVALID_STATE_TRANSITION' || err.statusCode === 409) {
      return apiResponse.error(res, {
        code: 'INVALID_STATE_TRANSITION',
        message: err.message
      }, 409);
    }
    if (err.name === 'PatchNotFoundError' || err.code === 'PATCH_NOT_FOUND' || err.code === 'RESOURCE_NOT_FOUND' || err.statusCode === 404) {
      return apiResponse.error(res, {
        code: 'RESOURCE_NOT_FOUND',
        message: err.message
      }, 404);
    }
    return apiResponse.error(res, {
      code: 'PATCH_VERIFICATION_FAILED',
      message: err.message || 'Failed to verify patch.'
    }, err.statusCode || 500);
  }
});

module.exports = router;
