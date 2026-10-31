/**
 * VULNEX Patches HTTP Routes
 *
 * Implements:
 * - Master Antigravity Execution Bible Section 4.7 (Canonical Endpoints):
 *   * POST /api/patches/:id/apply - Apply temporary patch; explicit confirmation required.
 *   * POST /api/patches/:id/rollback - Rollback temporary patch.
 *   * GET  /api/patches/:id - Retrieve patch entity.
 *   * GET  /api/patches - List patches.
 * - Section 4.10 (State Machines: Patch APPLIED_TO_TEMP, Finding PATCH_APPLIED)
 * - Section 7.2 Gate 35 (Original source/remote unchanged; rollback copy)
 * - Section 9.2 (Explicit Human Approval Gate)
 */

const express = require('express');
const router = express.Router();
const apiResponse = require('../utils/apiResponse');
const patchService = require('../services/patch.service');

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
      code: 'PATCHES_LIST_FAILED',
      message: err.message || 'Failed to list patches.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// GET /api/patches/:id - Get patch by ID
// ----------------------------------------------------------------------------
router.get('/:id', (req, res) => {
  try {
    const patch = patchService.getPatchById(req.params.id);
    if (!patch) {
      return apiResponse.error(res, {
        code: 'PATCH_NOT_FOUND',
        message: `Patch with ID '${req.params.id}' does not exist.`
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
// POST /api/patches/:id/apply - Apply approved patch in disposable workspace
// ----------------------------------------------------------------------------
router.post('/:id/apply', async (req, res) => {
  try {
    const patchId = req.params.id;
    const { approved, confirm, approverComments, workspacePath } = req.body || {};

    const result = await patchService.applyPatchToDisposableWorkspace({
      patchId,
      approved,
      confirm,
      approverComments,
      workspacePath
    });

    return apiResponse.success(res, result, 200);
  } catch (err) {
    const statusCode = err.statusCode || (err.code === 'PATCH_NOT_FOUND' ? 404 : 400);
    return apiResponse.error(res, {
      code: err.code || 'PATCH_APPLICATION_FAILED',
      message: err.message || 'Failed to apply patch.',
      details: err.details || []
    }, statusCode);
  }
});

// ----------------------------------------------------------------------------
// POST /api/patches/:id/rollback - Rollback applied patch
// ----------------------------------------------------------------------------
router.post('/:id/rollback', async (req, res) => {
  try {
    const result = await patchService.rollbackPatch(req.params.id);
    return apiResponse.success(res, result, 200);
  } catch (err) {
    const statusCode = err.statusCode || (err.code === 'PATCH_NOT_FOUND' ? 404 : 400);
    return apiResponse.error(res, {
      code: err.code || 'PATCH_ROLLBACK_FAILED',
      message: err.message || 'Failed to rollback patch.'
    }, statusCode);
  }
});

module.exports = router;
