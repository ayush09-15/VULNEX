/**
 * VULNEX Findings & AI Investigation HTTP Routes
 *
 * Implements:
 * - Master Antigravity Execution Bible Section 4.7 (Canonical Endpoints)
 *   * POST /api/findings/:id/investigate - Structured AI analysis & persistence
 *   * GET  /api/findings/:id/investigation - Retrieve persisted investigation record
 *   * GET  /api/findings/:id - Finding evidence and latest AI assessment
 *   * GET  /api/findings - List findings with filters and AI status
 * - Section 4.6 (Standard API Envelope & Request IDs)
 * - Section 4.10 (Finding State Machine: DETECTED -> TRIAGED)
 */

const express = require('express');
const router = express.Router();
const apiResponse = require('../utils/apiResponse');
const { investigationService } = require('../services/investigation.service');
const { scanOrchestrator } = require('../orchestrator/scanOrchestrator');
const scannerService = require('../services/scanner.service');
const patchService = require('../services/patch.service');
const verificationService = require('../services/verification.service');

// ----------------------------------------------------------------------------
// GET /api/findings - List findings with optional query filters
// ----------------------------------------------------------------------------
router.get('/', (req, res) => {
  try {
    const { scanId, severity, status, category, scanner } = req.query;

    let findings = scanOrchestrator.getAllFindings({ scanId, severity, status, category, scanner });
    if (!findings || findings.length === 0) {
      findings = scannerService.getAllFindings();
      if (scanId) {
        findings = findings.filter(f => f.scanId === scanId);
      }
      if (severity) {
        findings = findings.filter(f => f.severity && f.severity.toUpperCase() === severity.toUpperCase());
      }
      if (status) {
        findings = findings.filter(f => f.status && f.status.toUpperCase() === status.toUpperCase());
      }
      if (category) {
        findings = findings.filter(f => f.category && f.category.toUpperCase() === category.toUpperCase());
      }
      if (scanner) {
        findings = findings.filter(f => f.scanner && f.scanner.toLowerCase() === scanner.toLowerCase());
      }
    }

    // Attach investigation summary if present
    const enriched = findings.map(f => {
      const inv = investigationService.getInvestigationByFindingId(f.id);
      return inv ? { ...f, investigation: inv, aiAssessment: inv.assessment, aiConfidence: inv.confidence } : f;
    });

    return apiResponse.success(res, enriched, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'FINDINGS_LIST_FAILED',
      message: err.message || 'Failed to list findings.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// GET /api/findings/:id - Retrieve finding by ID with investigation evidence
// ----------------------------------------------------------------------------
router.get('/:id', (req, res) => {
  try {
    const findingId = req.params.id;
    const finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);

    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding with ID '${findingId}' does not exist.`
      }, 404);
    }

    const investigation = investigationService.getInvestigationByFindingId(findingId);
    const enrichedFinding = investigation
      ? {
          ...finding,
          investigationId: investigation.id,
          aiAssessment: investigation.assessment,
          aiConfidence: investigation.confidence,
          investigation
        }
      : finding;

    return apiResponse.success(res, enrichedFinding, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'FINDING_FETCH_FAILED',
      message: err.message || 'Failed to fetch finding.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// POST /api/findings/:id/investigate - Trigger evidence-bounded AI investigation
// ----------------------------------------------------------------------------
router.post('/:id/investigate', async (req, res) => {
  try {
    const findingId = req.params.id;
    const codeContext = req.body?.codeContext;

    // Check finding existence
    const finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);
    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding with ID '${findingId}' does not exist.`
      }, 404);
    }

    // Execute investigation and state transition (DETECTED -> TRIAGED)
    const result = await investigationService.investigateFinding(findingId, { codeContext });
    if (!result) {
      return apiResponse.error(res, {
        code: 'INVESTIGATION_FAILED',
        message: 'Could not execute investigation for finding.'
      }, 500);
    }

    return apiResponse.success(res, result.investigation, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'INVESTIGATION_ERROR',
      message: err.message || 'An error occurred during AI investigation.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// GET /api/findings/:id/investigation - Retrieve persisted investigation record
// ----------------------------------------------------------------------------
router.get('/:id/investigation', (req, res) => {
  try {
    const findingId = req.params.id;
    const finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);

    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding with ID '${findingId}' does not exist.`
      }, 404);
    }

    const investigation = investigationService.getInvestigationByFindingId(findingId);
    if (!investigation) {
      return apiResponse.error(res, {
        code: 'INVESTIGATION_NOT_FOUND',
        message: `Finding '${findingId}' has not been investigated yet.`
      }, 404);
    }

    return apiResponse.success(res, investigation, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'INVESTIGATION_FETCH_FAILED',
      message: err.message || 'Failed to fetch investigation.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// Backward-Compatibility Alias: POST /api/findings/:id/analyze -> investigate
// ----------------------------------------------------------------------------
router.post('/:id/analyze', async (req, res) => {
  try {
    const findingId = req.params.id;
    const finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);

    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding with ID '${findingId}' does not exist.`
      }, 404);
    }

    const result = await investigationService.investigateFinding(findingId, { codeContext: req.body?.codeContext });
    return apiResponse.success(res, result.investigation, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'INVESTIGATION_ERROR',
      message: err.message || 'An error occurred during AI investigation.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// POST /api/findings/:id/patches - Generate AI patch proposal (Section 4.7 canonical)
// ----------------------------------------------------------------------------
router.post('/:id/patches', async (req, res) => {
  try {
    const findingId = req.params.id;
    const finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);
    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding '${findingId}' not found.`
      }, 404);
    }

    const aiService = require('../services/ai.service');
    const sourceContext = req.body?.sourceContext || req.body?.originalCode || finding.evidence || finding.codeSnippet || '';

    // Generate proposal via AI Service
    let patchProposal;
    if (typeof aiService.generatePatchProposal === 'function') {
      const proposalResult = await aiService.generatePatchProposal(finding, { sourceContext });
      patchProposal = proposalResult?.proposal || proposalResult?.data;
    }

    if (!patchProposal) {
      const patchResult = await aiService.generatePatch(finding, sourceContext);
      const diff = patchService.createUnifiedDiff({
        filename: finding.filePath || finding.file || 'unknown.js',
        originalContent: patchResult.originalCode,
        patchedContent: patchResult.patchedCode
      });
      patchProposal = {
        findingId: finding.id,
        diff,
        rationale: patchResult.explanation || 'Applied defensive security fix.',
        changedFiles: [finding.filePath || finding.file || 'unknown.js'],
        evidenceReferences: [finding.fingerprint || `${finding.filePath || 'file'}#L${finding.startLine || 1}`]
      };
    }

    // Persist patch entity in patchService
    const savedPatch = patchService.savePatch({
      ...patchProposal,
      findingId: finding.id,
      status: 'GENERATED'
    });

    // Update finding state to PATCH_PROPOSED
    const updatedFinding = {
      ...finding,
      status: 'PATCH_PROPOSED',
      patchId: savedPatch.id,
      proposedPatch: savedPatch
    };
    scanOrchestrator.updateFinding(finding.id, updatedFinding);
    scannerService.updateFinding(finding.id, updatedFinding);

    return apiResponse.success(res, savedPatch, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'PATCH_GENERATION_FAILED',
      message: err.message || 'Failed to generate patch proposal.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// POST /api/findings/:id/generate-patch - Alias for /api/findings/:id/patches
// ----------------------------------------------------------------------------
router.post('/:id/generate-patch', async (req, res) => {
  try {
    const findingId = req.params.id;
    const finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);
    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding '${findingId}' not found.`
      }, 404);
    }

    const { originalCode } = req.body || {};
    const aiService = require('../services/ai.service');
    const patchResult = await aiService.generatePatch(finding, originalCode || finding.codeSnippet || finding.evidence);

    const diff = patchService.createUnifiedDiff({
      filename: finding.filePath || finding.file || 'unknown.js',
      originalContent: patchResult.originalCode,
      patchedContent: patchResult.patchedCode
    });

    const preview = patchService.previewPatch(patchResult.originalCode, patchResult.patchedCode);

    const savedPatch = patchService.savePatch({
      findingId: finding.id,
      diff,
      rationale: patchResult.explanation || 'Applied defensive security fix.',
      changedFiles: [finding.filePath || finding.file || 'unknown.js'],
      status: 'GENERATED'
    });

    const responseData = {
      ...patchResult,
      id: savedPatch.id,
      diff,
      preview
    };

    scannerService.updateFinding(req.params.id, { proposedPatch: responseData, status: 'PATCH_PROPOSED' });
    scanOrchestrator.updateFinding(req.params.id, { proposedPatch: responseData, status: 'PATCH_PROPOSED' });

    return apiResponse.success(res, responseData, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'PATCH_GENERATION_FAILED',
      message: err.message || 'Failed to generate patch.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// POST /api/findings/:id/verify-patch - Verify proposed patch
// ----------------------------------------------------------------------------
router.post('/:id/verify-patch', async (req, res) => {
  try {
    const finding = scanOrchestrator.getFindingById(req.params.id) || scannerService.getFindingById(req.params.id);
    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding '${req.params.id}' not found.`
      }, 404);
    }

    const { patchedCode, originalCode } = req.body || {};
    const verificationReport = await verificationService.verifyPatch({
      finding,
      patchedCode: patchedCode || finding.proposedPatch?.patchedCode,
      originalCode: originalCode || finding.codeSnippet || finding.evidence,
      filePath: finding.filePath || finding.file
    });

    const status = verificationReport.isVerified ? 'VERIFIED' : 'FAILED';
    scannerService.updateFinding(req.params.id, { verification: verificationReport, status });
    scanOrchestrator.updateFinding(req.params.id, { verification: verificationReport, status });

    return apiResponse.success(res, verificationReport, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: 'PATCH_VERIFICATION_FAILED',
      message: err.message || 'Failed to verify patch.'
    }, 500);
  }
});

// ----------------------------------------------------------------------------
// POST /api/findings/:id/apply-patch - Apply patch to disposable workspace
// ----------------------------------------------------------------------------
router.post('/:id/apply-patch', async (req, res) => {
  try {
    const findingId = req.params.id;
    const finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);
    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding '${findingId}' not found.`
      }, 404);
    }

    const { approved, confirm, approverComments, patchedCode, workspacePath } = req.body || {};
    const patch = patchService.getPatchByFindingId(findingId) || (finding.patchId ? patchService.getPatchById(finding.patchId) : null);

    if (patch) {
      const result = await patchService.applyPatchToDisposableWorkspace({
        patchId: patch.id,
        approved,
        confirm,
        approverComments,
        workspacePath
      });
      return apiResponse.success(res, result, 200);
    }

    const patchedContent = patchedCode || finding.proposedPatch?.patchedCode;
    if (!patchedContent) {
      return apiResponse.error(res, {
        code: 'MISSING_PATCH_CONTENT',
        message: 'No patched code or patch proposal found for this finding.'
      }, 400);
    }

    const result = await patchService.applyPatch({
      filePath: finding.filePath || finding.file,
      patchedContent
    });

    scannerService.updateFinding(findingId, { status: 'PATCH_APPLIED', resolvedAt: new Date().toISOString() });
    scanOrchestrator.updateFinding(findingId, { status: 'PATCH_APPLIED', resolvedAt: new Date().toISOString() });

    return apiResponse.success(res, result, 200);
  } catch (err) {
    const statusCode = err.statusCode || (err.code === 'CONFIRMATION_REQUIRED' || err.code === 'PATCH_VALIDATION_FAILED' ? 400 : 500);
    return apiResponse.error(res, {
      code: err.code || 'PATCH_APPLICATION_FAILED',
      message: err.message || 'Failed to apply patch.',
      details: err.details || []
    }, statusCode);
  }
});

// ----------------------------------------------------------------------------
// POST /api/findings/:id/rollback - Rollback applied patch
// ----------------------------------------------------------------------------
router.post('/:id/rollback', async (req, res) => {
  try {
    const findingId = req.params.id;
    const finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);
    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding '${findingId}' not found.`
      }, 404);
    }

    const patch = patchService.getPatchByFindingId(findingId) || (finding.patchId ? patchService.getPatchById(finding.patchId) : null);
    if (patch) {
      const result = await patchService.rollbackPatch(patch.id);
      return apiResponse.success(res, result, 200);
    }

    const result = await patchService.rollbackPatch({ filePath: finding.filePath || finding.file });
    scannerService.updateFinding(findingId, { status: 'DETECTED' });
    scanOrchestrator.updateFinding(findingId, { status: 'DETECTED' });

    return apiResponse.success(res, result, 200);
  } catch (err) {
    const statusCode = err.statusCode || 500;
    return apiResponse.error(res, {
      code: err.code || 'PATCH_ROLLBACK_FAILED',
      message: err.message || 'Failed to rollback patch.'
    }, statusCode);
  }
});

module.exports = router;
