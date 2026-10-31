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
const path = require('path');
const fs = require('fs');
const apiResponse = require('../utils/apiResponse');
const { investigationService } = require('../services/investigation.service');
const { scanOrchestrator } = require('../orchestrator/scanOrchestrator');
const scannerService = require('../services/scanner.service');
const patchService = require('../services/patch.service');
const verificationService = require('../services/verification.service');
const aiService = require('../services/ai.service');
const inventoryService = require('../services/inventory.service');
const repositoryService = require('../services/repository.service');
const { validateDiffAndPaths } = require('../validators/diffValidator');
const { parseUnifiedDiff } = require('../validators/patchProposal.schema');

// ----------------------------------------------------------------------------
// GET /api/findings - List findings with optional query filters
// ----------------------------------------------------------------------------
router.get('/', (req, res) => {
  try {
    const { scanId, severity, status, category, scanner, repositoryId } = req.query;

    let findings = scanOrchestrator.getAllFindings({ scanId, severity, status, category, scanner, repositoryId });
    if (!Array.isArray(findings)) {
      findings = scannerService.getAllFindings();
      if (scanId) {
        findings = findings.filter(f => f.scanId === scanId);
      }
      if (repositoryId) {
        findings = findings.filter(f => f.repositoryId === repositoryId);
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
    let sourceContext = null;
    if (finding.scanId && finding.filePath) {
      const scan = (typeof scanOrchestrator.getScan === 'function' ? scanOrchestrator.getScan(finding.scanId) : null) ||
                   (typeof scannerService.getScan === 'function' ? scannerService.getScan(finding.scanId) : null);
      if (scan && scan.workspacePath) {
        try {
          sourceContext = inventoryService.getFileExcerpt(
            scan.workspacePath,
            finding.filePath,
            finding.startLine || 1,
            finding.endLine || finding.startLine || 1,
            { contextLines: 4 }
          );
        } catch (_) {}
      }
    }

    const enrichedFinding = {
      ...finding,
      ...(sourceContext ? { sourceContext } : {}),
      ...(investigation
        ? {
            investigationId: investigation.id,
            aiAssessment: investigation.assessment,
            aiConfidence: investigation.confidence,
            investigation
          }
        : {})
    };

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

    // Check authoritative finding existence in scanner stores
    const finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);
    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding with ID '${findingId}' does not exist.`
      }, 404);
    }

    // Execute investigation and state transition (DETECTED -> TRIAGED)
    const result = await investigationService.investigateFinding(findingId);
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
    if (!result || !result.investigation) {
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

// Helper to authoritatively resolve finding and its real source context from workspace
async function resolveFindingAndContext(findingId, req) {
  // Authoritative server-side lookup
  let finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);

  // Fallback: If store was cleared on reload, restore finding from client session with matching ID
  if (!finding && req.body?.finding && (req.body.finding.id === findingId || !req.body.finding.id)) {
    finding = { ...req.body.finding, id: findingId };
    scanOrchestrator.addFinding(finding);
    scannerService.addFinding(finding);
  }

  // Fallback: Check if patchService already knows this finding
  if (!finding) {
    const existingPatch = patchService.getPatchByFindingId(findingId);
    if (existingPatch?.evidenceReferences) {
      finding = {
        id: findingId,
        filePath: existingPatch.changedFiles?.[0] || 'server.js',
        startLine: 1,
        category: 'SQL_INJECTION',
        title: 'Security Finding',
        evidence: existingPatch.evidenceReferences?.[0]?.reference || ''
      };
      scanOrchestrator.addFinding(finding);
      scannerService.addFinding(finding);
    }
  }

  if (!finding) {
    return { finding: null, sourceContext: '' };
  }

  // Authoritatively retrieve source code context from the repository workspace on disk first
  let sourceContext = '';
  if (finding.filePath) {
    let workspacePath = null;
    if (finding.scanId) {
      const scan = (typeof scanOrchestrator.getScan === 'function' ? scanOrchestrator.getScan(finding.scanId) : null) ||
                   (typeof scannerService.getScan === 'function' ? scannerService.getScan(finding.scanId) : null);
      if (scan?.workspacePath && fs.existsSync(scan.workspacePath)) {
        workspacePath = scan.workspacePath;
      }
    }
    if (!workspacePath && finding.repositoryId) {
      const repo = repositoryService.getRepositoryById(finding.repositoryId);
      if (repo?.workspacePath && fs.existsSync(repo.workspacePath)) {
        workspacePath = repo.workspacePath;
      }
    }
    if (!workspacePath) {
      const workspacesDir = path.resolve(__dirname, '../../.workspaces');
      if (fs.existsSync(workspacesDir)) {
        const entries = fs.readdirSync(workspacesDir).filter(e => e.startsWith('repo_'));
        for (const entry of entries.reverse()) {
          const candidate = path.join(workspacesDir, entry);
          if (fs.existsSync(path.join(candidate, finding.filePath))) {
            workspacePath = candidate;
            break;
          }
        }
      }
    }
    if (!workspacePath) {
      const fixturePath = path.resolve(__dirname, '../../../fixtures');
      if (fs.existsSync(path.join(fixturePath, finding.filePath))) {
        workspacePath = fixturePath;
      }
    }

    if (workspacePath) {
      try {
        const excerpt = inventoryService.getFileExcerpt(
          workspacePath,
          finding.filePath,
          finding.startLine || 1,
          finding.endLine || finding.startLine || 1,
          { contextLines: 6 }
        );
        if (excerpt?.lines && excerpt.lines.length > 0) {
          sourceContext = excerpt.lines.map(l => l.content).join('\n');
        } else if (excerpt?.content) {
          sourceContext = excerpt.content;
        } else if (excerpt?.rawExcerpt) {
          sourceContext = excerpt.rawExcerpt;
        }
      } catch (_) {}
    }
  }

  if (!sourceContext) {
    sourceContext = typeof finding.evidence === 'string'
      ? finding.evidence
      : (finding.codeSnippet || (finding.evidence ? JSON.stringify(finding.evidence) : ''));
  }

  return { finding, sourceContext };
}

// ----------------------------------------------------------------------------
// POST /api/findings/:id/patches - Generate AI patch proposal (Section 4.7 canonical)
// ----------------------------------------------------------------------------
router.post('/:id/patches', async (req, res) => {
  const reqId = req.headers['x-request-id'] || `req_${Date.now()}`;
  const t0 = Date.now();
  const logStage = (stage, status, extra = '') => {
    console.log(`[PATCH_TRACING] [${reqId}] Stage ${stage} (${Date.now() - t0}ms): ${status} ${extra}`);
  };

  try {
    const findingId = req.params.id;
    logStage(1, 'Request received by Express', `findingId=${findingId}`);

    const { finding, sourceContext } = await resolveFindingAndContext(findingId, req);
    if (!finding) {
      logStage(2, 'FAILED', `Finding '${findingId}' not found in authoritative store`);
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding '${findingId}' not found.`
      }, 404);
    }
    logStage(2, 'SUCCESS', `Finding retrieved: ${finding.id} (${finding.category || finding.cwe})`);
    logStage(3, 'SUCCESS', `Workspace/SourceContext resolved (length: ${sourceContext?.length || 0})`);

    // Generate proposal via AI Service
    logStage(5, 'AI request started');
    let patchProposal = null;
    let proposalResult = null;

    if (typeof aiService.generatePatchProposal === 'function') {
      proposalResult = await aiService.generatePatchProposal(finding, { sourceContext });
      if (proposalResult?.success && (proposalResult?.proposal || proposalResult?.data)) {
        patchProposal = proposalResult.proposal || proposalResult.data;
        logStage(6, 'SUCCESS', 'AI response received & processed');
      } else if (proposalResult?.error) {
        logStage(6, 'FAILED', `AI proposal failed: ${proposalResult.error.code} - ${proposalResult.error.message}`);
        return apiResponse.error(res, {
          code: proposalResult.error.code || 'AI_GENERATION_FAILED',
          message: proposalResult.error.message || 'AI failed to generate patch proposal.'
        }, proposalResult.error.code === 'AI_TIMEOUT' ? 504 : 502);
      }
    }

    if (!patchProposal) {
      logStage(7, 'FAILED', 'No patch proposal generated');
      return apiResponse.error(res, {
        code: 'PATCH_GENERATION_FAILED',
        message: 'Could not generate valid patch proposal.'
      }, 500);
    }

    logStage(8, 'SUCCESS', 'Unified diff generated');

    // Validate diff syntax and additions/deletions
    if (!patchProposal?.diff) {
      logStage(9, 'FAILED', 'Missing diff in proposal');
      return apiResponse.error(res, {
        code: 'MALFORMED_DIFF',
        message: `Cannot generate valid patch proposal for finding '${findingId}': missing diff.`
      }, 422);
    }

    const diffCheck = validateDiffAndPaths(patchProposal.diff, {
      finding,
      changedFiles: patchProposal.changedFiles || [finding.filePath]
    });
    if (!diffCheck.valid) {
      logStage(9, 'FAILED', `Diff validation failed: ${diffCheck.errors?.[0]}`);
      return apiResponse.error(res, {
        code: diffCheck.errorDetails?.[0]?.code || 'MALFORMED_DIFF',
        message: diffCheck.errors?.[0] || 'Generated diff failed validation.'
      }, 422);
    }

    const parsedDiff = parseUnifiedDiff(patchProposal.diff);
    if (!parsedDiff.valid || (parsedDiff.stats && parsedDiff.stats.totalChanges === 0)) {
      logStage(9, 'FAILED', 'Diff contains 0 changes');
      return apiResponse.error(res, {
        code: 'MALFORMED_DIFF',
        message: `Generated patch proposal contains zero additions or deletions.`
      }, 422);
    }
    logStage(9, 'SUCCESS', 'Diff validated cleanly');

    // Persist patch entity in patchService strictly matching findingId
    const savedPatch = patchService.savePatch({
      ...patchProposal,
      findingId: finding.id,
      status: 'GENERATED'
    });
    logStage(10, 'SUCCESS', `Patch persisted with ID ${savedPatch.id}`);

    // Update finding state to PATCH_PROPOSED
    const updatedFinding = {
      ...finding,
      status: 'PATCH_PROPOSED',
      patchId: savedPatch.id,
      proposedPatch: savedPatch
    };
    scanOrchestrator.updateFinding(finding.id, updatedFinding);
    scannerService.updateFinding(finding.id, updatedFinding);

    logStage(11, 'SUCCESS', `Response sent to frontend in ${Date.now() - t0}ms`);
    return apiResponse.success(res, savedPatch, 200);
  } catch (err) {
    console.error(`[PATCH_TRACING] [${reqId}] EXCEPTION (${Date.now() - t0}ms):`, err.message);
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
    const { finding, sourceContext } = await resolveFindingAndContext(findingId, req);

    if (!finding) {
      return apiResponse.error(res, {
        code: 'FINDING_NOT_FOUND',
        message: `Finding '${findingId}' not found.`
      }, 404);
    }

    let patchProposal;
    if (typeof aiService.generatePatchProposal === 'function') {
      const proposalResult = await aiService.generatePatchProposal(finding, { sourceContext });
      if (proposalResult?.success && (proposalResult?.proposal || proposalResult?.data)) {
        patchProposal = proposalResult.proposal || proposalResult.data;
      }
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
        evidenceReferences: [
          {
            type: 'SNIPPET',
            reference: finding.fingerprint || `${finding.filePath || 'file'}#L${finding.startLine || 1}`
          }
        ]
      };
    }

    // Validate diff syntax and additions/deletions
    if (!patchProposal?.diff) {
      return apiResponse.error(res, {
        code: 'MALFORMED_DIFF',
        message: `Cannot generate valid patch proposal for finding '${findingId}': missing diff.`
      }, 422);
    }

    const diffCheck = validateDiffAndPaths(patchProposal.diff, {
      finding,
      changedFiles: patchProposal.changedFiles || [finding.filePath]
    });
    if (!diffCheck.valid) {
      return apiResponse.error(res, {
        code: diffCheck.errorDetails?.[0]?.code || 'MALFORMED_DIFF',
        message: diffCheck.errors?.[0] || 'Generated diff failed validation.'
      }, 422);
    }

    const parsedDiff = parseUnifiedDiff(patchProposal.diff);
    if (!parsedDiff.valid || (parsedDiff.stats && parsedDiff.stats.totalChanges === 0)) {
      return apiResponse.error(res, {
        code: 'MALFORMED_DIFF',
        message: `Generated patch proposal contains zero additions or deletions.`
      }, 422);
    }

    const savedPatch = patchService.savePatch({
      ...patchProposal,
      findingId: finding.id,
      status: 'GENERATED'
    });

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

    // Explicit Confirmation Gate (Commit 34 Invariant)
    const isApproved = approved === true || approved === 'true' || confirm === true || confirm === 'true';
    if (!isApproved) {
      return apiResponse.error(res, {
        code: 'APPROVAL_REQUIRED',
        message: 'Patch application requires explicit user approval (approved: true).'
      }, 403);
    }

    const patch = (typeof patchService.getPatchByFindingId === 'function' ? patchService.getPatchByFindingId(findingId) : null)
      || (finding.patchId ? patchService.getPatchById(finding.patchId) : null);

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

    const patch = (typeof patchService.getPatchByFindingId === 'function' ? patchService.getPatchByFindingId(findingId) : null) || (finding.patchId ? patchService.getPatchById(finding.patchId) : null);
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
