/**
 * VULNEX End-to-End Workflow Integration Test (Commit 42)
 *
 * Verifies Commit 42 Gate:
 * - "Full truthful fixture workflow."
 * - Master Antigravity Execution Bible Section 8.7 (Steps 1-15) & Section 10.1-10.4
 * - Full Vertical Slice: Detect -> Investigate -> Patch -> Verify -> Report
 * - Operating on the controlled vulnerable fixture: fixtures/server.js
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const path = require('path');
const app = require('../src/app');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const investigationService = require('../src/services/investigation.service');
const patchService = require('../src/services/patch.service');
const verificationService = require('../src/services/verification.service');

// HTTP Dispatch Helper for end-to-end API testing
function dispatch(method, url, { body = {}, query = {}, headers = {} } = {}) {
  return new Promise((resolve) => {
    const [pathPart, queryPart] = url.split('?');
    const parsedQuery = {};
    if (queryPart) {
      for (const [k, v] of new URLSearchParams(queryPart)) {
        parsedQuery[k] = v;
      }
    }

    const req = new http.IncomingMessage();
    req.method = method.toUpperCase();
    req.url = url;
    req.originalUrl = url;
    req.headers = {
      'content-type': 'application/json',
      'x-request-id': `req_e2e_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      ...headers
    };
    req.body = body;
    req.query = { ...parsedQuery, ...query };

    const res = new http.ServerResponse(req);
    let rawBody = '';

    res.write = (chunk) => {
      rawBody += chunk ? chunk.toString() : '';
      return true;
    };

    res.end = (chunk) => {
      if (chunk) rawBody += chunk.toString();
      let json = null;
      try {
        json = JSON.parse(rawBody);
      } catch (_) {}
      resolve({
        statusCode: res.statusCode,
        headers: res.getHeaders(),
        body: json || rawBody
      });
    };

    app.handle(req, res);
  });
}

describe('End-to-End Workflow: Detect -> Investigate -> Patch -> Verify -> Report (Commit 42)', () => {
  const fixturePath = path.resolve(__dirname, '../../fixtures');
  let originalServerContent = '';

  beforeEach(() => {
    // Snapshot original fixture content to strictly assert immutability
    const serverFile = path.join(fixturePath, 'server.js');
    if (fs.existsSync(serverFile)) {
      originalServerContent = fs.readFileSync(serverFile, 'utf8');
    }

    scanOrchestrator.clearStores();
    investigationService.clearStore();
    patchService.clearStore();
    verificationService.clearStore();
  });

  afterEach(() => {
    // Invariant: Verify fixture was NEVER modified on host filesystem
    const serverFile = path.join(fixturePath, 'server.js');
    if (fs.existsSync(serverFile)) {
      const currentContent = fs.readFileSync(serverFile, 'utf8');
      assert.equal(
        currentContent,
        originalServerContent,
        'CRITICAL SAFETY VIOLATION: Original fixture source file was modified on host!'
      );
    }
  });

  it('executes the complete truthful vertical slice on the controlled fixture', async () => {
    // ========================================================================
    // STAGE 1: DETECT (Repository Intake & Deterministic Scan)
    // ========================================================================
    const startScanRes = await dispatch('POST', '/api/scans', {
      body: {
        repositoryId: 'repo_fixtures_e2e',
        repositoryPath: fixturePath,
        ref: 'main',
        scanners: ['patterns']
      }
    });

    assert.equal(startScanRes.statusCode, 201, 'Scan initiation must return HTTP 201');
    assert.equal(startScanRes.body.success, true);
    assert.ok(startScanRes.body.data.id, 'Scan must generate a unique scan ID');

    const scanId = startScanRes.body.data.id;
    assert.equal(startScanRes.body.data.status, 'COMPLETED');
    assert.equal(startScanRes.body.data.summary.totalFindings, 2);

    // Verify scan event timeline
    const eventsRes = await dispatch('GET', `/api/scans/${scanId}/events`);
    assert.equal(eventsRes.statusCode, 200);
    assert.ok(Array.isArray(eventsRes.body.data));
    const stagesLogged = eventsRes.body.data.map(e => e.stage);
    assert.ok(stagesLogged.includes('QUEUED'), 'Timeline must record QUEUED stage');
    assert.ok(stagesLogged.includes('PREPARING'), 'Timeline must record PREPARING stage');
    assert.ok(stagesLogged.includes('SCANNING'), 'Timeline must record SCANNING stage');
    assert.ok(stagesLogged.includes('NORMALIZING'), 'Timeline must record NORMALIZING stage');
    assert.ok(stagesLogged.includes('COMPLETED'), 'Timeline must record COMPLETED stage');

    // Retrieve normalized findings
    const findingsRes = await dispatch('GET', `/api/scans/${scanId}/findings`);
    assert.equal(findingsRes.statusCode, 200);
    assert.equal(findingsRes.body.success, true);

    const findings = findingsRes.body.data;
    assert.equal(findings.length, 2, 'Must detect exactly 2 controlled patterns in fixture');

    // Finding 1: SQL Injection
    const sqliFinding = findings.find(f => f.ruleId === 'vulnex.javascript.sqli');
    assert.ok(sqliFinding, 'Must detect SQL injection finding');
    assert.equal(sqliFinding.severity, 'CRITICAL');
    assert.equal(sqliFinding.category, 'SQL_INJECTION');
    assert.equal(sqliFinding.startLine, 47);
    assert.equal(sqliFinding.filePath, 'server.js');
    assert.equal(sqliFinding.status, 'DETECTED');
    assert.match(sqliFinding.fingerprint, /^[a-f0-9]{64}$/, 'Stable 64-char SHA-256 hex fingerprint required');

    // Finding 2: Cross-Site Scripting (XSS)
    const xssFinding = findings.find(f => f.ruleId === 'vulnex.javascript.xss');
    assert.ok(xssFinding, 'Must detect Reflected XSS finding');
    assert.equal(xssFinding.severity, 'HIGH');
    assert.equal(xssFinding.category, 'XSS');
    assert.equal(xssFinding.startLine, 79);
    assert.equal(xssFinding.filePath, 'server.js');

    // ========================================================================
    // STAGE 2: INVESTIGATE (AI Root-Cause Analysis & State Transition)
    // ========================================================================
    const invRes = await dispatch('POST', `/api/findings/${sqliFinding.id}/investigate`);
    assert.equal(invRes.statusCode, 200, 'Investigation endpoint must succeed');
    assert.equal(invRes.body.success, true);

    const investigation = invRes.body.data;
    assert.ok(investigation.id, 'Investigation must have unique id');
    assert.equal(investigation.findingId, sqliFinding.id);
    assert.ok(['LIKELY_TRUE', 'UNCERTAIN', 'LIKELY_FALSE'].includes(investigation.assessment));
    assert.equal(investigation.assessment, 'LIKELY_TRUE');
    assert.ok(investigation.explanation || investigation.summary);
    assert.ok(Array.isArray(investigation.evidence));
    assert.ok(Array.isArray(investigation.preconditions));
    assert.ok(investigation.model);
    assert.ok(investigation.promptVersion);

    // Verify finding state machine transitioned from DETECTED -> TRIAGED
    const triagedFindingRes = await dispatch('GET', `/api/findings/${sqliFinding.id}`);
    assert.equal(triagedFindingRes.statusCode, 200);
    assert.equal(triagedFindingRes.body.data.status, 'TRIAGED');
    assert.equal(triagedFindingRes.body.data.investigationId, investigation.id);

    // ========================================================================
    // STAGE 3: PATCH (Patch Proposal Generation)
    // ========================================================================
    const patchRes = await dispatch('POST', `/api/findings/${sqliFinding.id}/patches`);
    assert.equal(patchRes.statusCode, 200, 'Patch proposal generation must succeed');
    assert.equal(patchRes.body.success, true);

    const patch = patchRes.body.data;
    assert.ok(patch.id, 'Patch proposal must have unique id');
    assert.equal(patch.findingId, sqliFinding.id);
    assert.equal(patch.reviewState, 'PENDING_REVIEW');
    assert.ok(patch.diff.includes('--- a/server.js'), 'Diff must contain valid header for server.js');
    assert.ok(patch.diff.includes('+++ b/server.js'));
    assert.ok(patch.diff.includes('@@'), 'Diff must contain hunk markers');
    assert.deepEqual(patch.changedFiles, ['server.js']);

    // ========================================================================
    // STAGE 4: HUMAN APPROVAL & DISPOSABLE WORKSPACE APPLICATION
    // ========================================================================
    // 4a. Attempt to apply without approval -> Must be rejected (Bible Commit 34 Gate)
    const unapprovedApplyRes = await dispatch('POST', `/api/patches/${patch.id}/apply`, {
      body: { approved: false }
    });
    assert.equal(unapprovedApplyRes.statusCode, 403);
    assert.equal(unapprovedApplyRes.body.error.code, 'APPROVAL_REQUIRED');

    // 4b. Apply with explicit human approval
    const approvedApplyRes = await dispatch('POST', `/api/patches/${patch.id}/apply`, {
      body: {
        approved: true,
        workspacePath: fixturePath,
        approverComments: 'Human review: Parameterized query approved for testing.'
      }
    });
    assert.equal(approvedApplyRes.statusCode, 200);
    assert.equal(approvedApplyRes.body.success, true);
    assert.equal(approvedApplyRes.body.data.status, 'APPLIED_TO_TEMP');
    assert.ok(approvedApplyRes.body.data.appliedWorkspaceId.startsWith('ws_disposable_'));
    assert.ok(approvedApplyRes.body.data.disposableWorkspacePath.replace(/\\/g, '/').includes('.workspaces/ws_disposable_'));

    // Check patch review state updated
    const appliedPatchRes = await dispatch('GET', `/api/patches/${patch.id}`);
    assert.equal(appliedPatchRes.body.data.status, 'APPLIED_TO_TEMP');

    // ========================================================================
    // STAGE 5: VERIFY (Post-Patch Scanner, Fingerprint Matching, Audit Event)
    // ========================================================================
    const verifyRes = await dispatch('POST', `/api/patches/${patch.id}/verify`);
    assert.equal(verifyRes.statusCode, 200, 'Verification endpoint must return 200');
    assert.equal(verifyRes.body.success, true);

    const verification = verifyRes.body.data;
    assert.ok(verification.id);
    assert.equal(verification.status, 'PASSED');
    assert.equal(verification.testResults.syntaxValid, true);
    assert.equal(verification.testResults.testsPassed, true);
    assert.equal(verification.scannerResults.originalFindingResolved, true);
    assert.equal(verification.scannerResults.newFindingsCount, 0);
    assert.equal(verification.beforeAfterComparison.comparisonOutcome, 'RESOLVED');
    assert.equal(verification.beforeAfterComparison.regressionDetected, false);

    // Verify patch transitioned to VERIFIED
    const verifiedPatchRes = await dispatch('GET', `/api/patches/${patch.id}`);
    assert.equal(verifiedPatchRes.body.data.status, 'VERIFIED');
    assert.equal(verifiedPatchRes.body.data.isVerified, true);

    // Verify immutable AuditEvents recorded
    const auditEvents = verificationService.getAuditEvents(patch.id);
    assert.ok(auditEvents.length >= 2, 'Must log start and completion audit events');
    const actions = auditEvents.map(a => a.action);
    assert.ok(actions.includes('PATCH_VERIFICATION_STARTED'));
    assert.ok(actions.includes('PATCH_VERIFICATION_COMPLETED'));

    // ========================================================================
    // STAGE 6: REPORT (Consolidated Evidence-Backed Scan Report)
    // ========================================================================
    const reportRes = await dispatch('GET', `/api/scans/${scanId}/report`);
    assert.equal(reportRes.statusCode, 200);
    assert.equal(reportRes.body.success, true);

    const report = reportRes.body.data;

    // 1. Tools
    assert.ok(report.tools);
    assert.ok(report.tools['pattern-sast'] || report.tools.semgrep);

    // 2. Findings
    assert.equal(report.findings.length, 2);

    // 3. AI Investigation linked in report
    const reportedSqli = report.findings.find(f => f.id === sqliFinding.id);
    assert.ok(reportedSqli.investigation);
    assert.equal(reportedSqli.investigation.assessment, 'LIKELY_TRUE');
    assert.equal(reportedSqli.investigation.model, investigation.model);

    // 4. Patch linked in report
    assert.ok(reportedSqli.patch);
    assert.equal(reportedSqli.patch.id, patch.id);
    assert.equal(reportedSqli.patch.status, 'VERIFIED');
    assert.ok(reportedSqli.patch.diff.includes('--- a/server.js'));

    // 5. Verification linked in report with 5-point checklist
    assert.ok(reportedSqli.verification);
    assert.equal(reportedSqli.verification.status, 'PASSED');
    assert.equal(reportedSqli.verification.originalFindingResolved, true);
    assert.equal(reportedSqli.verification.regressionDetected, false);
    assert.equal(reportedSqli.verification.ambiguousMatch, false);

    assert.ok(Array.isArray(reportedSqli.verification.checks));
    assert.equal(reportedSqli.verification.checks.length, 5);

    const checkIds = reportedSqli.verification.checks.map(c => c.id);
    assert.deepEqual(checkIds, [
      'patch_apply',
      'syntax_validation',
      'targeted_tests',
      'post_patch_scan',
      'defect_regression'
    ]);

    for (const check of reportedSqli.verification.checks) {
      assert.equal(check.status, 'PASSED', `Check ${check.id} must be PASSED`);
    }

    // 6. Summary metrics
    assert.equal(report.summary.totalFindings, 2);
    assert.equal(report.summary.critical, 1);
    assert.equal(report.summary.high, 1);
    assert.equal(report.summary.remediated, 1);
  });

  it('safely handles invalid inputs and state transitions without corruption', async () => {
    // 1. Attempting to scan invalid non-existent path
    const invalidScanRes = await dispatch('POST', '/api/scans', {
      body: {
        repositoryId: 'repo_invalid',
        repositoryPath: '/non/existent/path/999',
        ref: 'main'
      }
    });
    assert.equal(invalidScanRes.statusCode, 201);
    assert.equal(invalidScanRes.body.data.status, 'FAILED');
    assert.equal(invalidScanRes.body.data.errorCode, 'WORKSPACE_ERROR');

    // 2. Investigating non-existent finding returns 404
    const notFoundInvRes = await dispatch('POST', '/api/findings/find_nonexistent_000/investigate');
    assert.equal(notFoundInvRes.statusCode, 404);
    assert.equal(notFoundInvRes.body.error.code, 'FINDING_NOT_FOUND');

    // 3. Verifying non-existent patch returns 404
    const notFoundVerifyRes = await dispatch('POST', '/api/patches/patch_nonexistent_000/verify');
    assert.equal(notFoundVerifyRes.statusCode, 404);
    assert.equal(notFoundVerifyRes.body.error.code, 'RESOURCE_NOT_FOUND');

    // 4. Verifying patch before it is applied to temporary workspace returns 409
    const dummyPatch = patchService.savePatch({
      id: 'patch_unapplied_001',
      findingId: 'find_dummy_001',
      status: 'GENERATED',
      diff: '--- a/test.js\n+++ b/test.js\n@@ -1,1 +1,1 @@\n-a\n+b\n'
    });
    const earlyVerifyRes = await dispatch('POST', `/api/patches/${dummyPatch.id}/verify`);
    assert.equal(earlyVerifyRes.statusCode, 409);
    assert.equal(earlyVerifyRes.body.error.code, 'INVALID_STATE_TRANSITION');
  });
});
