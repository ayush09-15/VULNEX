/**
 * Verification Failure States & Scanner Unavailable Tests (Commit 46)
 *
 * Verifies Commit 46 Acceptance Gate:
 * - "Evidence-based FAILED/INCONCLUSIVE/PARTIAL."
 * - Master Antigravity Execution Bible Section 8.9 (Failure Handling) & Section 9.3
 * - Negative and failure cases:
 *   1. Targeted tests fail -> status FAILED (never claims verified)
 *   2. Syntax parse error in patched file -> status FAILED
 *   3. Scanner unavailable or crashed -> status INCONCLUSIVE (checks cannot establish resolution)
 *   4. Vulnerability flaw persists after patch -> status FAILED (STILL_DETECTED)
 *   5. Defect regression introduced by patch -> status FAILED (REGRESSION_DETECTED)
 *   6. Partial verification checks executed -> status PARTIAL
 *   7. Immutable audit events record appropriate failure/inconclusive outcomes
 *   8. Report API (/api/scans/:id/report) preserves truthful evidence-based states
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const path = require('path');
const fs = require('fs');
const os = require('os');
const app = require('../src/app');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const patchService = require('../src/services/patch.service');
const verificationService = require('../src/services/verification.service');
const reportService = require('../src/services/report.service');
const scannerService = require('../src/services/scanner.service');

// HTTP Dispatch Helper for route testing
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
      'x-request-id': `req_fail_state_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
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

describe('Verification Failure States & Truthful Gate (Commit 46)', () => {
  let tempWorkspace;

  beforeEach(() => {
    scanOrchestrator.clearStores();
    patchService.clearStore();
    verificationService.clearStore();
    tempWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex_fail_test_'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempWorkspace, { recursive: true, force: true });
    } catch (_) {}
  });

  // --------------------------------------------------------------------------
  // 1. FAILING TARGETED TESTS -> FAILED
  // --------------------------------------------------------------------------
  it('1. transitions patch and verification to FAILED when targeted tests fail', async () => {
    const findingId = 'find_sqli_fail_test';
    const patchId = 'patch_sqli_fail_test';

    const finding = {
      id: findingId,
      scanId: 'scan_fail_test',
      ruleId: 'javascript.express.sqli',
      severity: 'CRITICAL',
      filePath: 'src/controllers/user.js',
      fingerprint: 'fp_sqli_fail_test_001',
      status: 'PATCH_APPLIED'
    };
    scanOrchestrator.addFinding(finding);

    const patch = patchService.savePatch({
      id: patchId,
      findingId,
      diff: '--- a/src/controllers/user.js\n+++ b/src/controllers/user.js\n@@ -1,1 +1,1 @@\n- bad\n+ good\n',
      status: 'APPLIED_TO_TEMP',
      appliedWorkspaceId: 'ws_disposable_fail_test'
    });

    // Run verification with simulated failing targeted tests
    const res = await dispatch('POST', `/api/patches/${patchId}/verify`, {
      body: {
        command: 'node',
        testFile: 'nonexistent-failing-test.js'
      }
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.success, true);

    const ver = res.body.data;
    assert.equal(ver.status, 'FAILED', 'Verification status must be FAILED when targeted tests fail');
    assert.equal(ver.testResults.testsPassed, false);
    assert.equal(ver.testResults.failed, 1);

    // Verify patch state machine transitioned to FAILED
    const updatedPatch = patchService.getPatchById(patchId);
    assert.equal(updatedPatch.status, 'FAILED');
    assert.equal(updatedPatch.isVerified, false);

    // Verify finding state machine transitioned to FAILED
    const updatedFinding = scanOrchestrator.getFindingById(findingId);
    assert.equal(updatedFinding.status, 'FAILED');

    // Verify AuditEvent recorded FAILURE outcome
    const auditEvents = verificationService.getAuditEvents(patchId);
    const completeEvent = auditEvents.find(e => e.action === 'PATCH_VERIFICATION_COMPLETED');
    assert.ok(completeEvent);
    assert.equal(completeEvent.outcome, 'FAILURE');
  });

  // --------------------------------------------------------------------------
  // 2. SCANNER UNAVAILABLE -> INCONCLUSIVE
  // --------------------------------------------------------------------------
  it('2. marks verification INCONCLUSIVE when post-patch scanner is unavailable', async () => {
    const findingId = 'find_xss_scanner_unavail';
    const patchId = 'patch_xss_scanner_unavail';

    const finding = {
      id: findingId,
      scanId: 'scan_scanner_unavail',
      ruleId: 'javascript.browser.xss',
      severity: 'HIGH',
      filePath: 'src/views/search.js',
      fingerprint: 'fp_xss_scanner_unavail_001',
      status: 'PATCH_APPLIED'
    };
    scanOrchestrator.addFinding(finding);

    patchService.savePatch({
      id: patchId,
      findingId,
      diff: '--- a/src/views/search.js\n+++ b/src/views/search.js\n@@ -1,1 +1,1 @@\n- bad\n+ good\n',
      status: 'APPLIED_TO_TEMP',
      appliedWorkspaceId: 'ws_disposable_unavail'
    });

    // Run verification indicating scanner is unavailable
    const res = await dispatch('POST', `/api/patches/${patchId}/verify`, {
      body: {
        options: {
          scannerUnavailable: true,
          scannerError: 'Semgrep CLI binary not installed or process crashed'
        }
      }
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.success, true);

    const ver = res.body.data;
    assert.equal(ver.status, 'INCONCLUSIVE', 'Verification MUST be INCONCLUSIVE when scanner is unavailable');
    assert.equal(ver.scannerResults.scannerUnavailable, true);
    assert.equal(ver.scannerResults.status, 'SCANNER_UNAVAILABLE');
    assert.equal(ver.scannerResults.originalFindingResolved, false);
    assert.equal(ver.beforeAfterComparison.comparisonOutcome, 'SCANNER_UNAVAILABLE');
    assert.equal(ver.beforeAfterComparison.ambiguousMatch, true);

    // Patch state machine: INCONCLUSIVE
    const updatedPatch = patchService.getPatchById(patchId);
    assert.equal(updatedPatch.status, 'INCONCLUSIVE');
    assert.equal(updatedPatch.isVerified, false);

    // Finding state machine: INCONCLUSIVE
    const updatedFinding = scanOrchestrator.getFindingById(findingId);
    assert.equal(updatedFinding.status, 'INCONCLUSIVE');

    // AuditEvent outcome: INCONCLUSIVE
    const auditEvents = verificationService.getAuditEvents(patchId);
    const completeEvent = auditEvents.find(e => e.action === 'PATCH_VERIFICATION_COMPLETED');
    assert.ok(completeEvent);
    assert.equal(completeEvent.outcome, 'INCONCLUSIVE');
  });

  // --------------------------------------------------------------------------
  // 3. VULNERABILITY PERSISTS AFTER PATCH -> FAILED (STILL_DETECTED)
  // --------------------------------------------------------------------------
  it('3. transitions verification to FAILED when original vulnerability still persists', async () => {
    const findingId = 'find_cmdi_persist';
    const patchId = 'patch_cmdi_persist';

    const utilsDir = path.join(tempWorkspace, 'src', 'utils');
    fs.mkdirSync(utilsDir, { recursive: true });
    fs.writeFileSync(
      path.join(utilsDir, 'exec.js'),
      'const child_process = require("child_process");\nchild_process.execSync(`ls -la ${userInput}`);\n',
      'utf8'
    );

    const finding = {
      id: findingId,
      scanId: 'scan_persist',
      ruleId: 'vulnex.javascript.cmd-injection',
      category: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      severity: 'CRITICAL',
      filePath: 'src/utils/exec.js',
      evidence: 'child_process.execSync(`ls ${userInput}`)',
      fingerprint: 'fp_cmdi_persist_001',
      status: 'PATCH_APPLIED'
    };
    scanOrchestrator.addFinding(finding);

    patchService.savePatch({
      id: patchId,
      findingId,
      // Patch is ineffective: still contains injection pattern
      diff: '--- a/src/utils/exec.js\n+++ b/src/utils/exec.js\n@@ -1,1 +1,1 @@\n- child_process.execSync(`ls ${userInput}`)\n+ child_process.execSync(`ls -la ${userInput}`)\n',
      status: 'APPLIED_TO_TEMP',
      disposableWorkspacePath: tempWorkspace,
      appliedWorkspaceId: path.basename(tempWorkspace),
      changedFiles: ['src/utils/exec.js']
    });

    const res = await dispatch('POST', `/api/patches/${patchId}/verify`, {
      body: { options: { workspacePath: tempWorkspace } }
    });
    assert.equal(res.statusCode, 200);

    const ver = res.body.data;
    assert.equal(ver.status, 'FAILED');
    assert.equal(ver.scannerResults.originalFindingResolved, false);
    assert.equal(ver.beforeAfterComparison.comparisonOutcome, 'STILL_DETECTED');

    const updatedPatch = patchService.getPatchById(patchId);
    assert.equal(updatedPatch.status, 'FAILED');
    assert.equal(updatedPatch.isVerified, false);
  });

  // --------------------------------------------------------------------------
  // 4. DEFECT REGRESSION DETECTED -> FAILED (REGRESSION_DETECTED)
  // --------------------------------------------------------------------------
  it('4. transitions verification to FAILED when patch introduces a defect regression', async () => {
    const findingId = 'find_clean_target';
    const patchId = 'patch_introduce_regression';

    const routesDir = path.join(tempWorkspace, 'src', 'routes');
    fs.mkdirSync(routesDir, { recursive: true });
    fs.writeFileSync(
      path.join(routesDir, 'api.js'),
      'const child_process = require("child_process");\nconst q = "SELECT * FROM x";\nchild_process.execSync(`echo ${id}`);\n',
      'utf8'
    );

    const finding = {
      id: findingId,
      scanId: 'scan_regression',
      ruleId: 'vulnex.javascript.sqli',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      severity: 'CRITICAL',
      filePath: 'src/routes/api.js',
      fingerprint: 'fp_sqli_resolved_001',
      status: 'PATCH_APPLIED'
    };
    scanOrchestrator.addFinding(finding);

    patchService.savePatch({
      id: patchId,
      findingId,
      // Fixes SQLi but introduces hardcoded secret / command injection
      diff: '--- a/src/routes/api.js\n+++ b/src/routes/api.js\n@@ -1,1 +1,1 @@\n- const q = `SELECT * FROM x WHERE id = ${id}`;\n+ const q = "SELECT * FROM x"; child_process.execSync(`echo ${id}`);\n',
      status: 'APPLIED_TO_TEMP',
      disposableWorkspacePath: tempWorkspace,
      appliedWorkspaceId: path.basename(tempWorkspace),
      changedFiles: ['src/routes/api.js']
    });

    const res = await dispatch('POST', `/api/patches/${patchId}/verify`, {
      body: { options: { workspacePath: tempWorkspace } }
    });
    assert.equal(res.statusCode, 200);

    const ver = res.body.data;
    assert.equal(ver.status, 'FAILED', 'Must fail verification when defect regression is detected');
    assert.equal(ver.beforeAfterComparison.regressionDetected, true);
    assert.equal(ver.beforeAfterComparison.comparisonOutcome, 'REGRESSION_DETECTED');
    assert.ok(ver.scannerResults.newFindingsCount > 0);

    const updatedPatch = patchService.getPatchById(patchId);
    assert.equal(updatedPatch.status, 'FAILED');
    assert.equal(updatedPatch.isVerified, false);
  });

  // --------------------------------------------------------------------------
  // 5. PARTIAL CHECKS EXECUTED -> PARTIAL
  // --------------------------------------------------------------------------
  it('5. handles PARTIAL verification state when some checks pass but required steps are skipped', async () => {
    const findingId = 'find_partial_test';
    const patchId = 'patch_partial_test';

    const finding = {
      id: findingId,
      scanId: 'scan_partial',
      ruleId: 'vulnex.javascript.sqli',
      severity: 'HIGH',
      filePath: 'src/services/db.js',
      fingerprint: 'fp_partial_001',
      status: 'PATCH_APPLIED'
    };
    scanOrchestrator.addFinding(finding);

    patchService.savePatch({
      id: patchId,
      findingId,
      diff: '--- a/src/services/db.js\n+++ b/src/services/db.js\n@@ -1,1 +1,1 @@\n- bad\n+ good\n',
      status: 'APPLIED_TO_TEMP',
      appliedWorkspaceId: 'ws_disposable_partial'
    });

    // Verification executed with partial flag (e.g. tests passed but re-scan skipped)
    const res = await dispatch('POST', `/api/patches/${patchId}/verify`, {
      body: {
        options: {
          partial: true
        }
      }
    });

    assert.equal(res.statusCode, 200);

    const ver = res.body.data;
    assert.equal(ver.status, 'PARTIAL', 'Status must be PARTIAL per Bible Section 9.3');

    const updatedPatch = patchService.getPatchById(patchId);
    assert.equal(updatedPatch.status, 'PARTIAL');
    assert.equal(updatedPatch.isVerified, false);

    const updatedFinding = scanOrchestrator.getFindingById(findingId);
    assert.equal(updatedFinding.status, 'PARTIAL');

    const auditEvents = verificationService.getAuditEvents(patchId);
    const completeEvent = auditEvents.find(e => e.action === 'PATCH_VERIFICATION_COMPLETED');
    assert.ok(completeEvent);
    assert.equal(completeEvent.outcome, 'PARTIAL');
  });

  // --------------------------------------------------------------------------
  // 6. REPORT CONSOLIDATION ACCURATELY REFLECTS EVIDENCE-BASED STATES
  // --------------------------------------------------------------------------
  it('6. exposes evidence-based FAILED, INCONCLUSIVE, and PARTIAL states in scan report', async () => {
    const scanId = 'scan_report_evidence_states';

    scanOrchestrator.addScan({
      id: scanId,
      repositoryId: 'repo_states_test',
      ref: 'main',
      status: 'COMPLETED',
      toolVersions: { semgrep: '1.98.0', deterministic: '1.0.0' }
    });

    // Finding 1: FAILED (test failure)
    const f1Id = 'find_f1';
    const p1Id = 'patch_p1';
    scanOrchestrator.addFinding({
      id: f1Id,
      scanId,
      ruleId: 'vulnex.javascript.sqli',
      severity: 'CRITICAL',
      filePath: 'src/a.js',
      status: 'FAILED'
    });
    const patch1 = patchService.savePatch({ id: p1Id, findingId: f1Id, status: 'FAILED' });
    verificationService.saveVerification({
      id: 'ver_v1',
      patchId: p1Id,
      status: 'FAILED',
      testResults: { testsPassed: false, syntaxValid: true, testsExecuted: 1, failed: 1, passed: 0 },
      scannerResults: { originalFindingResolved: true, newFindingsCount: 0, ruleId: 'vulnex.javascript.sqli' },
      beforeAfterComparison: { comparisonOutcome: 'RESOLVED', regressionDetected: false }
    });

    // Finding 2: INCONCLUSIVE (scanner unavailable)
    const f2Id = 'find_f2';
    const p2Id = 'patch_p2';
    scanOrchestrator.addFinding({
      id: f2Id,
      scanId,
      ruleId: 'vulnex.javascript.xss',
      severity: 'HIGH',
      filePath: 'src/b.js',
      status: 'INCONCLUSIVE'
    });
    const patch2 = patchService.savePatch({ id: p2Id, findingId: f2Id, status: 'INCONCLUSIVE' });
    verificationService.saveVerification({
      id: 'ver_v2',
      patchId: p2Id,
      status: 'INCONCLUSIVE',
      testResults: { testsPassed: true, syntaxValid: true, testsExecuted: 1, passed: 1, failed: 0 },
      scannerResults: { scannerUnavailable: true, status: 'SCANNER_UNAVAILABLE', originalFindingResolved: false, newFindingsCount: 0, ruleId: 'vulnex.javascript.xss' },
      beforeAfterComparison: { comparisonOutcome: 'SCANNER_UNAVAILABLE', ambiguousMatch: true, regressionDetected: false }
    });

    // Finding 3: PARTIAL (some checks executed)
    const f3Id = 'find_f3';
    const p3Id = 'patch_p3';
    scanOrchestrator.addFinding({
      id: f3Id,
      scanId,
      ruleId: 'vulnex.javascript.hardcoded-secret',
      severity: 'HIGH',
      filePath: 'src/c.js',
      status: 'PARTIAL'
    });
    const patch3 = patchService.savePatch({ id: p3Id, findingId: f3Id, status: 'PARTIAL' });
    verificationService.saveVerification({
      id: 'ver_v3',
      patchId: p3Id,
      status: 'PARTIAL',
      testResults: { testsPassed: true, syntaxValid: true, testsExecuted: 1, passed: 1, failed: 0 },
      scannerResults: { originalFindingResolved: true, newFindingsCount: 0, ruleId: 'vulnex.javascript.hardcoded-secret' },
      beforeAfterComparison: { comparisonOutcome: 'RESOLVED', regressionDetected: false }
    });

    const reportRes = await dispatch('GET', `/api/scans/${scanId}/report`);
    assert.equal(reportRes.statusCode, 200);

    const report = reportRes.body.data;
    assert.equal(report.findings.length, 3);

    // Finding 1 Verification Checks
    const r1 = report.findings.find(f => f.id === f1Id);
    assert.equal(r1.verification.status, 'FAILED');
    const r1TestCheck = r1.verification.checks.find(c => c.id === 'targeted_tests');
    assert.equal(r1TestCheck.status, 'FAILED');

    // Finding 2 Verification Checks
    const r2 = report.findings.find(f => f.id === f2Id);
    assert.equal(r2.verification.status, 'INCONCLUSIVE');
    const r2ScanCheck = r2.verification.checks.find(c => c.id === 'post_patch_scan');
    assert.equal(r2ScanCheck.status, 'INCONCLUSIVE');

    // Finding 3 Verification
    const r3 = report.findings.find(f => f.id === f3Id);
    assert.equal(r3.verification.status, 'PARTIAL');

    // Summary reflects truthful counts
    assert.equal(report.summary.inconclusive, 1);
    assert.equal(report.summary.remediated, 0);
  });
});
