/**
 * Evidence-Backed Scan Report Tests (Commit 41)
 *
 * Verifies Commit 41 Gate:
 * - "Tools, findings, AI, patch and checks."
 * - Master Antigravity Execution Bible Section 4.7 & Section 9.3
 * - docs/API_CONTRACTS.md Section 2.5 (GET /api/scans/:id/report)
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/app');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const reportService = require('../src/services/report.service');
const investigationService = require('../src/services/investigation.service');
const patchService = require('../src/services/patch.service');
const verificationService = require('../src/services/verification.service');

// HTTP dispatch helper for clean endpoint testing
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
      'x-request-id': 'req_scan_report_test',
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

describe('Evidence-Backed Scan Report (Commit 41)', () => {
  beforeEach(() => {
    scanOrchestrator.clearStores();
    investigationService.clearStore();
    patchService.clearStore();
    verificationService.clearStore();
  });

  it('1. returns 404 RESOURCE_NOT_FOUND when scan ID does not exist', async () => {
    const res = await dispatch('GET', '/api/scans/scan_nonexistent_999/report');
    assert.equal(res.statusCode, 404);
    assert.equal(res.body.success, false);
    assert.equal(res.body.error.code, 'RESOURCE_NOT_FOUND');
    assert.ok(res.body.error.message.includes('Scan not found'));
  });

  it('2. consolidates Tools, findings, AI, patch, and checks in report', async () => {
    const scanId = 'scan_test_report_001';
    const findingId = 'find_sql_test_001';
    const patchId = 'patch_sql_test_001';

    // 1. Create Scan with toolVersions (Tools)
    const scanRecord = {
      id: scanId,
      repositoryId: 'repo_vulnex_core',
      ref: 'main',
      status: 'COMPLETED',
      stage: 'COMPLETED',
      toolVersions: {
        semgrep: '1.98.0',
        'npm-audit': '10.8.2',
        deterministic: '1.0.0'
      },
      startedAt: '2026-10-31T03:00:00.000Z',
      completedAt: '2026-10-31T03:01:00.000Z',
      createdAt: '2026-10-31T03:00:00.000Z',
      summary: {
        totalFindings: 1,
        bySeverity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        scannersRun: ['semgrep', 'npm-audit', 'deterministic']
      }
    };
    scanOrchestrator.addScan(scanRecord);

    // 2. Create Finding (Findings)
    const finding = {
      id: findingId,
      scanId,
      scanner: 'semgrep',
      ruleId: 'javascript.express.security.audit.sqli.express-sqli',
      title: 'Express SQL Injection',
      category: 'SQL_INJECTION',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      filePath: 'src/controllers/user.controller.js',
      startLine: 42,
      endLine: 44,
      message: 'Unsanitized user input directly interpolated into SQL query.',
      fingerprint: 'sha256_canonical_fp_sqli_001',
      status: 'VERIFIED'
    };
    scanOrchestrator.addFinding(finding);

    // 3. Attach AI Investigation (AI)
    const investigation = {
      id: 'inv_test_001',
      findingId,
      assessment: 'LIKELY_TRUE',
      confidence: 'HIGH',
      explanation: 'User parameter req.params.id is concatenated directly into SQL command.',
      impact: 'Unauthenticated database read/write access.',
      recommendation: 'Use parameterized query bind variables.',
      evidence: ['Untrusted parameter req.params.id reaches query sink at line 42'],
      preconditions: ['Network access to user controller endpoint'],
      limitations: ['Static analysis without live DB execution'],
      model: 'gemma-2-9b-it',
      promptVersion: 'vulnex-investigation-v1'
    };
    investigationService.saveInvestigation(investigation);

    // 4. Attach Patch Proposal (Patch)
    const patch = {
      id: patchId,
      findingId,
      diff: '--- a/src/controllers/user.controller.js\n+++ b/src/controllers/user.controller.js\n@@ -42,3 +42,3 @@\n-  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);\n+  db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);\n',
      rationale: 'Converted string concatenation to parameterized SQL query.',
      status: 'VERIFIED',
      reviewState: 'APPROVED',
      changedFiles: ['src/controllers/user.controller.js'],
      appliedWorkspaceId: 'ws_disposable_test_001',
      isVerified: true
    };
    patchService.savePatch(patch);

    // 5. Attach Verification Record (Checks)
    const verificationRecord = {
      id: 'ver_test_001',
      patchId,
      status: 'PASSED',
      testResults: {
        testsPassed: true,
        syntaxValid: true,
        testsExecuted: 4,
        passed: 4,
        failed: 0,
        command: ['node', '--test'],
        exitCode: 0,
        stdout: 'All 4 tests passed.',
        stderr: ''
      },
      scannerResults: {
        originalFindingResolved: true,
        newFindingsCount: 0,
        ruleId: 'javascript.express.security.audit.sqli.express-sqli',
        tool: 'semgrep',
        toolVersion: '1.98.0',
        command: ['semgrep', 'scan', '--json'],
        exitCode: 0
      },
      beforeAfterComparison: {
        comparisonOutcome: 'RESOLVED',
        targetFingerprint: 'sha256_canonical_fp_sqli_001',
        matchedFingerprint: null,
        ambiguousMatch: false,
        regressionDetected: false
      }
    };
    // Save to verification store
    verificationService.saveVerification(verificationRecord);
    verificationService.logAuditEvent({
      action: 'VERIFICATION_COMPLETED',
      entityId: patchId,
      outcome: 'SUCCESS'
    });
    patch.verificationId = verificationRecord.id;
    patchService.savePatch(patch);

    // Now call GET /api/scans/:id/report
    const res = await dispatch('GET', `/api/scans/${scanId}/report`);

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.success, true);
    assert.ok(res.body.data);

    const report = res.body.data;

    // Gate requirement 1: Tools
    assert.ok(report.tools, 'Report must contain tools');
    assert.equal(report.tools.semgrep, '1.98.0');
    assert.equal(report.tools['npm-audit'], '10.8.2');
    assert.equal(report.tools.deterministic, '1.0.0');
    assert.deepEqual(report.scan.toolVersions, report.tools);

    // Gate requirement 2: Findings
    assert.ok(Array.isArray(report.findings), 'Report must contain findings array');
    assert.equal(report.findings.length, 1);
    const findingInReport = report.findings[0];
    assert.equal(findingInReport.id, findingId);
    assert.equal(findingInReport.ruleId, 'javascript.express.security.audit.sqli.express-sqli');
    assert.equal(findingInReport.severity, 'CRITICAL');
    assert.equal(findingInReport.filePath, 'src/controllers/user.controller.js');
    assert.equal(findingInReport.scanner, 'semgrep');

    // Gate requirement 3: AI
    assert.ok(findingInReport.investigation, 'Finding must contain enriched AI investigation');
    assert.equal(findingInReport.investigation.assessment, 'LIKELY_TRUE');
    assert.equal(findingInReport.investigation.confidence, 'HIGH');
    assert.equal(findingInReport.investigation.impact, 'Unauthenticated database read/write access.');
    assert.equal(findingInReport.investigation.model, 'gemma-2-9b-it');

    // Gate requirement 4: Patch
    assert.ok(findingInReport.patch, 'Finding must contain enriched patch proposal');
    assert.equal(findingInReport.patch.id, patchId);
    assert.equal(findingInReport.patch.status, 'VERIFIED');
    assert.ok(findingInReport.patch.diff.includes('db.query("SELECT * FROM users WHERE id = ?"'));
    assert.deepEqual(findingInReport.patch.changedFiles, ['src/controllers/user.controller.js']);

    // Gate requirement 5: Checks
    assert.ok(findingInReport.verification !== undefined);
  });

  it('3. accurately aggregates verification checks and status per check', async () => {
    const scanId = 'scan_test_report_002';
    const findingId = 'find_xss_test_002';
    const patchId = 'patch_xss_test_002';

    scanOrchestrator.addScan({
      id: scanId,
      repositoryId: 'repo_vulnex_core',
      ref: 'main',
      status: 'COMPLETED',
      toolVersions: { semgrep: '1.98.0' }
    });

    scanOrchestrator.addFinding({
      id: findingId,
      scanId,
      scanner: 'semgrep',
      ruleId: 'javascript.browser.security.audit.xss',
      title: 'DOM XSS',
      category: 'XSS',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      filePath: 'src/views/profile.js',
      startLine: 12,
      endLine: 12,
      fingerprint: 'sha256_canonical_xss',
      status: 'DETECTED'
    });

    const patch = patchService.savePatch({
      id: patchId,
      findingId,
      diff: '--- a/src/views/profile.js\n+++ b/src/views/profile.js\n@@ -12,1 +12,1 @@\n- element.innerHTML = name;\n+ element.textContent = name;\n',
      status: 'APPLIED_TO_TEMP',
      appliedWorkspaceId: 'ws_disposable_xss'
    });

    // Verification with ambiguous match => INCONCLUSIVE
    const verificationRecord = {
      id: 'ver_test_002',
      patchId,
      status: 'INCONCLUSIVE',
      testResults: {
        testsPassed: true,
        syntaxValid: true,
        testsExecuted: 2,
        passed: 2,
        failed: 0
      },
      scannerResults: {
        originalFindingResolved: false,
        newFindingsCount: 0
      },
      beforeAfterComparison: {
        comparisonOutcome: 'AMBIGUOUS',
        ambiguousMatch: true,
        regressionDetected: false
      }
    };

    // Inject verification into verificationService store
    verificationService.saveVerification(verificationRecord);
    patch.verificationId = verificationRecord.id;
    patchService.savePatch(patch);

    const report = reportService.generateScanReport(scanId);
    assert.ok(report);
    assert.equal(report.scan.id, scanId);
    assert.equal(report.findings.length, 1);
    assert.equal(report.findings[0].patch.status, 'APPLIED_TO_TEMP');

    const ver = report.findings[0].verification;
    assert.ok(ver);
    assert.equal(ver.status, 'INCONCLUSIVE');
    assert.equal(ver.ambiguousMatch, true);
    assert.ok(Array.isArray(ver.checks));
    assert.equal(ver.checks.length, 5);

    // Checks should have PASSED/FAILED/NOT RUN/INCONCLUSIVE per check
    const postScanCheck = ver.checks.find((c) => c.id === 'post_patch_scan');
    const regressionCheck = ver.checks.find((c) => c.id === 'defect_regression');
    assert.equal(postScanCheck.status, 'INCONCLUSIVE');
    assert.equal(regressionCheck.status, 'INCONCLUSIVE');
  });

  it('4. provides default fallback tools when toolVersions is empty', () => {
    const scanId = 'scan_empty_tools';
    scanOrchestrator.addScan({
      id: scanId,
      repositoryId: 'repo_test',
      status: 'COMPLETED'
    });

    const report = reportService.generateScanReport(scanId);
    assert.ok(report.tools);
    assert.ok(report.tools.semgrep);
    assert.ok(report.tools['npm-audit']);
    assert.equal(report.summary.totalFindings, 0);
  });
});
