/**
 * VULNEX Commit 47 Report Export & Scan History Test Suite
 *
 * Acceptance Gate: Only if core workflow stable.
 * Features:
 * - Scan history view with repo/ref, tool versions, finding counts, patch attempts, verification outcomes.
 * - Identification of tools and security rules producing results.
 * - Multi-format export: JSON, Markdown, SARIF v2.1.0, and CSV.
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');
const http = require('http');

const app = require('../src/app');
const reportService = require('../src/services/report.service');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const patchService = require('../src/services/patch.service');
const verificationService = require('../src/services/verification.service');

// HTTP Dispatch helper
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
    req.method = method;
    req.url = url;
    req.originalUrl = url;
    req.headers = {
      'content-type': 'application/json',
      host: 'localhost:5001',
      ...headers
    };
    req.query = { ...parsedQuery, ...query };

    let rawBody = '';
    const res = new http.ServerResponse(req);
    res.setHeader = (name, value) => {
      res._headers = res._headers || {};
      res._headers[name.toLowerCase()] = value;
    };
    res.getHeader = (name) => (res._headers && res._headers[name.toLowerCase()]) || null;
    res.getHeaders = () => res._headers || {};

    res.write = (chunk) => {
      if (chunk) rawBody += chunk;
      return true;
    };

    res.end = (chunk) => {
      if (chunk) rawBody += chunk;
      let parsed = null;
      try {
        parsed = rawBody ? JSON.parse(rawBody) : null;
      } catch (_) {
        parsed = rawBody;
      }

      resolve({
        statusCode: res.statusCode,
        headers: res.getHeaders(),
        body: parsed
      });
    };

    if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
      req.push(JSON.stringify(body));
    }
    req.push(null);

    app.handle(req, res);
  });
}

describe('Commit 47: Scan History & Report Export (Multi-Format, Tools/Rules)', () => {
  const scanId = 'scan_history_export_001';

  beforeEach(() => {
    scanOrchestrator.clearStores();
    patchService.clearStore();
    verificationService.clearStore();

    // Register a completed scan with rich metadata
    const scan = {
      id: scanId,
      repositoryId: 'repo_vulnex_sample',
      ref: 'main',
      status: 'COMPLETED',
      stage: 'COMPLETED',
      startedAt: '2026-10-31T10:00:00.000Z',
      completedAt: '2026-10-31T10:00:30.000Z',
      toolVersions: {
        semgrep: '1.98.0',
        'npm-audit': '10.8.2'
      },
      events: []
    };
    scanOrchestrator.addScan(scan);

    // Finding 1: SQL Injection (Remediated / Verified)
    const finding1 = {
      id: 'find_sqli_001',
      scanId,
      ruleId: 'javascript.express.security.audit.sqli.express-sqli',
      title: 'SQL Injection Vulnerability',
      category: 'SQL_INJECTION',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      filePath: 'src/routes/user.js',
      startLine: 24,
      endLine: 24,
      message: 'Unsanitized user input directly concatenated into SQL query',
      scanner: 'semgrep',
      status: 'VERIFIED',
      verification: {
        id: 'ver_001',
        status: 'PASSED',
        testResults: { testsPassed: true, syntaxValid: true },
        scannerResults: { originalFindingResolved: true, newFindingsCount: 0 }
      }
    };
    scanOrchestrator.addFinding(finding1);

    // Register patch for finding 1
    patchService.savePatch({
      id: 'patch_sqli_001',
      findingId: finding1.id,
      diff: '--- a/src/routes/user.js\n+++ b/src/routes/user.js\n@@ -24,1 +24,1 @@\n-query("SELECT * FROM users WHERE id = " + id)\n+query("SELECT * FROM users WHERE id = $1", [id])\n',
      rationale: 'Use parameterized queries instead of string concatenation.',
      status: 'VERIFIED',
      reviewState: 'APPROVED',
      isVerified: true
    });

    // Finding 2: Insecure Crypto (Triaged, not yet patched)
    const finding2 = {
      id: 'find_crypto_002',
      scanId,
      ruleId: 'VULN-005',
      title: 'Weak Cryptographic Hash (MD5)',
      category: 'INSECURE_CRYPTO',
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      filePath: 'src/utils/auth.js',
      startLine: 12,
      endLine: 12,
      message: 'Use of MD5 hash detected',
      scanner: 'semgrep',
      status: 'TRIAGED'
    };
    scanOrchestrator.addFinding(finding2);
  });

  it('1. retrieves historical scan summary with tool versions, finding counts, and verification outcomes', () => {
    const history = reportService.getScanHistory();

    assert.ok(Array.isArray(history.scans));
    assert.strictEqual(history.scans.length, 1);

    const scanRecord = history.scans[0];
    assert.strictEqual(scanRecord.id, scanId);
    assert.strictEqual(scanRecord.repositoryId, 'repo_vulnex_sample');
    assert.strictEqual(scanRecord.ref, 'main');
    assert.strictEqual(scanRecord.status, 'COMPLETED');
    assert.strictEqual(scanRecord.durationSeconds, 30);

    // Tool versions captured
    assert.strictEqual(scanRecord.toolVersions.semgrep, '1.98.0');
    assert.strictEqual(scanRecord.toolVersions['npm-audit'], '10.8.2');

    // Finding counts & verification outcome
    assert.strictEqual(scanRecord.summary.totalFindings, 2);
    assert.strictEqual(scanRecord.summary.critical, 1);
    assert.strictEqual(scanRecord.summary.medium, 1);
    assert.strictEqual(scanRecord.summary.patchAttempts, 1);
    assert.strictEqual(scanRecord.summary.remediated, 1);
    assert.strictEqual(scanRecord.verificationOutcome, 'PASSED');

    // Global summary
    assert.strictEqual(history.summary.totalScans, 1);
    assert.strictEqual(history.summary.completedScans, 1);
    assert.strictEqual(history.summary.totalFindingsDetected, 2);
    assert.strictEqual(history.summary.totalRemediated, 1);
  });

  it('2. identifies tools and security rules producing results', () => {
    const report = reportService.generateScanReport(scanId);

    assert.ok(report.toolsAndRules);
    assert.strictEqual(report.toolsAndRules.byScanner.semgrep, 2);

    assert.ok(Array.isArray(report.toolsAndRules.byRule));
    assert.strictEqual(report.toolsAndRules.byRule.length, 2);

    const sqliRule = report.toolsAndRules.byRule.find(
      (r) => r.ruleId === 'javascript.express.security.audit.sqli.express-sqli'
    );
    assert.ok(sqliRule);
    assert.strictEqual(sqliRule.occurrences, 1);
    assert.strictEqual(sqliRule.remediatedCount, 1);
    assert.strictEqual(sqliRule.severity, 'CRITICAL');
  });

  it('3. exports report in Markdown format with executive summary and verification receipts', () => {
    const report = reportService.generateScanReport(scanId, { format: 'markdown' });

    assert.strictEqual(report.format, 'markdown');
    assert.strictEqual(report.contentType, 'text/markdown');
    assert.strictEqual(typeof report.content, 'string');

    // Key markdown sections required for audit report
    assert.ok(report.content.includes('# VULNEX Security Audit & Verification Report'));
    assert.ok(report.content.includes('## 1. Engine Provenance & Tool Versions'));
    assert.ok(report.content.includes('semgrep'));
    assert.ok(report.content.includes('1.98.0'));
    assert.ok(report.content.includes('## 2. Executive Summary'));
    assert.ok(report.content.includes('## 3. Findings & Verification Receipts'));
    assert.ok(report.content.includes('javascript.express.security.audit.sqli.express-sqli'));
    assert.ok(report.content.includes('```diff'));
    assert.ok(report.content.includes('## 4. Auditor Disclaimer'));
  });

  it('4. exports report in SARIF v2.1.0 standard schema for GitHub Code Scanning', () => {
    const report = reportService.generateScanReport(scanId, { format: 'sarif' });

    assert.strictEqual(report.format, 'sarif');
    assert.strictEqual(report.contentType, 'application/sarif+json');
    assert.ok(report.sarif);

    const sarif = report.sarif;
    assert.strictEqual(sarif.version, '2.1.0');
    assert.ok(Array.isArray(sarif.runs));
    assert.strictEqual(sarif.runs.length, 1);

    const run = sarif.runs[0];
    assert.strictEqual(run.tool.driver.name, 'VULNEX Security Engine');
    assert.ok(Array.isArray(run.results));
    assert.strictEqual(run.results.length, 2);

    const r1 = run.results.find(
      (r) => r.ruleId === 'javascript.express.security.audit.sqli.express-sqli'
    );
    assert.ok(r1);
    assert.strictEqual(r1.locations[0].physicalLocation.artifactLocation.uri, 'src/routes/user.js');
    assert.strictEqual(r1.properties.verificationStatus, 'PASSED');
  });

  it('5. exports report in CSV format for spreadsheet auditing', () => {
    const report = reportService.generateScanReport(scanId, { format: 'csv' });

    assert.strictEqual(report.format, 'csv');
    assert.strictEqual(report.contentType, 'text/csv');
    assert.strictEqual(typeof report.content, 'string');

    const lines = report.content.split('\n');
    assert.ok(lines.length >= 3);
    assert.ok(lines[0].includes('Finding ID,Rule ID,Severity,File Path'));
    assert.ok(report.content.includes('"find_sqli_001"'));
    assert.ok(report.content.includes('"CRITICAL"'));
    assert.ok(report.content.includes('YES'));
  });

  it('6. GET /api/scans/history returns historical scans and aggregate metrics', async () => {
    const res = await dispatch('GET', '/api/scans/history');

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(Array.isArray(res.body.data.scans));
    assert.strictEqual(res.body.data.scans.length, 1);
    assert.strictEqual(res.body.data.scans[0].id, scanId);
    assert.strictEqual(res.body.data.summary.totalScans, 1);
    assert.strictEqual(res.body.data.summary.totalRemediated, 1);
  });

  it('7. GET /api/scans/:id/report supports format query parameter', async () => {
    const res = await dispatch('GET', `/api/scans/${scanId}/report?format=markdown`);

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.format, 'markdown');
    assert.ok(res.body.data.content.includes('# VULNEX Security Audit & Verification Report'));
  });

  it('8. GET /api/scans/:id/export provides multi-format export capabilities', async () => {
    const res = await dispatch('GET', `/api/scans/${scanId}/export?format=sarif`);

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.format, 'sarif');
    assert.strictEqual(res.body.data.sarif.version, '2.1.0');
  });
});
