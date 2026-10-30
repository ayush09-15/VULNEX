const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { ScanOrchestrator, generateFingerprint, recordEvent } = require('../src/orchestrator/scanOrchestrator');
const { SCAN_STATES } = require('../src/orchestrator/scanStateMachine');

describe('Scan Orchestrator Core (Task 16)', () => {
  let testWorkspace;
  let orchestrator;

  before(() => {
    orchestrator = new ScanOrchestrator();

    // Create temporary workspace with controlled vulnerable fixtures
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex-orch-test-'));
    fs.mkdirSync(path.join(testWorkspace, 'src', 'controllers'), { recursive: true });

    // Vulnerable SQL file
    fs.writeFileSync(
      path.join(testWorkspace, 'src', 'controllers', 'user.js'),
      'const express = require("express");\n' +
      'app.get("/users", (req, res) => {\n' +
      '  const q = `SELECT * FROM users WHERE name = ${req.query.name}`;\n' +
      '  db.query(q);\n' +
      '});\n'
    );

    // Hard-coded secret file
    fs.writeFileSync(
      path.join(testWorkspace, 'src', 'config.js'),
      'module.exports = {\n' +
      '  apiKey: "AKIA1234567890ABCDEF",\n' +
      '  jwtSecret: "super_secret_token_1234567890"\n' +
      '};\n'
    );

    // Package manifest
    fs.writeFileSync(
      path.join(testWorkspace, 'package.json'),
      JSON.stringify({ name: 'vulnerable-test-app', version: '1.0.0' }, null, 2)
    );
  });

  after(() => {
    if (testWorkspace && fs.existsSync(testWorkspace)) {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    }
  });

  // --------------------------------------------------------------------------
  // 1. One Scan ID & Event Timeline
  // --------------------------------------------------------------------------
  describe('One Scan ID & Stage Events Timeline', () => {
    it('should assign a single traceable scanId across all stages and findings', async () => {
      const scan = await orchestrator.startScan({
        repositoryId: 'repo_unit_test',
        repositoryPath: testWorkspace,
        ref: 'main',
        scanners: ['patterns']
      });

      assert.ok(scan.id.startsWith('scan_'), 'scanId must start with scan_');
      assert.strictEqual(scan.repositoryId, 'repo_unit_test');
      assert.strictEqual(scan.ref, 'main');
      assert.strictEqual(scan.status, SCAN_STATES.COMPLETED);

      // Verify all findings have the EXACT SAME scanId
      const findings = orchestrator.getScanFindings(scan.id);
      assert.ok(findings.length >= 2, 'Should detect SQL injection and hard-coded secrets');
      for (const finding of findings) {
        assert.strictEqual(finding.scanId, scan.id, 'Finding scanId must match parent scan');
      }
    });

    it('should record chronological, immutable stage events throughout scan lifecycle', async () => {
      const scan = await orchestrator.startScan({
        repositoryId: 'repo_events_test',
        repositoryPath: testWorkspace,
        scanners: ['patterns']
      });

      const events = orchestrator.getScanEvents(scan.id);
      assert.ok(Array.isArray(events));
      assert.ok(events.length >= 4, 'Must contain events for QUEUED, PREPARING, SCANNING, NORMALIZING, COMPLETED');

      const stagesLogged = events.map((e) => e.stage);
      assert.ok(stagesLogged.includes(SCAN_STATES.QUEUED));
      assert.ok(stagesLogged.includes(SCAN_STATES.PREPARING));
      assert.ok(stagesLogged.includes(SCAN_STATES.SCANNING));
      assert.ok(stagesLogged.includes(SCAN_STATES.NORMALIZING));

      // Check event structure
      for (const event of events) {
        assert.ok(event.stage);
        assert.ok(['IN_PROGRESS', 'SUCCESS', 'FAILED', 'SKIPPED'].includes(event.status));
        assert.ok(event.timestamp && !isNaN(new Date(event.timestamp).getTime()));
        assert.ok(typeof event.message === 'string' && event.message.length > 0);
      }
    });
  });

  // --------------------------------------------------------------------------
  // 2. Normalization & Fingerprint Deduplication
  // --------------------------------------------------------------------------
  describe('Finding Normalization & Deduplication', () => {
    it('should normalize findings to canonical schema and deduplicate identical findings', async () => {
      const scan = await orchestrator.startScan({
        repositoryId: 'repo_dedup_test',
        repositoryPath: testWorkspace,
        scanners: ['patterns']
      });

      const findings = orchestrator.getScanFindings(scan.id);

      // Verify canonical fields on each finding
      for (const finding of findings) {
        assert.ok(finding.id.startsWith('find_'));
        assert.strictEqual(finding.status, 'DETECTED');
        assert.ok(finding.fingerprint && finding.fingerprint.length === 64);
        assert.ok(finding.startLine >= 1);
        assert.ok(finding.endLine >= finding.startLine);
        assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(finding.severity));
        assert.ok(!finding.filePath.startsWith('/'), 'filePath must be relative');
      }

      // Check for zero duplicate fingerprints within the scan
      const fingerprints = findings.map((f) => f.fingerprint);
      const uniqueFingerprints = new Set(fingerprints);
      assert.strictEqual(fingerprints.length, uniqueFingerprints.size, 'No duplicate fingerprints allowed');
    });

    it('should generate stable deterministic fingerprints', () => {
      const fp1 = generateFingerprint({
        ruleId: 'vulnex.javascript.sqli',
        filePath: 'src/controllers/user.js',
        evidence: 'db.query(q);'
      });

      const fp2 = generateFingerprint({
        ruleId: 'vulnex.javascript.sqli',
        filePath: 'src/controllers/user.js',
        evidence: '  db.query(q);  ' // extra whitespace normalized
      });

      assert.strictEqual(fp1, fp2, 'Fingerprints must match after whitespace normalization');
    });
  });

  // --------------------------------------------------------------------------
  // 3. Partial Failure Behavior (Bible Section 8.9)
  // --------------------------------------------------------------------------
  describe('Partial Failure Behavior', () => {
    it('should mark scan as PARTIAL and preserve surviving findings if one scanner fails', async () => {
      // Mock an orchestrator where Semgrep is forced to fail, but pattern scanner succeeds
      const mockSemgrepService = {
        isAvailable: async () => true,
        scanWithSemgrep: async () => ({
          success: false,
          status: 'FAILED',
          findings: [],
          errors: ['Semgrep ruleset failed to compile syntax error']
        })
      };

      const partialOrchestrator = new ScanOrchestrator();
      partialOrchestrator.semgrep = mockSemgrepService;

      const scan = await partialOrchestrator.startScan({
        repositoryId: 'repo_partial_test',
        repositoryPath: testWorkspace,
        scanners: ['semgrep', 'patterns']
      });

      // Partial status assertion
      assert.strictEqual(scan.status, SCAN_STATES.PARTIAL, 'Must be marked as PARTIAL');
      assert.strictEqual(scan.summary.scannersFailed.length, 1);
      assert.strictEqual(scan.summary.scannersFailed[0].scanner, 'semgrep');
      assert.ok(scan.summary.scannersRun.includes('pattern-sast'));

      // Findings from surviving scanner must NOT be discarded
      assert.ok(scan.summary.totalFindings > 0, 'Surviving scanner findings must be preserved');
      const findings = partialOrchestrator.getScanFindings(scan.id);
      assert.strictEqual(findings.length, scan.summary.totalFindings);

      // Event log must document the partial failure honestly
      const events = partialOrchestrator.getScanEvents(scan.id);
      const semgrepFailEvent = events.find((e) => e.message.includes('Semgrep scanner reported error'));
      assert.ok(semgrepFailEvent, 'Event log must capture scanner failure');
    });

    it('should mark scan as FAILED if all scanners fail', async () => {
      const mockAllFailedSemgrep = {
        isAvailable: async () => true,
        scanWithSemgrep: async () => ({
          success: false,
          status: 'FAILED',
          findings: [],
          errors: ['Semgrep crashed']
        })
      };

      const failingOrchestrator = new ScanOrchestrator();
      failingOrchestrator.semgrep = mockAllFailedSemgrep;

      // Run ONLY the failing scanner
      const scan = await failingOrchestrator.startScan({
        repositoryId: 'repo_failed_test',
        repositoryPath: testWorkspace,
        scanners: ['semgrep']
      });

      assert.strictEqual(scan.status, SCAN_STATES.FAILED);
      assert.strictEqual(scan.errorCode, 'SCANNER_FAILURE');
      assert.strictEqual(scan.summary.totalFindings, 0);

      const events = failingOrchestrator.getScanEvents(scan.id);
      const lastEvent = events[events.length - 1];
      assert.strictEqual(lastEvent.stage, SCAN_STATES.FAILED);
    });

    it('should transition to FAILED with WORKSPACE_ERROR if workspace does not exist', async () => {
      const scan = await orchestrator.startScan({
        repositoryId: 'repo_missing',
        repositoryPath: '/path/does/not/exist/anywhere/12345'
      });

      assert.strictEqual(scan.status, SCAN_STATES.FAILED);
      assert.strictEqual(scan.stage, SCAN_STATES.FAILED);
      assert.strictEqual(scan.errorCode, 'WORKSPACE_ERROR');
      assert.strictEqual(scan.summary.totalFindings, 0);
    });
  });

  // --------------------------------------------------------------------------
  // 4. Filtering and Store Retrieval
  // --------------------------------------------------------------------------
  describe('Findings Query & Severity Filtering', () => {
    it('should filter findings by severity, category, and scanner', async () => {
      const scan = await orchestrator.startScan({
        repositoryId: 'repo_filter_test',
        repositoryPath: testWorkspace,
        scanners: ['patterns']
      });

      const criticals = orchestrator.getScanFindings(scan.id, { severity: 'CRITICAL' });
      for (const c of criticals) {
        assert.strictEqual(c.severity, 'CRITICAL');
      }

      const sqliFindings = orchestrator.getScanFindings(scan.id, { category: 'SQL_INJECTION' });
      for (const s of sqliFindings) {
        assert.strictEqual(s.category, 'SQL_INJECTION');
      }

      const patternFindings = orchestrator.getScanFindings(scan.id, { scanner: 'pattern-sast' });
      for (const p of patternFindings) {
        assert.strictEqual(p.scanner, 'pattern-sast');
      }
    });
  });
});
