const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { ScanOrchestrator, sanitizeErrorMessage } = require('../src/orchestrator/scanOrchestrator');
const { SCAN_STATES } = require('../src/orchestrator/scanStateMachine');

describe('Dependency Scan Partial-Result Handling (feat/scanner)', () => {
  let testWorkspace;
  let orchestrator;

  before(() => {
    orchestrator = new ScanOrchestrator();

    // Set up isolated temp workspace
    testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex-partial-test-'));
    fs.mkdirSync(path.join(testWorkspace, 'src'), { recursive: true });

    // Mock dummy source file
    fs.writeFileSync(
      path.join(testWorkspace, 'src', 'app.js'),
      'console.log("hello world");\n'
    );

    // Mock package manifests
    fs.writeFileSync(
      path.join(testWorkspace, 'package.json'),
      JSON.stringify({ name: 'partial-test-app', version: '1.0.0' }, null, 2)
    );
    fs.writeFileSync(
      path.join(testWorkspace, 'package-lock.json'),
      JSON.stringify({ name: 'partial-test-app', version: '1.0.0', lockfileVersion: 2 }, null, 2)
    );
  });

  after(() => {
    if (testWorkspace && fs.existsSync(testWorkspace)) {
      fs.rmSync(testWorkspace, { recursive: true, force: true });
    }
  });

  const sampleSemgrepFinding = {
    id: 'find_semgrep_sqli',
    scanner: 'semgrep',
    ruleId: 'javascript.express.security.audit.sqli',
    title: 'SQL Injection via query concatenation',
    category: 'SQL_INJECTION',
    severity: 'HIGH',
    confidence: 'HIGH',
    filePath: 'src/app.js',
    startLine: 1,
    endLine: 1,
    message: 'Direct concatenation of query input into SQL query',
    evidence: 'db.query("SELECT * FROM users WHERE id = " + req.query.id);'
  };

  const sampleNpmFinding = {
    id: 'find_npm_semver',
    scanner: 'npm-audit',
    rule: 'npm-audit:semver:GHSA-c2qf-rxjj-qqgw',
    title: 'Regular Expression Denial of Service in semver',
    category: 'VULNERABLE_DEPENDENCY',
    severity: 'HIGH',
    confidence: 'HIGH',
    path: 'package-lock.json',
    startLine: 1,
    endLine: 1,
    message: 'Regular Expression Denial of Service in semver',
    evidence: 'semver@5.7.1 (<5.7.2) via package-lock.json',
    fingerprint: '3a1f4b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a'
  };

  // --------------------------------------------------------------------------
  // Scenario 1: Both Scanners Succeed
  // --------------------------------------------------------------------------
  describe('1. Both Scanners Succeed', () => {
    it('should complete scan with COMPLETED status and merge findings through normalization', async () => {
      const mockSemgrep = {
        isAvailable: async () => true,
        scanWithSemgrep: async () => ({
          success: true,
          status: 'COMPLETED',
          findings: [sampleSemgrepFinding],
          errors: [],
          provenance: { version: '1.45.0' },
          durationMs: 40
        })
      };

      const mockNpmAudit = {
        isAvailable: async () => true,
        getVersion: async () => '10.2.4',
        scanWorkspace: async () => ({
          success: true,
          status: 'COMPLETED',
          scanner: 'npm-audit',
          findings: [sampleNpmFinding],
          errors: [],
          durationMs: 35
        })
      };

      const testOrch = new ScanOrchestrator();
      testOrch.semgrep = mockSemgrep;
      testOrch.npmAudit = mockNpmAudit;

      const scan = await testOrch.startScan({
        repositoryId: 'repo_both_succeed',
        repositoryPath: testWorkspace,
        scanners: ['semgrep', 'npm-audit']
      });

      assert.strictEqual(scan.status, SCAN_STATES.COMPLETED);
      assert.strictEqual(scan.stage, SCAN_STATES.COMPLETED);
      assert.strictEqual(scan.errorCode, null);
      assert.strictEqual(scan.summary.scannersRun.length, 2);
      assert.ok(scan.summary.scannersRun.includes('semgrep'));
      assert.ok(scan.summary.scannersRun.includes('npm-audit'));
      assert.strictEqual(scan.summary.scannersFailed.length, 0);

      // Verify scannerOutcomes
      assert.strictEqual(scan.summary.scannerOutcomes.semgrep.status, 'COMPLETED');
      assert.strictEqual(scan.summary.scannerOutcomes.semgrep.findingsCount, 1);
      assert.strictEqual(scan.summary.scannerOutcomes['npm-audit'].status, 'COMPLETED');
      assert.strictEqual(scan.summary.scannerOutcomes['npm-audit'].findingsCount, 1);

      // Verify merged findings
      assert.strictEqual(scan.summary.totalFindings, 2);
      const findings = testOrch.getScanFindings(scan.id);
      assert.strictEqual(findings.length, 2);

      const semgrepFound = findings.find(f => f.scanner === 'semgrep');
      const npmFound = findings.find(f => f.scanner === 'npm-audit');
      assert.ok(semgrepFound, 'Semgrep finding must be preserved in merged results');
      assert.ok(npmFound, 'npm-audit finding must be preserved in merged results');
      assert.strictEqual(npmFound.category, 'VULNERABLE_DEPENDENCY');
    });
  });

  // --------------------------------------------------------------------------
  // Scenario 2: Semgrep Fails, npm Audit Succeeds
  // --------------------------------------------------------------------------
  describe('2. Semgrep Fails, npm Audit Succeeds', () => {
    it('should mark scan as PARTIAL, preserve npm audit findings, and record Semgrep failure', async () => {
      const mockSemgrep = {
        isAvailable: async () => true,
        scanWithSemgrep: async () => ({
          success: false,
          status: 'FAILED',
          findings: [],
          errors: ['Semgrep internal error: rule compilation failed'],
          durationMs: 25
        })
      };

      const mockNpmAudit = {
        isAvailable: async () => true,
        getVersion: async () => '10.2.4',
        scanWorkspace: async () => ({
          success: true,
          status: 'COMPLETED',
          scanner: 'npm-audit',
          findings: [sampleNpmFinding],
          errors: [],
          durationMs: 50
        })
      };

      const testOrch = new ScanOrchestrator();
      testOrch.semgrep = mockSemgrep;
      testOrch.npmAudit = mockNpmAudit;

      const scan = await testOrch.startScan({
        repositoryId: 'repo_semgrep_fails',
        repositoryPath: testWorkspace,
        scanners: ['semgrep', 'npm-audit']
      });

      assert.strictEqual(scan.status, SCAN_STATES.PARTIAL);
      assert.strictEqual(scan.stage, SCAN_STATES.COMPLETED);
      assert.strictEqual(scan.summary.scannersRun.length, 1);
      assert.ok(scan.summary.scannersRun.includes('npm-audit'));
      assert.strictEqual(scan.summary.scannersFailed.length, 1);
      assert.strictEqual(scan.summary.scannersFailed[0].scanner, 'semgrep');
      assert.strictEqual(scan.summary.scannerOutcomes.semgrep.status, 'FAILED');
      assert.strictEqual(scan.summary.scannerOutcomes['npm-audit'].status, 'COMPLETED');

      // Findings from surviving npm audit must NOT be discarded
      assert.strictEqual(scan.summary.totalFindings, 1);
      const findings = testOrch.getScanFindings(scan.id);
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].scanner, 'npm-audit');
      assert.strictEqual(findings[0].ruleId, 'npm-audit:semver:GHSA-c2qf-rxjj-qqgw');

      // Event log check
      const events = testOrch.getScanEvents(scan.id);
      const failEvent = events.find(e => e.message.includes('Semgrep scanner reported error'));
      assert.ok(failEvent, 'Event log must capture Semgrep failure');
    });
  });

  // --------------------------------------------------------------------------
  // Scenario 3: npm Audit Fails, Semgrep Succeeds
  // --------------------------------------------------------------------------
  describe('3. npm Audit Fails, Semgrep Succeeds', () => {
    it('should mark scan as PARTIAL, preserve Semgrep findings, and record npm audit failure', async () => {
      const mockSemgrep = {
        isAvailable: async () => true,
        scanWithSemgrep: async () => ({
          success: true,
          status: 'COMPLETED',
          findings: [sampleSemgrepFinding],
          errors: [],
          provenance: { version: '1.45.0' },
          durationMs: 30
        })
      };

      const mockNpmAudit = {
        isAvailable: async () => true,
        getVersion: async () => '10.2.4',
        scanWorkspace: async () => ({
          success: false,
          status: 'FAILED',
          scanner: 'npm-audit',
          findings: [],
          errors: ['npm audit registry connection refused (EAI_AGAIN)'],
          durationMs: 45
        })
      };

      const testOrch = new ScanOrchestrator();
      testOrch.semgrep = mockSemgrep;
      testOrch.npmAudit = mockNpmAudit;

      const scan = await testOrch.startScan({
        repositoryId: 'repo_npmaudit_fails',
        repositoryPath: testWorkspace,
        scanners: ['semgrep', 'npm-audit']
      });

      assert.strictEqual(scan.status, SCAN_STATES.PARTIAL);
      assert.strictEqual(scan.stage, SCAN_STATES.COMPLETED);
      assert.strictEqual(scan.summary.scannersRun.length, 1);
      assert.ok(scan.summary.scannersRun.includes('semgrep'));
      assert.strictEqual(scan.summary.scannersFailed.length, 1);
      assert.strictEqual(scan.summary.scannersFailed[0].scanner, 'npm-audit');
      assert.strictEqual(scan.summary.scannerOutcomes.semgrep.status, 'COMPLETED');
      assert.strictEqual(scan.summary.scannerOutcomes['npm-audit'].status, 'FAILED');

      // Findings from surviving Semgrep must NOT be discarded
      assert.strictEqual(scan.summary.totalFindings, 1);
      const findings = testOrch.getScanFindings(scan.id);
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].scanner, 'semgrep');
      assert.strictEqual(findings[0].ruleId, 'javascript.express.security.audit.sqli');

      // Event log check
      const events = testOrch.getScanEvents(scan.id);
      const failEvent = events.find(e => e.message.includes('npm-audit scanner reported error'));
      assert.ok(failEvent, 'Event log must capture npm-audit failure');
    });
  });

  // --------------------------------------------------------------------------
  // Scenario 4: Both Scanners Fail
  // --------------------------------------------------------------------------
  describe('4. Both Scanners Fail', () => {
    it('should return a structured failure result without crashing application', async () => {
      const mockSemgrep = {
        isAvailable: async () => true,
        scanWithSemgrep: async () => ({
          success: false,
          status: 'FAILED',
          findings: [],
          errors: ['Semgrep crashed with SIGSEGV'],
          durationMs: 15
        })
      };

      const mockNpmAudit = {
        isAvailable: async () => true,
        getVersion: async () => '10.2.4',
        scanWorkspace: async () => ({
          success: false,
          status: 'FAILED',
          scanner: 'npm-audit',
          findings: [],
          errors: ['npm binary exited with code 127'],
          durationMs: 10
        })
      };

      const testOrch = new ScanOrchestrator();
      testOrch.semgrep = mockSemgrep;
      testOrch.npmAudit = mockNpmAudit;

      const scan = await testOrch.startScan({
        repositoryId: 'repo_both_fail',
        repositoryPath: testWorkspace,
        scanners: ['semgrep', 'npm-audit']
      });

      assert.strictEqual(scan.status, SCAN_STATES.FAILED);
      assert.strictEqual(scan.stage, SCAN_STATES.FAILED);
      assert.strictEqual(scan.errorCode, 'SCANNER_FAILURE');
      assert.strictEqual(scan.summary.totalFindings, 0);
      assert.strictEqual(scan.summary.scannersRun.length, 0);
      assert.strictEqual(scan.summary.scannersFailed.length, 2);

      assert.strictEqual(scan.summary.scannerOutcomes.semgrep.status, 'FAILED');
      assert.strictEqual(scan.summary.scannerOutcomes['npm-audit'].status, 'FAILED');

      const events = testOrch.getScanEvents(scan.id);
      const finalEvent = events[events.length - 1];
      assert.strictEqual(finalEvent.stage, SCAN_STATES.FAILED);
    });
  });

  // --------------------------------------------------------------------------
  // Scenario 5: One Scanner Times Out
  // --------------------------------------------------------------------------
  describe('5. One Scanner Times Out', () => {
    it('should handle timeout cleanly, mark scan as PARTIAL, and preserve surviving scanner findings', async () => {
      const mockSemgrep = {
        isAvailable: async () => true,
        scanWithSemgrep: async () => ({
          success: true,
          status: 'COMPLETED',
          findings: [sampleSemgrepFinding],
          errors: [],
          provenance: { version: '1.45.0' },
          durationMs: 20
        })
      };

      const mockNpmAudit = {
        isAvailable: async () => true,
        getVersion: async () => '10.2.4',
        scanWorkspace: async () => ({
          success: false,
          status: 'FAILED',
          scanner: 'npm-audit',
          findings: [],
          advisories: [],
          errors: ['Dependency audit timed out after 120s'],
          durationMs: 120000,
          timedOut: true
        })
      };

      const testOrch = new ScanOrchestrator();
      testOrch.semgrep = mockSemgrep;
      testOrch.npmAudit = mockNpmAudit;

      const scan = await testOrch.startScan({
        repositoryId: 'repo_timeout_test',
        repositoryPath: testWorkspace,
        scanners: ['semgrep', 'npm-audit']
      });

      assert.strictEqual(scan.status, SCAN_STATES.PARTIAL);
      assert.strictEqual(scan.summary.scannersRun.length, 1);
      assert.ok(scan.summary.scannersRun.includes('semgrep'));
      assert.strictEqual(scan.summary.scannersFailed.length, 1);
      assert.strictEqual(scan.summary.scannersFailed[0].scanner, 'npm-audit');
      assert.ok(scan.summary.scannersFailed[0].error.includes('timed out'));

      assert.strictEqual(scan.summary.totalFindings, 1);
      const findings = testOrch.getScanFindings(scan.id);
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].scanner, 'semgrep');
    });
  });

  // --------------------------------------------------------------------------
  // Scenario 6: Findings From Successful Scanner Are Never Discarded
  // --------------------------------------------------------------------------
  describe('6. Findings Preservation Invariant', () => {
    it('should never discard findings even when scanner throws an unhandled rejection', async () => {
      const mockSemgrep = {
        isAvailable: async () => true,
        scanWithSemgrep: async () => {
          throw new Error('Unexpected fatal native segmentation fault in Semgrep CLI');
        }
      };

      const mockNpmAudit = {
        isAvailable: async () => true,
        getVersion: async () => '10.2.4',
        scanWorkspace: async () => ({
          success: true,
          status: 'COMPLETED',
          scanner: 'npm-audit',
          findings: [sampleNpmFinding],
          errors: [],
          durationMs: 25
        })
      };

      const testOrch = new ScanOrchestrator();
      testOrch.semgrep = mockSemgrep;
      testOrch.npmAudit = mockNpmAudit;

      const scan = await testOrch.startScan({
        repositoryId: 'repo_preservation_test',
        repositoryPath: testWorkspace,
        scanners: ['semgrep', 'npm-audit']
      });

      assert.strictEqual(scan.status, SCAN_STATES.PARTIAL);
      assert.strictEqual(scan.summary.totalFindings, 1);
      const findings = testOrch.getScanFindings(scan.id);
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].scanner, 'npm-audit');
    });
  });

  // --------------------------------------------------------------------------
  // Scenario 7: Empty Successful Results Are Not Treated As Failures
  // --------------------------------------------------------------------------
  describe('7. Empty Successful Results Not Treated As Failures', () => {
    it('should mark scan as COMPLETED when both scanners run successfully with 0 findings', async () => {
      const mockSemgrep = {
        isAvailable: async () => true,
        scanWithSemgrep: async () => ({
          success: true,
          status: 'COMPLETED',
          findings: [],
          errors: [],
          provenance: { version: '1.45.0' },
          durationMs: 15
        })
      };

      const mockNpmAudit = {
        isAvailable: async () => true,
        getVersion: async () => '10.2.4',
        scanWorkspace: async () => ({
          success: true,
          status: 'COMPLETED',
          scanner: 'npm-audit',
          findings: [],
          errors: [],
          durationMs: 20
        })
      };

      const testOrch = new ScanOrchestrator();
      testOrch.semgrep = mockSemgrep;
      testOrch.npmAudit = mockNpmAudit;

      const scan = await testOrch.startScan({
        repositoryId: 'repo_empty_clean',
        repositoryPath: testWorkspace,
        scanners: ['semgrep', 'npm-audit']
      });

      assert.strictEqual(scan.status, SCAN_STATES.COMPLETED);
      assert.strictEqual(scan.summary.totalFindings, 0);
      assert.strictEqual(scan.summary.scannersRun.length, 2);
      assert.strictEqual(scan.summary.scannersFailed.length, 0);
    });

    it('should mark scan as PARTIAL when one scanner succeeds with 0 findings and another fails', async () => {
      const mockSemgrep = {
        isAvailable: async () => true,
        scanWithSemgrep: async () => ({
          success: true,
          status: 'COMPLETED',
          findings: [],
          errors: [],
          provenance: { version: '1.45.0' },
          durationMs: 15
        })
      };

      const mockNpmAudit = {
        isAvailable: async () => true,
        getVersion: async () => '10.2.4',
        scanWorkspace: async () => ({
          success: false,
          status: 'FAILED',
          scanner: 'npm-audit',
          findings: [],
          errors: ['Lockfile parsing failed'],
          durationMs: 10
        })
      };

      const testOrch = new ScanOrchestrator();
      testOrch.semgrep = mockSemgrep;
      testOrch.npmAudit = mockNpmAudit;

      const scan = await testOrch.startScan({
        repositoryId: 'repo_empty_partial',
        repositoryPath: testWorkspace,
        scanners: ['semgrep', 'npm-audit']
      });

      assert.strictEqual(scan.status, SCAN_STATES.PARTIAL);
      assert.strictEqual(scan.summary.totalFindings, 0);
      assert.strictEqual(scan.summary.scannersRun.length, 1);
      assert.ok(scan.summary.scannersRun.includes('semgrep'));
      assert.strictEqual(scan.summary.scannersFailed.length, 1);
      assert.strictEqual(scan.summary.scannersFailed[0].scanner, 'npm-audit');
    });
  });

  // --------------------------------------------------------------------------
  // Scenario 8: Error Sanitization
  // --------------------------------------------------------------------------
  describe('8. Scanner Error Sanitization', () => {
    it('should sanitize stack traces, credentials, and host paths from error outputs', () => {
      const stackErr = 'Error: Spawn failed\n    at ChildProcess.spawn (/Users/anand/project/node_modules/exec.js:10:5)\n    at Object.run';
      const sanitizedStack = sanitizeErrorMessage(stackErr);
      assert.strictEqual(sanitizedStack, 'Error: Spawn failed');

      const awsErr = 'Fatal error: AccessDenied for AKIAIOSFODNN7EXAMPLE credentials';
      const sanitizedAws = sanitizeErrorMessage(awsErr);
      assert.ok(!sanitizedAws.includes('AKIAIOSFODNN7EXAMPLE'));
      assert.ok(sanitizedAws.includes('[REDACTED_AWS_KEY]'));

      const tokenErr = 'Authentication failure with token=ghp_abcdefghijklmnopqrstuvwxyz1234567890';
      const sanitizedToken = sanitizeErrorMessage(tokenErr);
      assert.ok(!sanitizedToken.includes('ghp_'));
      assert.ok(sanitizedToken.includes('[REDACTED_TOKEN]'));

      const secretErr = 'Database connection failed: password=mySuperSecretPass123';
      const sanitizedSecret = sanitizeErrorMessage(secretErr);
      assert.ok(!sanitizedSecret.includes('mySuperSecretPass123'));
      assert.ok(sanitizedSecret.includes('[REDACTED_SECRET]'));

      const pathErr = 'File not found at /Users/developer/secret-repo/package.json';
      const sanitizedPath = sanitizeErrorMessage(pathErr);
      assert.ok(!sanitizedPath.includes('/Users/developer/'));
      assert.ok(sanitizedPath.includes('~/secret-repo/package.json'));
    });
  });
});
