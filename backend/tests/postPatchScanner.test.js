/**
 * VULNEX Commit 38 Verification Gate Test Suite
 *
 * Acceptance Gate: Tool version, command, exit code and output.
 * Invariant: Operates strictly within disposable workspaces, validating post-patch scanner execution.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const verificationService = require('../src/services/verification.service');
const patchService = require('../src/services/patch.service');
const scannerService = require('../src/services/scanner.service');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');

describe('Commit 38: Post-Patch Scanner Execution (Tool Version, Command, Exit Code, Output)', () => {
  let tempWorkspace;

  beforeEach(() => {
    tempWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex_scanner_test_'));
    patchService.clearStore();
    verificationService.clearStore();
    if (typeof scanOrchestrator.clearAll === 'function') {
      scanOrchestrator.clearAll();
    }
  });

  afterEach(() => {
    if (tempWorkspace && fs.existsSync(tempWorkspace)) {
      try {
        fs.rmSync(tempWorkspace, { recursive: true, force: true });
      } catch (_) {}
    }
  });

  it('1. captures tool version, command array, exit code and raw output on resolved vulnerability', async () => {
    const targetFile = 'src/routes/secureUser.js';
    const fullPath = path.join(tempWorkspace, targetFile);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    // Clean, secure code that uses parameterized query
    fs.writeFileSync(
      fullPath,
      'const query = "SELECT * FROM users WHERE id = $1";\nconst result = await db.query(query, [userId]);\n',
      'utf8'
    );

    const scanResult = await verificationService.runPostPatchScanner({
      workspacePath: tempWorkspace,
      filePath: targetFile,
      targetRuleId: 'VULN-001',
      tool: 'semgrep'
    });

    // Verify Commit 38 Acceptance Gate properties
    assert.strictEqual(typeof scanResult.tool, 'string');
    assert.strictEqual(scanResult.tool, 'semgrep');

    // Tool Version
    assert.strictEqual(typeof scanResult.toolVersion, 'string');
    assert.match(scanResult.toolVersion, /^\d+\.\d+\.\d+/);

    // Command array
    assert.ok(Array.isArray(scanResult.command));
    assert.strictEqual(scanResult.command[0], 'semgrep');
    assert.ok(scanResult.command.includes('scan'));
    assert.ok(scanResult.command.includes('--json'));
    assert.ok(scanResult.command.some(c => c.includes('secureUser.js')));

    // Exit code & Raw Output
    assert.strictEqual(scanResult.exitCode, 0);
    assert.strictEqual(typeof scanResult.rawOutput, 'string');
    assert.ok(scanResult.rawOutput.length > 0);

    const parsedOutput = JSON.parse(scanResult.rawOutput);
    assert.strictEqual(parsedOutput.scanner, 'semgrep');
    assert.strictEqual(parsedOutput.findingsCount, 0);

    // Findings evaluation
    assert.strictEqual(scanResult.originalFindingResolved, true);
    assert.strictEqual(scanResult.newFindingsCount, 0);
    assert.ok(scanResult.durationMs >= 0);
  });

  it('2. captures exitCode 1 and output when original vulnerability persists after patch', async () => {
    const targetFile = 'src/routes/vulnerableUser.js';
    const fullPath = path.join(tempWorkspace, targetFile);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    // Vulnerable code still using string concatenation (VULN-001)
    fs.writeFileSync(
      fullPath,
      'const query = "SELECT * FROM users WHERE id = " + userId;\nconst result = await db.query(query);\n',
      'utf8'
    );

    const scanResult = await verificationService.runPostPatchScanner({
      workspacePath: tempWorkspace,
      filePath: targetFile,
      targetRuleId: 'VULN-001'
    });

    // Gate: Tool version, command, exit code and output
    assert.match(scanResult.toolVersion, /^\d+\.\d+\.\d+/);
    assert.ok(Array.isArray(scanResult.command));
    assert.strictEqual(scanResult.exitCode, 1);
    assert.strictEqual(scanResult.originalFindingResolved, false);

    const parsedOutput = JSON.parse(scanResult.rawOutput);
    assert.ok(parsedOutput.findingsCount >= 1);
    assert.ok(parsedOutput.findings.some(f => f.ruleId === 'VULN-001'));
  });

  it('3. detects regression when patch fixes original issue but introduces a new vulnerability', async () => {
    const targetFile = 'src/routes/regressionUser.js';
    const fullPath = path.join(tempWorkspace, targetFile);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    // Patch fixed SQL injection (VULN-001), but introduced command injection (VULN-002)
    fs.writeFileSync(
      fullPath,
      '// SQL fix applied:\nconst query = "SELECT * FROM users WHERE id = $1";\n// But introduces command injection:\neval("console.log(" + userInput + ")");\n',
      'utf8'
    );

    const scanResult = await verificationService.runPostPatchScanner({
      workspacePath: tempWorkspace,
      filePath: targetFile,
      targetRuleId: 'VULN-001'
    });

    // Original vulnerability resolved, but regression detected!
    assert.strictEqual(scanResult.originalFindingResolved, true);
    assert.strictEqual(scanResult.newFindingsCount, 1);
    assert.strictEqual(scanResult.exitCode, 1);
    assert.strictEqual(scanResult.newFindings[0].ruleId, 'VULN-002');

    const parsedOutput = JSON.parse(scanResult.rawOutput);
    assert.strictEqual(parsedOutput.findingsCount, 1);
    assert.strictEqual(parsedOutput.findings[0].ruleId, 'VULN-002');
  });

  it('4. end-to-end verification gates on post-patch scanner and fails on regression', async () => {
    const targetFile = 'src/routes/api.js';
    const fullPath = path.join(tempWorkspace, targetFile);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    // Target file contains regression: fixes SQL, introduces command injection
    fs.writeFileSync(
      fullPath,
      'const safe = "SELECT * FROM users WHERE id = $1";\neval("dangerous(" + code + ")");\n',
      'utf8'
    );

    const finding = {
      id: 'find_regr_001',
      filePath: targetFile,
      ruleId: 'VULN-001',
      status: 'PATCH_APPLIED'
    };
    scanOrchestrator.addFinding(finding);
    scannerService.addFinding(finding);

    const patch = patchService.savePatch({
      id: 'patch_regr_001',
      findingId: finding.id,
      diff: '--- a/src/routes/api.js\n+++ b/src/routes/api.js\n@@ -1,1 +1,1 @@\n-bad\n+safe\n',
      status: 'APPLIED_TO_TEMP',
      reviewState: 'APPROVED',
      disposableWorkspacePath: tempWorkspace,
      changedFiles: [targetFile]
    });

    const result = await verificationService.verifyPatch({
      patchId: patch.id,
      workspacePath: tempWorkspace
    });

    // Verification must fail due to regression
    assert.strictEqual(result.isVerified, false);
    assert.strictEqual(result.verification.status, 'FAILED');
    assert.strictEqual(result.verification.beforeAfterComparison.regressionDetected, true);
    assert.strictEqual(result.verification.beforeAfterComparison.comparisonOutcome, 'REGRESSION_DETECTED');

    // Tool version, command, exit code, and raw output captured in verification record
    assert.strictEqual(result.verification.scannerResults.tool, 'semgrep');
    assert.match(result.verification.scannerResults.toolVersion, /^\d+\.\d+\.\d+/);
    assert.ok(Array.isArray(result.verification.scannerResults.command));
    assert.strictEqual(result.verification.scannerResults.exitCode, 1);
    assert.ok(result.verification.scannerResults.rawOutput.length > 0);

    // Patch state machine must reflect FAILED
    const patchAfter = patchService.getPatchById(patch.id);
    assert.strictEqual(patchAfter.status, 'FAILED');
    assert.strictEqual(patchAfter.isVerified, false);
  });

  it('5. end-to-end verification succeeds and marks patch VERIFIED when scanner passes cleanly', async () => {
    const targetFile = 'src/routes/clean.js';
    const fullPath = path.join(tempWorkspace, targetFile);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    // Completely safe code
    fs.writeFileSync(
      fullPath,
      'const query = "SELECT * FROM users WHERE id = $1";\nreturn query;\n',
      'utf8'
    );

    const finding = {
      id: 'find_clean_001',
      filePath: targetFile,
      ruleId: 'VULN-001',
      status: 'PATCH_APPLIED'
    };
    scanOrchestrator.addFinding(finding);
    scannerService.addFinding(finding);

    const patch = patchService.savePatch({
      id: 'patch_clean_001',
      findingId: finding.id,
      diff: '--- a/src/routes/clean.js\n+++ b/src/routes/clean.js\n@@ -1,1 +1,1 @@\n-bad\n+good\n',
      status: 'APPLIED_TO_TEMP',
      reviewState: 'APPROVED',
      disposableWorkspacePath: tempWorkspace,
      changedFiles: [targetFile]
    });

    const result = await verificationService.verifyPatch({
      patchId: patch.id,
      workspacePath: tempWorkspace
    });

    assert.strictEqual(result.isVerified, true);
    assert.strictEqual(result.verification.status, 'PASSED');
    assert.strictEqual(result.verification.beforeAfterComparison.regressionDetected, false);
    assert.strictEqual(result.verification.beforeAfterComparison.comparisonOutcome, 'RESOLVED');

    // Verify all Gate fields
    const { scannerResults } = result.verification;
    assert.strictEqual(scannerResults.tool, 'semgrep');
    assert.match(scannerResults.toolVersion, /^\d+\.\d+\.\d+/);
    assert.ok(Array.isArray(scannerResults.command));
    assert.strictEqual(scannerResults.exitCode, 0);
    assert.ok(scannerResults.rawOutput.includes('"findingsCount": 0'));
    assert.strictEqual(scannerResults.originalFindingResolved, true);
    assert.strictEqual(scannerResults.newFindingsCount, 0);

    const patchAfter = patchService.getPatchById(patch.id);
    assert.strictEqual(patchAfter.status, 'VERIFIED');
    assert.strictEqual(patchAfter.isVerified, true);
  });
});
