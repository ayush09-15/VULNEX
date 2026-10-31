/**
 * VULNEX Commit 39 Verification Acceptance Gate Test Suite
 *
 * Feature: Compare before and after finding fingerprints
 * Acceptance Gate: Ambiguous matching becomes INCONCLUSIVE.
 * Master Antigravity Execution Bible Section 8.7 Step 13, Section 9.3 & Section 9.4
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const verificationService = require('../src/services/verification.service');
const patchService = require('../src/services/patch.service');
const scannerService = require('../src/services/scanner.service');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const { VerificationSchema } = require('../src/validators/canonical.schema');

describe('Commit 39: Before and After Finding Fingerprint Comparison', () => {
  let tempWorkspace;

  beforeEach(() => {
    tempWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex_fp_test_'));
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

  it('1. correctly identifies resolved finding when target fingerprint is absent after patch', () => {
    const targetFinding = {
      id: 'find_sqli_01',
      ruleId: 'VULN-001',
      filePath: 'src/routes/user.js',
      evidence: 'const q = `SELECT * FROM users WHERE id = ${id}`;',
      fingerprint: crypto.createHash('sha256').update('VULN-001:src/routes/user.js:const q = `SELECT * FROM users WHERE id = ${id}`;').digest('hex')
    };

    // Post-scan findings: clean, empty
    const postScanFindings = [];

    const result = verificationService.compareFindingFingerprints({
      targetFinding,
      postScanFindings,
      targetFilePath: 'src/routes/user.js'
    });

    assert.strictEqual(result.originalFindingResolved, true);
    assert.strictEqual(result.comparisonOutcome, 'RESOLVED');
    assert.strictEqual(result.isAmbiguous, false);
    assert.strictEqual(result.regressionDetected, false);
  });

  it('2. detects persistent vulnerability when fingerprint matches candidate post-patch', () => {
    const targetFinding = {
      id: 'find_sqli_02',
      ruleId: 'VULN-001',
      filePath: 'src/routes/user.js',
      evidence: 'const q = `SELECT * FROM users WHERE id = ${id}`;',
      fingerprint: crypto.createHash('sha256').update('VULN-001:src/routes/user.js:const q = `SELECT * FROM users WHERE id = ${id}`;').digest('hex')
    };

    // Post-scan findings contains the same flaw
    const postScanFindings = [
      {
        id: 'find_post_01',
        ruleId: 'VULN-001',
        filePath: 'src/routes/user.js',
        evidence: 'const q = `SELECT * FROM users WHERE id = ${id}`;',
        fingerprint: targetFinding.fingerprint
      }
    ];

    const result = verificationService.compareFindingFingerprints({
      targetFinding,
      postScanFindings,
      targetFilePath: 'src/routes/user.js'
    });

    assert.strictEqual(result.originalFindingResolved, false);
    assert.strictEqual(result.comparisonOutcome, 'STILL_DETECTED');
    assert.strictEqual(result.isAmbiguous, false);
    assert.strictEqual(result.matchedFingerprint, targetFinding.fingerprint);
  });

  it('3. acceptance gate: ambiguous matching transitions outcome to AMBIGUOUS and status to INCONCLUSIVE', async () => {
    const targetFile = 'src/routes/ambiguous.js';
    const fullPath = path.join(tempWorkspace, targetFile);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    // File with multiple SQLi patterns that cannot be uniquely matched to original single finding
    fs.writeFileSync(
      fullPath,
      'const q1 = db.query(`SELECT * FROM a WHERE id = ${id1}`);\nconst q2 = db.query(`SELECT * FROM b WHERE id = ${id2}`);\n',
      'utf8'
    );

    const targetFinding = {
      id: 'find_ambig_01',
      ruleId: 'VULN-001',
      filePath: targetFile,
      evidence: 'const q1 = db.query(`SELECT * FROM a WHERE id = ${id1}`);',
      fingerprint: 'non_matching_target_fingerprint_001'
    };
    scannerService.addFinding(targetFinding);
    scanOrchestrator.addFinding(targetFinding);

    const appliedPatch = patchService.savePatch({
      id: 'patch_ambig_001',
      findingId: targetFinding.id,
      diff: '--- a/src/routes/ambiguous.js\n+++ b/src/routes/ambiguous.js\n@@ -1,2 +1,2 @@\n-const q = 1;\n+const q = 2;\n',
      status: 'APPLIED_TO_TEMP',
      reviewState: 'APPROVED',
      disposableWorkspacePath: tempWorkspace,
      appliedWorkspaceId: path.basename(tempWorkspace),
      changedFiles: [targetFile]
    });

    const res = await verificationService.verifyPatch({
      patchId: appliedPatch.id,
      workspacePath: tempWorkspace
    });

    // Verify Commit 39 Acceptance Gate: Ambiguous matching becomes INCONCLUSIVE
    assert.strictEqual(res.status, 'INCONCLUSIVE');
    assert.strictEqual(res.isVerified, false);
    assert.strictEqual(res.verification.beforeAfterComparison.comparisonOutcome, 'AMBIGUOUS');

    // Patch & finding state machine must reflect INCONCLUSIVE
    const patchAfter = patchService.getPatchById(appliedPatch.id);
    assert.strictEqual(patchAfter.status, 'INCONCLUSIVE');

    const findingAfter = scanOrchestrator.getFindingById(targetFinding.id);
    assert.strictEqual(findingAfter.status, 'INCONCLUSIVE');

    // Validate verification record against canonical schema
    const schemaVal = VerificationSchema.safeParse(res.verification);
    assert.strictEqual(schemaVal.success, true);
  });

  it('4. detects regression when new defect of different rule is introduced', () => {
    const targetFinding = {
      id: 'find_sqli_03',
      ruleId: 'VULN-001',
      filePath: 'src/routes/user.js',
      fingerprint: 'fp_orig_01'
    };

    // Original SQLi is gone, but command injection (VULN-002) is introduced
    const postScanFindings = [
      {
        id: 'find_cmd_01',
        ruleId: 'VULN-002',
        filePath: 'src/routes/user.js',
        evidence: 'child_process.exec(`rm ${file}`);'
      }
    ];

    const result = verificationService.compareFindingFingerprints({
      targetFinding,
      postScanFindings,
      targetFilePath: 'src/routes/user.js'
    });

    assert.strictEqual(result.originalFindingResolved, true);
    assert.strictEqual(result.comparisonOutcome, 'REGRESSION_DETECTED');
    assert.strictEqual(result.regressionDetected, true);
    assert.strictEqual(result.newDefectFindings.length, 1);
  });
});
