/**
 * VULNEX Verification Gate & State Transition Tests
 *
 * Verifies Commit 37 Gate:
 * - "State transition and audit event tests"
 * - Master Antigravity Execution Bible Section 8.7 & Section 4.10
 * - Patch State Machine: GENERATED -> VALIDATED -> APPLIED_TO_TEMP -> TESTING -> VERIFIED / FAILED
 * - AuditEvent generation and immutability
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const app = require('../src/app');
const patchService = require('../src/services/patch.service');
const verificationService = require('../src/services/verification.service');
const scannerService = require('../src/services/scanner.service');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const { AuditEventSchema } = require('../src/validators/canonical.schema');

// In-memory HTTP dispatch helper
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
      'x-request-id': 'req_verification_gate_test',
      ...headers
    };
    req.body = body;
    req.query = { ...parsedQuery, ...query };

    const res = new http.ServerResponse(req);
    let rawBody = '';

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

    app.handle(req, res);
  });
}

describe('Verification Orchestration Gate & Audit Events (Commit 37)', () => {
  let tempWorkspace;

  beforeEach(() => {
    patchService.clearStore();
    verificationService.clearStore();
    tempWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex_gate_test_'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempWorkspace, { recursive: true, force: true });
    } catch (_) {}
  });

  it('1. rejects verification with 409 INVALID_STATE_TRANSITION when patch is in GENERATED state', async () => {
    const unappliedPatch = patchService.savePatch({
      id: 'patch_generated_001',
      findingId: 'find_sqli_gate_001',
      diff: '--- a/src/app.js\n+++ b/src/app.js\n@@ -1,1 +1,1 @@\n-const a=1;\n+const a=2;\n',
      status: 'GENERATED',
      reviewState: 'PENDING_REVIEW'
    });

    const res = await dispatch('POST', `/api/patches/${unappliedPatch.id}/verify`);
    assert.strictEqual(res.statusCode, 409);
    assert.strictEqual(res.body.success, false);
    assert.strictEqual(res.body.error.code, 'INVALID_STATE_TRANSITION');
    assert.match(res.body.error.message, /APPLIED_TO_TEMP/i);
  });

  it('2. rejects verification when patch is in VALIDATED or REJECTED state', async () => {
    const rejectedPatch = patchService.savePatch({
      id: 'patch_rejected_001',
      findingId: 'find_sqli_gate_002',
      diff: '--- a/src/app.js\n+++ b/src/app.js\n@@ -1,1 +1,1 @@\n-const a=1;\n+const a=2;\n',
      status: 'VALIDATED',
      reviewState: 'REJECTED'
    });

    const res = await dispatch('POST', `/api/patches/${rejectedPatch.id}/verify`);
    assert.strictEqual(res.statusCode, 409);
    assert.strictEqual(res.body.error.code, 'INVALID_STATE_TRANSITION');
  });

  it('3. transitions state to TESTING and then VERIFIED on successful verification', async () => {
    // Write sample patched file in temp workspace
    const routesDir = path.join(tempWorkspace, 'src', 'routes');
    fs.mkdirSync(routesDir, { recursive: true });
    fs.writeFileSync(path.join(routesDir, 'user.js'), 'const query = "SELECT * FROM users WHERE id = $1";\n', 'utf8');

    const finding = {
      id: 'find_gate_success_001',
      scanId: 'scan_gate_001',
      filePath: 'src/routes/user.js',
      ruleId: 'sql-injection-rule',
      status: 'PATCH_APPLIED'
    };
    scannerService.addFinding(finding);
    scanOrchestrator.addFinding(finding);

    const appliedPatch = patchService.savePatch({
      id: 'patch_applied_001',
      findingId: finding.id,
      diff: '--- a/src/routes/user.js\n+++ b/src/routes/user.js\n@@ -1,1 +1,1 @@\n-bad\n+good\n',
      status: 'APPLIED_TO_TEMP',
      reviewState: 'APPROVED',
      disposableWorkspacePath: tempWorkspace,
      appliedWorkspaceId: path.basename(tempWorkspace),
      changedFiles: ['src/routes/user.js']
    });

    const res = await dispatch('POST', `/api/patches/${appliedPatch.id}/verify`, {
      body: { options: { workspacePath: tempWorkspace } }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.status, 'PASSED');

    // Verify patch transitioned to VERIFIED
    const patchAfter = patchService.getPatchById(appliedPatch.id);
    assert.strictEqual(patchAfter.status, 'VERIFIED');
    assert.strictEqual(patchAfter.isVerified, true);

    // Verify finding transitioned to VERIFIED
    const findingAfter = scanOrchestrator.getFindingById(finding.id);
    assert.strictEqual(findingAfter.status, 'VERIFIED');
  });

  it('4. records immutable AuditEvents for verification start and completion', async () => {
    const finding = {
      id: 'find_audit_001',
      filePath: 'src/routes/user.js',
      ruleId: 'sample-rule',
      status: 'PATCH_APPLIED'
    };
    scannerService.addFinding(finding);
    scanOrchestrator.addFinding(finding);

    const appliedPatch = patchService.savePatch({
      id: 'patch_audit_001',
      findingId: finding.id,
      diff: '--- a/src/routes/user.js\n+++ b/src/routes/user.js\n@@ -1,1 +1,1 @@\n-bad\n+good\n',
      status: 'APPLIED_TO_TEMP',
      reviewState: 'APPROVED',
      disposableWorkspacePath: tempWorkspace,
      appliedWorkspaceId: path.basename(tempWorkspace),
      changedFiles: ['src/routes/user.js']
    });

    await dispatch('POST', `/api/patches/${appliedPatch.id}/verify`, {
      body: { options: { workspacePath: tempWorkspace } }
    });

    const events = verificationService.getAuditEvents(appliedPatch.id);
    assert.ok(events.length >= 2);

    const startEvent = events.find(e => e.action === 'PATCH_VERIFICATION_STARTED');
    const completeEvent = events.find(e => e.action === 'PATCH_VERIFICATION_COMPLETED');

    assert.ok(startEvent, 'Must record PATCH_VERIFICATION_STARTED audit event');
    assert.ok(completeEvent, 'Must record PATCH_VERIFICATION_COMPLETED audit event');

    assert.strictEqual(startEvent.entityId, appliedPatch.id);
    assert.strictEqual(completeEvent.entityId, appliedPatch.id);
    assert.strictEqual(completeEvent.outcome, 'SUCCESS');

    // Validate conformance to canonical AuditEventSchema
    const parseStart = AuditEventSchema.safeParse(startEvent);
    assert.strictEqual(parseStart.success, true);
    const parseComplete = AuditEventSchema.safeParse(completeEvent);
    assert.strictEqual(parseComplete.success, true);
  });

  it('5. transitions patch to FAILED when targeted tests fail', async () => {
    // Write failing test into temp workspace
    const testFile = path.join(tempWorkspace, 'failing.test.js');
    fs.writeFileSync(
      testFile,
      `const { test } = require('node:test');
const assert = require('node:assert/strict');
test('fails verification', () => {
  assert.strictEqual(1, 2);
});`,
      'utf8'
    );

    const appliedPatch = patchService.savePatch({
      id: 'patch_failing_test_001',
      findingId: 'find_fail_001',
      diff: '--- a/src/app.js\n+++ b/src/app.js\n@@ -1,1 +1,1 @@\n-old\n+new\n',
      status: 'APPLIED_TO_TEMP',
      reviewState: 'APPROVED',
      disposableWorkspacePath: tempWorkspace,
      appliedWorkspaceId: path.basename(tempWorkspace),
      changedFiles: ['src/app.js']
    });

    const res = await dispatch('POST', `/api/patches/${appliedPatch.id}/verify`, {
      body: {
        testFile: 'failing.test.js',
        command: 'node',
        options: { workspacePath: tempWorkspace }
      }
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.data.status, 'FAILED');
    assert.strictEqual(res.body.data.testResults.testsPassed, false);

    const patchAfter = patchService.getPatchById(appliedPatch.id);
    assert.strictEqual(patchAfter.status, 'FAILED');
    assert.strictEqual(patchAfter.isVerified, false);
  });
});
