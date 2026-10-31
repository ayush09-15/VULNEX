/**
 * VULNEX Explicit Patch Approval State & Application Gate Integration Tests
 *
 * Verifies Commit 34 acceptance gate:
 * - "No apply without explicit confirmation and valid state."
 * - Master Antigravity Execution Bible Section 8.7 & DATA_MODELS.md Section 2.5
 * - docs/API_CONTRACTS.md Section 2.4 (POST /api/patches/:id/apply, approve, reject)
 * - Invariant: Never applies patches to user's primary source directory or original repository
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const path = require('path');
const app = require('../src/app');
const patchService = require('../src/services/patch.service');
const scannerService = require('../src/services/scanner.service');

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
      'x-request-id': 'req_patch_approval_test',
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

describe('Explicit Patch Approval & Application Gate (Commit 34)', () => {
  beforeEach(() => {
    patchService.clearPatches();
  });

  const samplePatch = {
    id: 'patch_test_approval_001',
    findingId: 'find_sqli_001',
    diff: `--- a/src/routes/auth.js\n+++ b/src/routes/auth.js\n@@ -10,3 +10,3 @@\n-const query = "SELECT * FROM users WHERE id = '" + id + "'";\n+const query = "SELECT * FROM users WHERE id = $1";\n`,
    rationale: 'Replaces string concatenation with parameterized prepared statement query.',
    changedFiles: ['src/routes/auth.js'],
    reviewState: 'PENDING_REVIEW',
    status: 'GENERATED'
  };

  it('1. registers a patch proposal defaulting to PENDING_REVIEW state', async () => {
    patchService.savePatch(samplePatch);

    const res = await dispatch('GET', `/api/patches/${samplePatch.id}`);
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.id, samplePatch.id);
    assert.strictEqual(res.body.data.reviewState, 'PENDING_REVIEW');
    assert.strictEqual(res.body.data.status, 'GENERATED');
  });

  it('2. rejects patch apply with 403 APPROVAL_REQUIRED when approved is missing or false', async () => {
    patchService.savePatch(samplePatch);

    // Missing approved in body
    const resNoApproved = await dispatch('POST', `/api/patches/${samplePatch.id}/apply`, {
      body: {}
    });
    assert.strictEqual(resNoApproved.statusCode, 403);
    assert.strictEqual(resNoApproved.body.success, false);
    assert.strictEqual(resNoApproved.body.error.code, 'APPROVAL_REQUIRED');

    // Explicit false
    const resFalse = await dispatch('POST', `/api/patches/${samplePatch.id}/apply`, {
      body: { approved: false }
    });
    assert.strictEqual(resFalse.statusCode, 403);
    assert.strictEqual(resFalse.body.success, false);
    assert.strictEqual(resFalse.body.error.code, 'APPROVAL_REQUIRED');
  });

  it('3. rejects patch apply with 409 INVALID_STATE_TRANSITION when patch is in PENDING_REVIEW state', async () => {
    patchService.savePatch(samplePatch);

    // Even if client passes approved: true, unapproved state must be rejected
    const res = await dispatch('POST', `/api/patches/${samplePatch.id}/apply`, {
      body: { approved: true }
    });
    assert.strictEqual(res.statusCode, 409);
    assert.strictEqual(res.body.success, false);
    assert.strictEqual(res.body.error.code, 'INVALID_STATE_TRANSITION');
    assert.match(res.body.error.message, /APPROVED state prior to application/i);
  });

  it('4. explicitly approves a patch transitioning state to APPROVED and recording reviewer metadata', async () => {
    patchService.savePatch(samplePatch);

    const approveRes = await dispatch('POST', `/api/patches/${samplePatch.id}/approve`, {
      body: {
        reviewedBy: 'gaurav_sec_engineer',
        comments: 'Verified parameterized query syntax and CWE-89 remediation.'
      }
    });

    assert.strictEqual(approveRes.statusCode, 200);
    assert.strictEqual(approveRes.body.success, true);
    assert.strictEqual(approveRes.body.data.reviewState, 'APPROVED');
    assert.strictEqual(approveRes.body.data.reviewedBy, 'gaurav_sec_engineer');
    assert.strictEqual(approveRes.body.data.reviewComments, 'Verified parameterized query syntax and CWE-89 remediation.');
    assert.ok(approveRes.body.data.reviewedAt);

    // Verify persisted state via GET
    const getRes = await dispatch('GET', `/api/patches/${samplePatch.id}`);
    assert.strictEqual(getRes.body.data.reviewState, 'APPROVED');
  });

  it('5. explicitly rejects a patch transitioning state to REJECTED and recording reason', async () => {
    patchService.savePatch(samplePatch);

    const rejectRes = await dispatch('POST', `/api/patches/${samplePatch.id}/reject`, {
      body: {
        reviewedBy: 'gaurav_sec_engineer',
        reason: 'Change alters query signature unexpectedly.'
      }
    });

    assert.strictEqual(rejectRes.statusCode, 200);
    assert.strictEqual(rejectRes.body.success, true);
    assert.strictEqual(rejectRes.body.data.reviewState, 'REJECTED');
    assert.strictEqual(rejectRes.body.data.reviewComments, 'Change alters query signature unexpectedly.');

    // Attempting to apply a REJECTED patch must fail with 409
    const applyRes = await dispatch('POST', `/api/patches/${samplePatch.id}/apply`, {
      body: { approved: true }
    });
    assert.strictEqual(applyRes.statusCode, 409);
    assert.strictEqual(applyRes.body.error.code, 'INVALID_STATE_TRANSITION');
  });

  it('6. applies approved patch with approved: true into an isolated disposable workspace', async () => {
    patchService.savePatch(samplePatch);

    // 1. Approve
    await dispatch('POST', `/api/patches/${samplePatch.id}/approve`, {
      body: { reviewedBy: 'gaurav_sec_engineer', comments: 'Approved' }
    });

    // 2. Apply
    const applyRes = await dispatch('POST', `/api/patches/${samplePatch.id}/apply`, {
      body: { approved: true, approverComments: 'Proceed with disposable sandbox application' }
    });

    assert.strictEqual(applyRes.statusCode, 200);
    assert.strictEqual(applyRes.body.success, true);
    assert.strictEqual(applyRes.body.data.status, 'APPLIED_TO_TEMP');
    assert.ok(applyRes.body.data.appliedWorkspaceId.startsWith('ws_disposable_'));
    assert.ok(applyRes.body.data.appliedAt);

    // Verify workspace directory existence
    const wsPath = path.resolve(process.cwd(), '.workspaces', applyRes.body.data.appliedWorkspaceId);
    assert.strictEqual(fs.existsSync(wsPath), true);
    assert.strictEqual(fs.existsSync(path.join(wsPath, 'workspace.meta.json')), true);

    // Invariant: original repository file must NOT be altered
    // Check that primary repo path does not exist or was not modified
    assert.ok(!fs.existsSync(path.resolve(process.cwd(), 'src/routes/auth.js')));
  });

  it('7. returns 404 RESOURCE_NOT_FOUND when patch ID does not exist', async () => {
    const res = await dispatch('POST', '/api/patches/non_existent_patch_id/apply', {
      body: { approved: true }
    });
    assert.strictEqual(res.statusCode, 404);
    assert.strictEqual(res.body.error.code, 'RESOURCE_NOT_FOUND');
  });

  it('8. enforces approval gate on finding apply-patch endpoint', async () => {
    // Register finding
    const finding = {
      id: 'find_gate_test_01',
      title: 'SQL Injection in user route',
      severity: 'HIGH',
      status: 'TRIAGED',
      filePath: 'src/routes/user.js',
      proposedPatch: {
        patchedCode: 'const user = await db.query(query, [id]);'
      }
    };
    scannerService.addFinding(finding);

    // Attempt apply without approved: true
    const res = await dispatch('POST', `/api/findings/${finding.id}/apply-patch`, {
      body: { patchedCode: 'const x = 1;' }
    });
    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.error.code, 'APPROVAL_REQUIRED');
  });

  it('9. verifies patch in disposable workspace after application', async () => {
    patchService.savePatch(samplePatch);

    // Approve & Apply
    await dispatch('POST', `/api/patches/${samplePatch.id}/approve`, { body: {} });
    await dispatch('POST', `/api/patches/${samplePatch.id}/apply`, { body: { approved: true } });

    // Verify
    const verifyRes = await dispatch('POST', `/api/patches/${samplePatch.id}/verify`);
    assert.strictEqual(verifyRes.statusCode, 200);
    assert.strictEqual(verifyRes.body.success, true);
    assert.strictEqual(verifyRes.body.data.status, 'PASSED');
    assert.strictEqual(verifyRes.body.data.testResults.testsPassed, true);
  });
});
