/**
 * VULNEX Safe Patch Application Integration Tests (Commit 35)
 *
 * Implements Acceptance Gate for Commit 35:
 * - Master Antigravity Execution Bible Section 7.2 (Commit 35)
 * - Exact Commit: feat(patch): apply approved diff in disposable workspace
 * - Acceptance Gate: Original source/remote unchanged; rollback copy.
 * - Section 4.7 & 4.10: State machines (Patch APPLIED_TO_TEMP, Finding PATCH_APPLIED)
 * - Section 9.2: Explicit human approval gate (approved: true / confirm: true)
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');

const app = require('../src/app');
const patchService = require('../src/services/patch.service');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const scannerService = require('../src/services/scanner.service');

// In-memory HTTP dispatch helper (bypasses TCP socket binding in sandbox)
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
      'x-request-id': 'req_safe_patch_test',
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

describe('Commit 35: Safe Patch Application in Disposable Workspace', () => {
  let originalWorkspace;
  let originalFilePath;
  const originalFileContent = [
    'const express = require("express");',
    'const router = express.Router();',
    '',
    'router.get("/users", async (req, res) => {',
    '  const id = req.query.id;',
    '- const query = `SELECT * FROM users WHERE id = ${id}`;',
    '  const result = await db.query(query);',
    '  res.json(result);',
    '});',
    '',
    'module.exports = router;'
  ].join('\n');

  // Pristine target code without diff markers
  const pristineSourceCode = [
    'const express = require("express");',
    'const router = express.Router();',
    '',
    'router.get("/users", async (req, res) => {',
    '  const id = req.query.id;',
    '  const query = `SELECT * FROM users WHERE id = ${id}`;',
    '  const result = await db.query(query);',
    '  res.json(result);',
    '});',
    '',
    'module.exports = router;'
  ].join('\n');

  const validUnifiedDiff = [
    '--- a/src/routes/user.js',
    '+++ b/src/routes/user.js',
    '@@ -5,3 +5,3 @@',
    '   const id = req.query.id;',
    '-  const query = `SELECT * FROM users WHERE id = ${id}`;',
    '+  const query = "SELECT * FROM users WHERE id = $1";',
    '   const result = await db.query(query);'
  ].join('\n') + '\n';

  beforeEach(() => {
    patchService.clearStore();
    scanOrchestrator.clearStores();

    // Create a pristine mock original repository workspace
    originalWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex_orig_repo_'));
    const routesDir = path.join(originalWorkspace, 'src', 'routes');
    fs.mkdirSync(routesDir, { recursive: true });
    originalFilePath = path.join(routesDir, 'user.js');
    fs.writeFileSync(originalFilePath, pristineSourceCode, 'utf8');
  });

  afterEach(() => {
    try {
      fs.rmSync(originalWorkspace, { recursive: true, force: true });
    } catch (_) {}
  });

  // --------------------------------------------------------------------------
  // 1. Disposable Workspace Isolation & Original Repository Invariance
  // --------------------------------------------------------------------------
  describe('1. Disposable Workspace Isolation & Original Repository Invariance', () => {
    it('should apply patch ONLY in disposable workspace, leaving original source 100% untouched', async () => {
      const sampleFinding = {
        id: 'find_sqli_001',
        scanId: 'scan_001',
        workspacePath: originalWorkspace,
        filePath: 'src/routes/user.js',
        startLine: 6,
        endLine: 6,
        severity: 'CRITICAL',
        status: 'PATCH_PROPOSED'
      };
      scanOrchestrator.addFinding(sampleFinding);

      const savedPatch = patchService.savePatch({
        id: 'patch_test_001',
        findingId: 'find_sqli_001',
        diff: validUnifiedDiff,
        rationale: 'Use parameterized queries instead of string template interpolation.',
        changedFiles: ['src/routes/user.js'],
        status: 'VALIDATED'
      });

      // Apply patch to disposable workspace with explicit approval
      const result = await patchService.applyPatchToDisposableWorkspace({
        patchId: savedPatch.id,
        workspacePath: originalWorkspace,
        approved: true
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.status, 'APPLIED_TO_TEMP');
      assert.ok(result.appliedWorkspaceId);
      assert.ok(result.disposableWorkspacePath);
      assert.notStrictEqual(result.disposableWorkspacePath, originalWorkspace);

      // INVARIANT 1: Original repository source file must remain completely UNTOUCHED
      const origContentAfter = fs.readFileSync(originalFilePath, 'utf8');
      assert.strictEqual(origContentAfter, pristineSourceCode, 'Original source file MUST NOT be altered');

      // INVARIANT 2: Disposable workspace file MUST contain the patched code
      const patchedFilePath = path.join(result.disposableWorkspacePath, 'src', 'routes', 'user.js');
      assert.ok(fs.existsSync(patchedFilePath), 'Patched file must exist in disposable workspace');
      const patchedContent = fs.readFileSync(patchedFilePath, 'utf8');
      assert.ok(patchedContent.includes('const query = "SELECT * FROM users WHERE id = $1";'));
      assert.ok(!patchedContent.includes('${id}'));

      // INVARIANT 3: Rollback copy must exist inside the disposable workspace
      const backupFilePath = `${patchedFilePath}.vulnex.bak`;
      assert.ok(fs.existsSync(backupFilePath), 'Rollback backup file must exist in disposable workspace');
      assert.strictEqual(fs.readFileSync(backupFilePath, 'utf8'), pristineSourceCode);

      // State machine updates
      const updatedPatch = patchService.getPatchById(savedPatch.id);
      assert.strictEqual(updatedPatch.status, 'APPLIED_TO_TEMP');
      assert.strictEqual(updatedPatch.reviewState, 'APPROVED');

      const updatedFinding = scanOrchestrator.getFindingById('find_sqli_001');
      assert.strictEqual(updatedFinding.status, 'PATCH_APPLIED');
      assert.strictEqual(updatedFinding.appliedWorkspaceId, result.appliedWorkspaceId);
    });
  });

  // --------------------------------------------------------------------------
  // 2. Rollback Capability
  // --------------------------------------------------------------------------
  describe('2. Rollback Capability', () => {
    it('should restore target file from rollback copy and revert state machine', async () => {
      const sampleFinding = {
        id: 'find_sqli_002',
        scanId: 'scan_002',
        workspacePath: originalWorkspace,
        filePath: 'src/routes/user.js',
        status: 'PATCH_PROPOSED'
      };
      scanOrchestrator.addFinding(sampleFinding);

      const savedPatch = patchService.savePatch({
        id: 'patch_test_002',
        findingId: 'find_sqli_002',
        diff: validUnifiedDiff,
        rationale: 'Fix SQL injection.',
        changedFiles: ['src/routes/user.js']
      });

      const applyRes = await patchService.applyPatchToDisposableWorkspace({
        patchId: savedPatch.id,
        workspacePath: originalWorkspace,
        confirm: true
      });

      assert.strictEqual(applyRes.status, 'APPLIED_TO_TEMP');

      // Now rollback the patch
      const rollbackRes = await patchService.rollbackPatch(savedPatch.id);
      assert.strictEqual(rollbackRes.success, true);
      assert.strictEqual(rollbackRes.status, 'REVERTED');

      // Verify file in disposable workspace is reverted
      const disposableFilePath = path.join(applyRes.disposableWorkspacePath, 'src', 'routes', 'user.js');
      const revertedContent = fs.readFileSync(disposableFilePath, 'utf8');
      assert.strictEqual(revertedContent, pristineSourceCode);

      // Verify state machine rollback
      const patchAfter = patchService.getPatchById(savedPatch.id);
      assert.strictEqual(patchAfter.status, 'VALIDATED');

      const findingAfter = scanOrchestrator.getFindingById('find_sqli_002');
      assert.strictEqual(findingAfter.status, 'PATCH_PROPOSED');
    });
  });

  // --------------------------------------------------------------------------
  // 3. Human Approval Gate
  // --------------------------------------------------------------------------
  describe('3. Human Approval Gate', () => {
    it('should reject patch application if approved or confirm is not true', async () => {
      const savedPatch = patchService.savePatch({
        id: 'patch_test_unapproved',
        findingId: 'find_003',
        diff: validUnifiedDiff,
        changedFiles: ['src/routes/user.js']
      });

      await assert.rejects(
        () => patchService.applyPatchToDisposableWorkspace({
          patchId: savedPatch.id,
          workspacePath: originalWorkspace,
          approved: false
        }),
        (err) => {
          assert.strictEqual(err.code, 'CONFIRMATION_REQUIRED');
          return true;
        }
      );

      // Verify original source remains pristine
      assert.strictEqual(fs.readFileSync(originalFilePath, 'utf8'), pristineSourceCode);
    });
  });

  // --------------------------------------------------------------------------
  // 4. Hunk Context Mismatch Failure Handling
  // --------------------------------------------------------------------------
  describe('4. Hunk Context Mismatch Failure Handling', () => {
    it('should fail closed and clean up if hunk context does not match target file', async () => {
      const mismatchedDiff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -1,3 +1,3 @@',
        ' const nonExistentContextLine = true;',
        '-const query = `bad`;',
        '+const query = `good`;',
        ' const anotherNonExistentLine = false;'
      ].join('\n') + '\n';

      const savedPatch = patchService.savePatch({
        id: 'patch_test_mismatch',
        findingId: 'find_004',
        diff: mismatchedDiff,
        changedFiles: ['src/routes/user.js']
      });

      await assert.rejects(
        () => patchService.applyPatchToDisposableWorkspace({
          patchId: savedPatch.id,
          workspacePath: originalWorkspace,
          approved: true
        }),
        (err) => {
          assert.ok(err.message.includes('Context mismatch') || err.message.includes('Failed to apply'));
          return true;
        }
      );

      // Verify original source remains pristine
      assert.strictEqual(fs.readFileSync(originalFilePath, 'utf8'), pristineSourceCode);
    });
  });

  // --------------------------------------------------------------------------
  // 5. HTTP Routes: POST /api/patches/:id/apply & POST /api/patches/:id/rollback
  // --------------------------------------------------------------------------
  describe('5. HTTP Canonical Endpoints (/api/patches)', () => {
    it('should return 400 CONFIRMATION_REQUIRED when approval flag is missing in HTTP call', async () => {
      const savedPatch = patchService.savePatch({
        id: 'p_http_001',
        findingId: 'f_http_001',
        diff: validUnifiedDiff,
        changedFiles: ['src/routes/user.js']
      });

      const res = await dispatch('POST', `/api/patches/${savedPatch.id}/apply`, {
        body: {} // No approved or confirm flag
      });

      assert.strictEqual(res.statusCode, 400);
      assert.strictEqual(res.body.success, false);
      assert.strictEqual(res.body.error.code, 'CONFIRMATION_REQUIRED');
    });

    it('should successfully apply approved patch via POST /api/patches/:id/apply', async () => {
      const sampleFinding = {
        id: 'f_http_002',
        scanId: 's_http_002',
        workspacePath: originalWorkspace,
        filePath: 'src/routes/user.js',
        status: 'PATCH_PROPOSED'
      };
      scanOrchestrator.addFinding(sampleFinding);

      const savedPatch = patchService.savePatch({
        id: 'p_http_002',
        findingId: 'f_http_002',
        diff: validUnifiedDiff,
        changedFiles: ['src/routes/user.js']
      });

      const res = await dispatch('POST', `/api/patches/${savedPatch.id}/apply`, {
        body: { approved: true, workspacePath: originalWorkspace }
      });

      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.body.success, true);
      assert.strictEqual(res.body.data.status, 'APPLIED_TO_TEMP');
      assert.ok(res.body.data.appliedWorkspaceId);

      // Verify GET /api/patches/:id
      const getRes = await dispatch('GET', `/api/patches/${savedPatch.id}`);
      assert.strictEqual(getRes.statusCode, 200);
      assert.strictEqual(getRes.body.data.status, 'APPLIED_TO_TEMP');

      // Verify POST /api/patches/:id/rollback
      const rollRes = await dispatch('POST', `/api/patches/${savedPatch.id}/rollback`);
      assert.strictEqual(rollRes.statusCode, 200);
      assert.strictEqual(rollRes.body.data.status, 'REVERTED');
    });

    it('should return 404 PATCH_NOT_FOUND for non-existent patch ID', async () => {
      const res = await dispatch('POST', '/api/patches/nonexistent_patch_id/apply', {
        body: { approved: true }
      });

      assert.strictEqual(res.statusCode, 404);
      assert.strictEqual(res.body.error.code, 'PATCH_NOT_FOUND');
    });
  });
});
