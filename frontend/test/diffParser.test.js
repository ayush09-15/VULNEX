/**
 * VULNEX Syntax-Aware Patch Diff Parser Unit Tests
 * Verifies Commit 33 gate: Rationale, additions/deletions, files and validation.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeDiffPath,
  isSafeFilePath,
  parseHunkHeader,
  parseUnifiedDiff,
  validateDiffScope
} from '../src/utils/diffParser.js';

describe('Syntax-Aware Diff Parser & Validator (Commit 33)', () => {
  const sampleDiff = `--- a/src/controllers/user.controller.js
+++ b/src/controllers/user.controller.js
@@ -42,5 +42,5 @@ async function getUser(req, res) {
   const { id } = req.params;
-  const query = \`SELECT * FROM users WHERE id = '\${id}'\`;
-  const result = await db.query(query);
+  const query = 'SELECT * FROM users WHERE id = $1';
+  const result = await db.query(query, [id]);
   return res.json(result.rows[0]);
 }`;

  it('1. correctly parses unified diff into files, hunks, and line tokens', () => {
    const result = parseUnifiedDiff(sampleDiff);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.files.length, 1);
    assert.strictEqual(result.files[0].oldFile, 'src/controllers/user.controller.js');
    assert.strictEqual(result.files[0].newFile, 'src/controllers/user.controller.js');
    assert.strictEqual(result.hunks.length, 1);

    const hunk = result.hunks[0];
    assert.strictEqual(hunk.oldStart, 42);
    assert.strictEqual(hunk.oldLines, 5);
    assert.strictEqual(hunk.newStart, 42);
    assert.strictEqual(hunk.newLines, 5);
    assert.strictEqual(hunk.section, 'async function getUser(req, res) {');

    // Lines check
    const adds = hunk.lines.filter(l => l.type === 'add');
    const dels = hunk.lines.filter(l => l.type === 'delete');
    const ctx = hunk.lines.filter(l => l.type === 'context');

    assert.strictEqual(adds.length, 2);
    assert.strictEqual(dels.length, 2);
    assert.ok(ctx.length >= 2);
  });

  it('2. calculates addition and deletion statistics accurately', () => {
    const result = parseUnifiedDiff(sampleDiff);
    assert.strictEqual(result.stats.additions, 2);
    assert.strictEqual(result.stats.deletions, 2);
    assert.strictEqual(result.stats.totalChanges, 4);
    assert.strictEqual(result.stats.filesCount, 1);
  });

  it('3. generates correct dual line numbers for added, deleted, and context lines', () => {
    const result = parseUnifiedDiff(sampleDiff);
    const hunk = result.hunks[0];

    // Context line before edits
    const firstContext = hunk.lines.find(l => l.type === 'context');
    assert.strictEqual(firstContext.oldLineNumber, 42);
    assert.strictEqual(firstContext.newLineNumber, 42);

    // Deletion line
    const firstDelete = hunk.lines.find(l => l.type === 'delete');
    assert.strictEqual(firstDelete.oldLineNumber, 43);
    assert.strictEqual(firstDelete.newLineNumber, null);

    // Addition line
    const firstAdd = hunk.lines.find(l => l.type === 'add');
    assert.strictEqual(firstAdd.oldLineNumber, null);
    assert.strictEqual(firstAdd.newLineNumber, 43);
  });

  it('4. detects path traversal attempts in diff headers', () => {
    const maliciousDiff = `--- a/../../../etc/passwd
+++ b/../../../etc/passwd
@@ -1,2 +1,2 @@
-root:x:0:0:root:/root:/bin/bash
+root:x:0:0:root:/root:/bin/sh`;

    const result = parseUnifiedDiff(maliciousDiff);
    assert.strictEqual(result.valid, false);
    assert.match(result.error, /unsafe file path/i);
  });

  it('5. detects absolute file paths in diff headers', () => {
    const absoluteDiff = `--- /etc/shadow
+++ /etc/shadow
@@ -1,2 +1,2 @@
-admin:hash
+admin:newhash`;

    const result = parseUnifiedDiff(absoluteDiff);
    assert.strictEqual(result.valid, false);
    assert.match(result.error, /unsafe file path/i);
  });

  it('6. rejects malformed diffs without hunk markers', () => {
    const noHunkDiff = `--- a/src/app.js
+++ b/src/app.js
console.log('no hunk here');`;

    const result = parseUnifiedDiff(noHunkDiff);
    assert.strictEqual(result.valid, false);
    assert.match(result.error, /no hunks/i);
  });

  it('7. rejects empty or non-string diff inputs', () => {
    assert.strictEqual(parseUnifiedDiff('').valid, false);
    assert.strictEqual(parseUnifiedDiff('   \n\n  ').valid, false);
    assert.strictEqual(parseUnifiedDiff(null).valid, false);
    assert.strictEqual(parseUnifiedDiff(undefined).valid, false);
  });

  it('8. validates diff scope against target finding file', () => {
    const validScope = validateDiffScope(sampleDiff, 'src/controllers/user.controller.js');
    assert.strictEqual(validScope.valid, true);

    const invalidScope = validateDiffScope(sampleDiff, 'src/models/user.js');
    assert.strictEqual(invalidScope.valid, false);
    assert.match(invalidScope.error, /out-of-scope/i);
  });

  it('9. parses hunk header attributes accurately', () => {
    const header = parseHunkHeader('@@ -10,15 +20,18 @@ function initDatabase()');
    assert.deepStrictEqual(header, {
      oldStart: 10,
      oldLines: 15,
      newStart: 20,
      newLines: 18,
      section: 'function initDatabase()',
      raw: '@@ -10,15 +20,18 @@ function initDatabase()'
    });
  });

  it('10. normalizes diff paths stripping prefixes cleanly', () => {
    assert.strictEqual(normalizeDiffPath('a/src/file.js'), 'src/file.js');
    assert.strictEqual(normalizeDiffPath('b/backend\\src\\file.js'), 'backend/src/file.js');
    assert.strictEqual(normalizeDiffPath('"a/src/file.js"'), 'src/file.js');
    assert.strictEqual(isSafeFilePath('src/app.js'), true);
    assert.strictEqual(isSafeFilePath('../app.js'), false);
    assert.strictEqual(isSafeFilePath('C:/app.js'), false);
  });
});
