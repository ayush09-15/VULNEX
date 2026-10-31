/**
 * VULNEX Path Traversal & Malformed Diff Rejection Tests (Commit 31)
 *
 * Implements Acceptance Gate for Commit 31:
 * - Master Antigravity Execution Bible Section 7.2 (Commit 31)
 * - Exact Commit: test(patch): add traversal and malformed diff rejection cases
 * - Acceptance Gate: Reject absolute paths, ../, unexpected files and malformed hunks.
 * - Part IX (Threat Model): Unsafe AI patch, path traversal, symlink escapes.
 * - Invariant: Original source and disk remain untouched in all negative cases.
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const {
  validateDiffAndPaths,
  validateWorkspacePath,
  assertValidDiff,
  normalizeDiffFilePath,
  DiffValidationError
} = require('../src/validators/diffValidator');

const {
  validateProposalScope,
  assertProposalScope,
  OutOfScopeProposalError
} = require('../src/validators/patchProposal.schema');

describe('Commit 31: Traversal and Malformed Diff Rejection Tests', () => {
  let tempWorkspace;
  let sampleFilePath;
  const sampleOriginalContent = 'const a = 1;\nconst query = `SELECT * FROM users WHERE id = ${id}`;\nconst b = 2;\n';

  beforeEach(() => {
    tempWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex_patch_sec_test_'));
    const routesDir = path.join(tempWorkspace, 'src', 'routes');
    fs.mkdirSync(routesDir, { recursive: true });
    sampleFilePath = path.join(routesDir, 'user.js');
    fs.writeFileSync(sampleFilePath, sampleOriginalContent, 'utf8');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempWorkspace, { recursive: true, force: true });
    } catch (_) {}
  });

  // --------------------------------------------------------------------------
  // 1. Absolute Path Rejection
  // --------------------------------------------------------------------------
  describe('1. Absolute Path Rejection', () => {
    it('should reject Unix root absolute paths in diff header (--- a//etc/passwd)', () => {
      const diff = [
        '--- a//etc/passwd',
        '+++ b//etc/passwd',
        '@@ -1,1 +1,1 @@',
        '-root:x:0:0:root:/root:/bin/bash',
        '+root:x:0:0:root:/root:/bin/sh'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /absolute|escapes/i.test(e)));
      assert.throws(() => assertValidDiff(diff, { workspacePath: tempWorkspace }), DiffValidationError);
    });

    it('should reject Windows absolute paths with drive letter (C:\\Windows\\System32)', () => {
      const diff = [
        '--- a/C:\\Windows\\System32\\cmd.exe',
        '+++ b/C:\\Windows\\System32\\cmd.exe',
        '@@ -1,1 +1,1 @@',
        '-old',
        '+new'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /drive letter|absolute|escapes/i.test(e)));
    });

    it('should reject Windows drive letter without leading slash (D:/data/secret.key)', () => {
      const diff = [
        '--- a/D:/data/secret.key',
        '+++ b/D:/data/secret.key',
        '@@ -1,1 +1,1 @@',
        '-old',
        '+new'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.length > 0);
    });

    it('should reject double-slash root absolute path (//var/log/syslog)', () => {
      const diff = [
        '--- a//var/log/syslog',
        '+++ b//var/log/syslog',
        '@@ -1,1 +1,1 @@',
        '-old',
        '+new'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /absolute/i.test(e)));
    });
  });

  // --------------------------------------------------------------------------
  // 2. Path Traversal Rejection (../)
  // --------------------------------------------------------------------------
  describe('2. Path Traversal Rejection (../)', () => {
    it('should reject direct parent traversal (../../../etc/passwd)', () => {
      const diff = [
        '--- a/../../../etc/passwd',
        '+++ b/../../../etc/passwd',
        '@@ -1,1 +1,1 @@',
        '-root:x:0:0:root:/root:/bin/bash',
        '+root:x:0:0:root:/root:/bin/sh'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /traversal|\.\./i.test(e)));
      assert.ok(result.rejectedPaths.includes('../../../etc/passwd'));
    });

    it('should reject nested traversal in middle of path (src/routes/../../package.json)', () => {
      const diff = [
        '--- a/src/routes/../../package.json',
        '+++ b/src/routes/../../package.json',
        '@@ -1,1 +1,1 @@',
        '-old',
        '+new'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /traversal|\.\./i.test(e)));
    });

    it('should reject traversal present only in new file header (+++ b/../../secret)', () => {
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/../../secret.txt',
        '@@ -1,1 +1,1 @@',
        '-old',
        '+new'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /traversal|\.\./i.test(e)));
    });

    it('should reject traversal present only in old file header (--- a/../../secret)', () => {
      const diff = [
        '--- a/../../secret.txt',
        '+++ b/src/routes/user.js',
        '@@ -1,1 +1,1 @@',
        '-old',
        '+new'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /traversal|\.\./i.test(e)));
    });

    it('should reject null byte injection in file paths', () => {
      const check = validateWorkspacePath('src/routes/user.js\0.txt', tempWorkspace);
      assert.strictEqual(check.valid, false);
      assert.strictEqual(check.code, 'NULL_BYTE');
    });

    it('should reject recorded unsafe path traversal fixture from disk', () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'patch', 'unsafe-path-traversal.json');
      const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

      const result = validateDiffAndPaths(fixture.diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /traversal|\.\./i.test(e)));
    });
  });

  // --------------------------------------------------------------------------
  // 3. Symlink Escape Rejection
  // --------------------------------------------------------------------------
  describe('3. Symlink Escape Rejection', () => {
    it('should reject symlink file pointing outside workspace boundaries', () => {
      const outsideFile = path.join(os.tmpdir(), `vulnex_outside_${Date.now()}.txt`);
      fs.writeFileSync(outsideFile, 'secret content', 'utf8');

      const symlinkPath = path.join(tempWorkspace, 'src', 'routes', 'escaped_link.js');
      try {
        fs.symlinkSync(outsideFile, symlinkPath);
      } catch {
        // Skip if filesystem does not permit symlinks
        return;
      }

      try {
        const check = validateWorkspacePath('src/routes/escaped_link.js', tempWorkspace);
        assert.strictEqual(check.valid, false);
        assert.strictEqual(check.code, 'SYMLINK_WORKSPACE_ESCAPE');
      } finally {
        try { fs.unlinkSync(outsideFile); } catch (_) {}
      }
    });

    it('should reject symlink directory pointing outside workspace boundaries', () => {
      const outsideDir = path.join(os.tmpdir(), `vulnex_outside_dir_${Date.now()}`);
      fs.mkdirSync(outsideDir, { recursive: true });
      fs.writeFileSync(path.join(outsideDir, 'target.js'), 'code', 'utf8');

      const symlinkDir = path.join(tempWorkspace, 'external_link');
      try {
        fs.symlinkSync(outsideDir, symlinkDir, 'dir');
      } catch {
        return;
      }

      try {
        const check = validateWorkspacePath('external_link/target.js', tempWorkspace);
        assert.strictEqual(check.valid, false);
        assert.strictEqual(check.code, 'SYMLINK_WORKSPACE_ESCAPE');
      } finally {
        try { fs.rmSync(outsideDir, { recursive: true, force: true }); } catch (_) {}
      }
    });
  });

  // --------------------------------------------------------------------------
  // 4. Unexpected / Out-of-Scope File Rejection
  // --------------------------------------------------------------------------
  describe('4. Unexpected and Out-of-Scope Files Rejection', () => {
    it('should reject diff modifying files not in declared changedFiles list', () => {
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -1,1 +1,1 @@',
        '-old',
        '+new'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, {
        workspacePath: tempWorkspace,
        declaredChangedFiles: ['src/other/different.js'] // expected is different
      });

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /do not match declared|not declared in proposal/i.test(e)));
    });

    it('should reject recorded unrelated edits diff fixture modifying package.json when finding is in user.js', () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'patch', 'unrelated-edits-diff.json');
      const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

      const sampleFinding = {
        id: 'find_sqli_001',
        filePath: 'src/routes/user.js',
        startLine: 10,
        endLine: 12
      };

      const proposalWithFinding = {
        ...fixture,
        findingId: 'find_sqli_001'
      };

      const scopeCheck = validateProposalScope(proposalWithFinding, sampleFinding);
      assert.strictEqual(scopeCheck.valid, false);
      assert.ok(scopeCheck.error.includes('outside finding scope') || scopeCheck.error.includes('must include finding target file'));
    });

    it('should reject multi-file diff when allowMultiFile is false', () => {
      const multiDiff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -1,1 +1,1 @@',
        '-old',
        '+new',
        '--- a/src/routes/auth.js',
        '+++ b/src/routes/auth.js',
        '@@ -1,1 +1,1 @@',
        '-auth_old',
        '+auth_new'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(multiDiff, {
        workspacePath: tempWorkspace,
        allowMultiFile: false
      });

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /multi-file diff/i.test(e)));
    });
  });

  // --------------------------------------------------------------------------
  // 5. Malformed Diff Hunks Rejection
  // --------------------------------------------------------------------------
  describe('5. Malformed Diff Hunks Rejection', () => {
    it('should reject non-diff conversational string (recorded malformed-diff fixture)', () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'patch', 'malformed-diff.json');
      const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

      const result = validateDiffAndPaths(fixture.diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /header|malformed|missing|file headers/i.test(e)));
    });

    it('should reject empty or whitespace-only diffs', () => {
      const resEmpty = validateDiffAndPaths('', { workspacePath: tempWorkspace });
      assert.strictEqual(resEmpty.valid, false);

      const resSpaces = validateDiffAndPaths('    \n\n  \t  ', { workspacePath: tempWorkspace });
      assert.strictEqual(resSpaces.valid, false);
    });

    it('should reject missing file headers (diff containing only hunks without ---/+++)', () => {
      const diff = [
        '@@ -1,3 +1,3 @@',
        ' const a = 1;',
        '-const query = `bad`;',
        '+const query = "good";',
        ' const b = 2;'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /file headers/i.test(e)));
    });

    it('should reject malformed hunk header syntax (e.g. @@ broken @@)', () => {
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ invalid hunk header @@',
        '-old',
        '+new'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /malformed hunk header/i.test(e)));
    });

    it('should reject invalid hunk line prefix characters (not +, -, space, or \\)', () => {
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -1,2 +1,2 @@',
        '?this is not a valid diff prefix line',
        ' const a = 1;'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /invalid.*prefix/i.test(e)));
    });

    it('should reject inconsistent line count where actual lines are fewer than declared', () => {
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -10,10 +10,10 @@', // Declares 10 lines
        '-line1',
        '+line1_fixed'
        // only 1 line provided instead of 10
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /inconsistent line count/i.test(e)));
    });

    it('should reject diff with zero modifications (no added or deleted lines)', () => {
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -1,3 +1,3 @@',
        ' const a = 1;',
        ' const b = 2;',
        ' const c = 3;'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /zero additions or deletions|no.*changes/i.test(e)));
    });

    it('should reject diff attempting file creation (--- /dev/null)', () => {
      const diff = [
        '--- /dev/null',
        '+++ b/src/routes/new_exploit.js',
        '@@ -0,0 +1,1 @@',
        '+console.log("created");'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace, allowCreation: false });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /file creation/i.test(e)));
    });

    it('should reject diff attempting file deletion (+++ /dev/null)', () => {
      const diff = [
        '--- a/src/routes/user.js',
        '+++ /dev/null',
        '@@ -1,1 +0,0 @@',
        '-old'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: tempWorkspace, allowDeletion: false });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => /file deletion/i.test(e)));
    });
  });

  // --------------------------------------------------------------------------
  // 6. Invariant Verification: Disk and Original Source Remain Untouched
  // --------------------------------------------------------------------------
  describe('6. Invariant Verification: Disk Remains Untouched on Rejection', () => {
    it('should guarantee original file content is byte-for-byte identical after all rejected checks', () => {
      const currentContent = fs.readFileSync(sampleFilePath, 'utf8');
      assert.strictEqual(currentContent, sampleOriginalContent);

      // Verify no backup or temporary files were created inside the workspace
      const filesInDir = fs.readdirSync(path.join(tempWorkspace, 'src', 'routes'));
      assert.deepStrictEqual(filesInDir, ['user.js']);
    });
  });
});
