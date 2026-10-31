/**
 * VULNEX Independent Unified Diff & Changed-File Path Validator Tests
 *
 * Verifies:
 * - Deterministic, non-AI validation of unified diff syntax and structure.
 * - Deep parsing of single-file and multi-file diff headers (--- / +++ / diff --git).
 * - Identification and normalization of all changed-file paths.
 * - Workspace confinement checks: rejection of absolute paths, ../ traversal, and canonicalization escapes.
 * - Symlink escape detection via realpath resolution against workspace root.
 * - Rejection of unsupported operations: file creation, deletion, renaming, and binary diffs.
 * - Hunk header validation and line-count consistency enforcement.
 * - Invariant: In-memory validation only; never applies patches or touches disk repository files.
 * - Fail closed: any invalid hunk, unsafe path, or unpermitted modification causes immediate rejection.
 */

const { describe, it, before, after } = require('node:test');
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

describe('Independent Unified Diff & Changed-File Path Validator', () => {

  // --------------------------------------------------------------------------
  // 1. Valid Single-File and Multi-File Diffs
  // --------------------------------------------------------------------------
  describe('1. Valid Single-File & Multi-File Diffs', () => {
    it('should validate a standard single-file unified diff', () => {
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -42,3 +42,3 @@',
        ' const a = 1;',
        '-const query = `SELECT * FROM users WHERE id = ${id}`;',
        '+const query = "SELECT * FROM users WHERE id = $1";',
        ' const b = 2;'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, true);
      assert.equal(result.errors.length, 0);
      assert.deepEqual(result.detectedFiles, ['src/routes/user.js']);
      assert.deepEqual(result.changedFiles, ['src/routes/user.js']);
      assert.equal(result.rejectedPaths.length, 0);
      assert.equal(result.hunksCount, 1);
      assert.equal(result.stats.additions, 1);
      assert.equal(result.stats.deletions, 1);
      assert.equal(result.stats.filesCount, 1);
    });

    it('should validate git-style diff header with git metadata lines', () => {
      const diff = [
        'diff --git a/src/services/auth.js b/src/services/auth.js',
        'index 1234567..89abcdef 100644',
        '--- a/src/services/auth.js',
        '+++ b/src/services/auth.js',
        '@@ -10,2 +10,2 @@',
        '-const oldHash = md5(password);',
        '+const newHash = sha256(password);',
        ' return newHash;'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, true);
      assert.deepEqual(result.detectedFiles, ['src/services/auth.js']);
      assert.equal(result.hunksCount, 1);
    });

    it('should validate multi-file diff when permitted', () => {
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -1,2 +1,2 @@',
        '-const x = 1;',
        '+const x = 2;',
        ' const y = 3;',
        '--- a/src/routes/profile.js',
        '+++ b/src/routes/profile.js',
        '@@ -5,2 +5,2 @@',
        '-const a = "a";',
        '+const a = "b";',
        ' const c = "c";'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { allowMultiFile: true });
      assert.equal(result.valid, true);
      assert.deepEqual(result.detectedFiles.sort(), ['src/routes/profile.js', 'src/routes/user.js'].sort());
      assert.equal(result.stats.filesCount, 2);
      assert.equal(result.hunksCount, 2);
    });

    it('should reject multi-file diff when allowMultiFile is false', () => {
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -1,1 +1,1 @@',
        '-const x = 1;',
        '+const x = 2;',
        '--- a/src/routes/profile.js',
        '+++ b/src/routes/profile.js',
        '@@ -5,1 +5,1 @@',
        '-const a = "a";',
        '+const a = "b";'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { allowMultiFile: false });
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('multi-file diffs are not permitted')));
    });

    it('should accept diffs with "\\ No newline at end of file" marker', () => {
      const diff = [
        '--- a/src/config.json',
        '+++ b/src/config.json',
        '@@ -1,1 +1,1 @@',
        '-{"debug": true}',
        '\\ No newline at end of file',
        '+{"debug": false}',
        '\\ No newline at end of file'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, true);
      assert.equal(result.stats.additions, 1);
      assert.equal(result.stats.deletions, 1);
    });
  });

  // --------------------------------------------------------------------------
  // 2. Malformed Diff Headers and Hunks
  // --------------------------------------------------------------------------
  describe('2. Malformed Diff Headers & Hunks', () => {
    it('should reject diff missing file headers', () => {
      const diff = [
        '@@ -1,2 +1,2 @@',
        '-const a = 1;',
        '+const a = 2;',
        ' const b = 3;'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('without preceding file headers') || e.includes('file headers')));
    });

    it('should reject malformed hunk header syntax', () => {
      const diff = [
        '--- a/src/app.js',
        '+++ b/src/app.js',
        '@@ invalid hunk header @@',
        '-a',
        '+b'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Malformed hunk header')));
    });

    it('should reject invalid diff hunk line prefix characters', () => {
      const diff = [
        '--- a/src/app.js',
        '+++ b/src/app.js',
        '@@ -1,2 +1,2 @@',
        '-const a = 1;',
        '?const a = 2;', // Invalid line prefix '?'
        ' const b = 3;'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Invalid diff hunk line prefix')));
    });

    it('should reject diff containing zero additions or deletions', () => {
      const diff = [
        '--- a/src/app.js',
        '+++ b/src/app.js',
        '@@ -1,2 +1,2 @@',
        ' const a = 1;',
        ' const b = 2;'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('zero additions or deletions')));
    });

    it('should reject file header without any hunks', () => {
      const diff = [
        '--- a/src/app.js',
        '+++ b/src/app.js'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('no hunk headers')));
    });
  });

  // --------------------------------------------------------------------------
  // 3. Inconsistent Line Counts & Incomplete Diffs
  // --------------------------------------------------------------------------
  describe('3. Inconsistent Line Counts & Incomplete Diffs', () => {
    it('should detect inconsistent line count when actual lines are fewer than declared (incomplete diff)', () => {
      // Declared -3,+3 but only supplied 1 deletion and 1 addition
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -10,3 +10,3 @@',
        '-const query = `SELECT * FROM users WHERE id = ${id}`;',
        '+const query = "SELECT * FROM users WHERE id = $1";'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Inconsistent line count')));
      assert.ok(result.errors.some(e => e.includes('declared -3,+3 but found -1,+1')));
    });

    it('should detect inconsistent line count when actual lines exceed declared', () => {
      // Declared -1,+1 but supplied 2 context lines and 1 addition/deletion
      const diff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -10,1 +10,1 @@',
        ' context line 1',
        '-const query = `...`;',
        '+const query = "...";',
        ' context line 2'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Inconsistent line count')));
    });

    it('should reject empty or whitespace-only diffs', () => {
      assert.equal(validateDiffAndPaths('').valid, false);
      assert.equal(validateDiffAndPaths('   \n\t  ').valid, false);
      assert.equal(validateDiffAndPaths(null).valid, false);
    });
  });

  // --------------------------------------------------------------------------
  // 4. Absolute Paths & Path Traversal Prevention
  // --------------------------------------------------------------------------
  describe('4. Absolute Paths & Path Traversal Prevention', () => {
    it('should reject Unix absolute paths in diff headers', () => {
      const diff = [
        '--- a//etc/passwd',
        '+++ b//etc/passwd',
        '@@ -1,1 +1,1 @@',
        '-root:x:0:0:',
        '+root:x:0:1:'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.rejectedPaths.includes('/etc/passwd'));
      assert.ok(result.errors.some(e => e.includes('Absolute paths are not permitted')));
    });

    it('should reject Windows absolute paths with drive letters', () => {
      const diff = [
        '--- C:\\Windows\\System32\\drivers\\etc\\hosts',
        '+++ C:\\Windows\\System32\\drivers\\etc\\hosts',
        '@@ -1,1 +1,1 @@',
        '-127.0.0.1 localhost',
        '+127.0.0.1 malicious.local'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Absolute paths are not permitted')));
    });

    it('should reject path traversal sequences (../)', () => {
      const diff = [
        '--- a/../../../etc/shadow',
        '+++ b/../../../etc/shadow',
        '@@ -1,1 +1,1 @@',
        '-root:$6$hash',
        '+root:$6$cracked'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Path traversal ("..") is not permitted')));
    });

    it('should reject hidden nested path traversal (src/../../secret.txt)', () => {
      const diff = [
        '--- a/src/../../secret.txt',
        '+++ b/src/../../secret.txt',
        '@@ -1,1 +1,1 @@',
        '-secret',
        '+leaked'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Path traversal ("..") is not permitted')));
    });

    it('should reject null bytes in file paths', () => {
      const result = validateWorkspacePath('src/file\0.js');
      assert.equal(result.valid, false);
      assert.equal(result.code, 'NULL_BYTE');
    });
  });

  // --------------------------------------------------------------------------
  // 5. Workspace Confinement & Symlink Escape Detection
  // --------------------------------------------------------------------------
  describe('5. Workspace Confinement & Symlink Escape Detection', () => {
    let tempDir;
    let workspaceDir;
    let outsideDir;

    before(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex-diff-validator-test-'));
      workspaceDir = path.join(tempDir, 'workspace');
      outsideDir = path.join(tempDir, 'outside');

      fs.mkdirSync(workspaceDir);
      fs.mkdirSync(outsideDir);
      fs.mkdirSync(path.join(workspaceDir, 'src'));

      // Create dummy safe file
      fs.writeFileSync(path.join(workspaceDir, 'src', 'app.js'), 'console.log("safe");\n');

      // Create target outside file
      fs.writeFileSync(path.join(outsideDir, 'secret.env'), 'SECRET_KEY=leaked\n');

      // Create symlink directory pointing outside
      fs.symlinkSync(outsideDir, path.join(workspaceDir, 'symlink_outside'));

      // Create symlink file pointing outside
      fs.symlinkSync(path.join(outsideDir, 'secret.env'), path.join(workspaceDir, 'symlink_file.env'));

      // Create safe internal symlink
      fs.symlinkSync(path.join(workspaceDir, 'src', 'app.js'), path.join(workspaceDir, 'src', 'app_link.js'));
    });

    after(() => {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    });

    it('should accept valid file path strictly confined inside workspace', () => {
      const check = validateWorkspacePath('src/app.js', workspaceDir);
      assert.equal(check.valid, true);
      assert.equal(check.normalizedPath, 'src/app.js');
    });

    it('should reject symlink directory pointing outside workspace', () => {
      const check = validateWorkspacePath('symlink_outside/secret.env', workspaceDir);
      assert.equal(check.valid, false);
      assert.equal(check.code, 'SYMLINK_WORKSPACE_ESCAPE');
      assert.ok(check.error.includes('resolves via symlink outside workspace'));
    });

    it('should reject symlink file pointing outside workspace', () => {
      const check = validateWorkspacePath('symlink_file.env', workspaceDir);
      assert.equal(check.valid, false);
      assert.equal(check.code, 'SYMLINK_WORKSPACE_ESCAPE');
      assert.ok(check.error.includes('resolves via symlink outside workspace'));
    });

    it('should accept internal symlink resolving inside workspace', () => {
      const check = validateWorkspacePath('src/app_link.js', workspaceDir);
      assert.equal(check.valid, true);
    });

    it('should reject diff modifying path that resolves via symlink outside workspace', () => {
      const diff = [
        '--- a/symlink_outside/secret.env',
        '+++ b/symlink_outside/secret.env',
        '@@ -1,1 +1,1 @@',
        '-SECRET_KEY=leaked',
        '+SECRET_KEY=safe'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(diff, { workspacePath: workspaceDir });
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('resolves via symlink outside workspace')));
      assert.ok(result.rejectedPaths.includes('symlink_outside/secret.env'));
    });
  });

  // --------------------------------------------------------------------------
  // 6. Declared vs Actual changedFiles & Scope Bounding
  // --------------------------------------------------------------------------
  describe('6. Declared Files Mismatch & Finding Scope Enforcement', () => {
    const validDiff = [
      '--- a/src/routes/user.js',
      '+++ b/src/routes/user.js',
      '@@ -1,1 +1,1 @@',
      '-oldLine();',
      '+newLine();'
    ].join('\n') + '\n';

    it('should pass when actual diff file matches declared changedFiles exactly', () => {
      const result = validateDiffAndPaths(validDiff, {
        declaredChangedFiles: ['src/routes/user.js']
      });
      assert.equal(result.valid, true);
    });

    it('should reject when diff modifies a file not in declared changedFiles', () => {
      const result = validateDiffAndPaths(validDiff, {
        declaredChangedFiles: ['src/routes/other.js']
      });
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('not declared in proposal changedFiles')));
      assert.ok(result.rejectedPaths.includes('src/routes/user.js'));
    });

    it('should reject when declared changedFiles declares files missing from diff', () => {
      const result = validateDiffAndPaths(validDiff, {
        declaredChangedFiles: ['src/routes/user.js', 'src/routes/extra.js']
      });
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('is not modified in the diff')));
      assert.ok(result.rejectedPaths.includes('src/routes/extra.js'));
    });

    it('should reject diff modifying file outside finding target scope', () => {
      const mockFinding = {
        id: 'finding_sqli_01',
        filePath: 'src/routes/admin.js'
      };

      const result = validateDiffAndPaths(validDiff, { finding: mockFinding });
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('outside permitted finding scope')));
      assert.ok(result.rejectedPaths.includes('src/routes/user.js'));
    });
  });

  // --------------------------------------------------------------------------
  // 7. Unsupported Lifecycle Operations & Binary Diffs
  // --------------------------------------------------------------------------
  describe('7. Unsupported Operations: Rename, Delete, Create, Binary', () => {
    it('should reject binary diffs', () => {
      const binaryDiff = [
        'diff --git a/logo.png b/logo.png',
        'Binary files a/logo.png and b/logo.png differ'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(binaryDiff);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Binary diffs are not supported')));
    });

    it('should reject file creation when allowCreation is false', () => {
      const createDiff = [
        '--- /dev/null',
        '+++ b/src/newFile.js',
        '@@ -0,0 +1,1 @@',
        '+console.log("new");'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(createDiff, { allowCreation: false });
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('File creation') && e.includes('not supported')));
    });

    it('should reject file deletion when allowDeletion is false', () => {
      const deleteDiff = [
        '--- a/src/obsolete.js',
        '+++ /dev/null',
        '@@ -1,1 +0,0 @@',
        '-console.log("obsolete");'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(deleteDiff, { allowDeletion: false });
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('File deletion') && e.includes('not supported')));
    });

    it('should reject file rename operations when allowRename is false', () => {
      const renameDiff = [
        'diff --git a/src/oldName.js b/src/newName.js',
        'rename from src/oldName.js',
        'rename to src/newName.js',
        '--- a/src/oldName.js',
        '+++ b/src/newName.js',
        '@@ -1,1 +1,1 @@',
        '-const x = 1;',
        '+const x = 1;'
      ].join('\n') + '\n';

      const result = validateDiffAndPaths(renameDiff, { allowRename: false });
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('rename') && e.includes('not supported')));
    });
  });

  // --------------------------------------------------------------------------
  // 8. assertValidDiff Convenience Wrapper
  // --------------------------------------------------------------------------
  describe('8. assertValidDiff Convenience Helper', () => {
    it('should return result on valid diff without throwing', () => {
      const validDiff = [
        '--- a/src/routes/user.js',
        '+++ b/src/routes/user.js',
        '@@ -1,1 +1,1 @@',
        '-a',
        '+b'
      ].join('\n') + '\n';

      assert.doesNotThrow(() => {
        const res = assertValidDiff(validDiff);
        assert.equal(res.valid, true);
      });
    });

    it('should throw DiffValidationError with details on invalid diff', () => {
      const invalidDiff = 'not a diff at all';

      assert.throws(() => {
        assertValidDiff(invalidDiff);
      }, (err) => {
        assert.ok(err instanceof DiffValidationError);
        assert.ok(err.details);
        assert.equal(err.details.valid, false);
        return true;
      });
    });
  });

  // --------------------------------------------------------------------------
  // 9. Critical Security Invariant: Non-destructive & Independent
  // --------------------------------------------------------------------------
  describe('9. Critical Security Invariant: Repository Untouched', () => {
    it('should verify validation never applies patches or alters disk files', () => {
      const sampleFile = path.join(__dirname, 'fixtures', 'patch', 'valid-minimal-sqli-patch.json');
      const originalStat = fs.statSync(sampleFile);
      const originalContent = fs.readFileSync(sampleFile, 'utf8');

      const fixtureJson = JSON.parse(originalContent);
      const result = validateDiffAndPaths(fixtureJson.diff, {
        declaredChangedFiles: fixtureJson.changedFiles
      });

      assert.equal(result.valid, true);

      // Verify file on disk is completely unmodified
      const afterContent = fs.readFileSync(sampleFile, 'utf8');
      assert.equal(afterContent, originalContent, 'File content on disk must remain strictly identical');
      assert.equal(fs.statSync(sampleFile).mtimeMs, originalStat.mtimeMs, 'File mtime must not change');
    });
  });
});
