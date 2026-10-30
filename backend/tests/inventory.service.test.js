const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const inventoryService = require('../src/services/inventory.service');
const repositoryService = require('../src/services/repository.service');

describe('Bounded Source Inventory Service (Task 12)', () => {
  let tempWorkspace;

  before(() => {
    // Create temporary workspace with controlled structure
    tempWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex-inv-test-'));

    // 1. Regular source files
    fs.mkdirSync(path.join(tempWorkspace, 'src', 'utils'), { recursive: true });
    fs.writeFileSync(path.join(tempWorkspace, 'src', 'index.js'), 'const a = 1;\nconsole.log(a);\n');
    fs.writeFileSync(path.join(tempWorkspace, 'src', 'utils', 'helper.js'), 'function help() {\n  return "ok";\n}\nmodule.exports = help;\n');
    fs.writeFileSync(path.join(tempWorkspace, 'README.md'), '# Sample Project\nDocumentation.\n');
    fs.writeFileSync(path.join(tempWorkspace, 'package.json'), JSON.stringify({ name: 'sample-project', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempWorkspace, 'package-lock.json'), JSON.stringify({ name: 'sample-project', lockfileVersion: 3 }));

    // 2. Secret-containing file for excerpt test
    fs.writeFileSync(
      path.join(tempWorkspace, 'src', 'secret.js'),
      'const apiKey = "AKIA1234567890ABCDEF";\nconst password = "SuperSecretPassword123!";\nconst auth = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.xyz";\n'
    );

    // 3. Ignored directory
    fs.mkdirSync(path.join(tempWorkspace, 'node_modules', 'dep'), { recursive: true });
    fs.writeFileSync(path.join(tempWorkspace, 'node_modules', 'dep', 'index.js'), 'module.exports = {};');
    fs.mkdirSync(path.join(tempWorkspace, 'dist'), { recursive: true });
    fs.writeFileSync(path.join(tempWorkspace, 'dist', 'bundle.js'), '/* compiled bundle */');

    // 4. Binary files
    fs.writeFileSync(path.join(tempWorkspace, 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
    fs.writeFileSync(path.join(tempWorkspace, 'binary-without-ext'), Buffer.from([0x00, 0x01, 0x02, 0x00, 0x04]));

    // 5. Large file
    const largeContent = 'X'.repeat(5000);
    fs.writeFileSync(path.join(tempWorkspace, 'large.txt'), largeContent);
  });

  after(() => {
    // Cleanup temporary workspace
    if (tempWorkspace && fs.existsSync(tempWorkspace)) {
      fs.rmSync(tempWorkspace, { recursive: true, force: true });
    }
  });

  // --------------------------------------------------------------------------
  // 1. Basic Traversal & Manifest Identification
  // --------------------------------------------------------------------------
  describe('Workspace Scanning & Language Identification', () => {
    it('should accurately index source files and ignore vendor/build dirs', () => {
      const result = inventoryService.scanWorkspace(tempWorkspace);

      assert.strictEqual(result.workspacePath, path.resolve(tempWorkspace));
      assert.ok(result.totalFiles > 0);

      // Verify ignored directories were skipped
      const hasNodeModules = result.sourceFiles.some((f) => f.path.includes('node_modules'));
      assert.strictEqual(hasNodeModules, false, 'node_modules must not be in source files');

      const hasDist = result.sourceFiles.some((f) => f.path.includes('dist'));
      assert.strictEqual(hasDist, false, 'dist must not be in source files');

      // Verify source file details
      const indexFile = result.sourceFiles.find((f) => f.path === 'src/index.js' || f.path === 'src\\index.js');
      assert.ok(indexFile, 'src/index.js must be indexed');
      assert.strictEqual(indexFile.language, 'javascript');
      assert.strictEqual(indexFile.extension, '.js');
      assert.strictEqual(indexFile.lines, 3);
    });

    it('should detect package manifests (package.json and lockfile)', () => {
      const result = inventoryService.scanWorkspace(tempWorkspace);

      assert.strictEqual(result.summary.hasPackageJson, true);
      assert.strictEqual(result.summary.hasLockfile, true);
      assert.ok(result.manifests.length >= 2);

      const pkgManifest = result.manifests.find((m) => m.name === 'package.json');
      assert.ok(pkgManifest);
      assert.strictEqual(pkgManifest.type, 'npm');
    });

    it('should skip known binary extensions and files containing null bytes', () => {
      const result = inventoryService.scanWorkspace(tempWorkspace);

      const hasPng = result.sourceFiles.some((f) => f.path.endsWith('.png'));
      assert.strictEqual(hasPng, false, 'PNG file must be skipped from source files');

      const binarySkipped = result.skippedFiles.filter((s) => s.reason === 'BINARY_FILE');
      assert.ok(binarySkipped.length >= 2, 'Must identify both PNG and null-byte binary file');
    });
  });

  // --------------------------------------------------------------------------
  // 2. Resource Limits & Bounds Enforcement
  // --------------------------------------------------------------------------
  describe('Resource Bounds Enforcement', () => {
    it('should enforce maxFileSize limit and skip large files', () => {
      const result = inventoryService.scanWorkspace(tempWorkspace, {
        maxFileSize: 2000 // 2KB limit (large.txt is 5000 bytes)
      });

      const largeSkipped = result.skippedFiles.find((s) => s.relativePath === 'large.txt' && s.reason === 'FILE_TOO_LARGE');
      assert.ok(largeSkipped, 'large.txt must be flagged as FILE_TOO_LARGE');

      const largeInSource = result.sourceFiles.some((f) => f.path === 'large.txt');
      assert.strictEqual(largeInSource, false);
    });

    it('should enforce maxFiles limit and truncate crawl safely', () => {
      const result = inventoryService.scanWorkspace(tempWorkspace, {
        maxFiles: 2
      });

      assert.strictEqual(result.totalFiles, 2);
      assert.strictEqual(result.summary.truncated, true);
      assert.ok(result.summary.truncationReason.includes('MAX_FILES_LIMIT_EXCEEDED'));
    });

    it('should enforce maxTotalBytes limit and truncate crawl safely', () => {
      const result = inventoryService.scanWorkspace(tempWorkspace, {
        maxTotalBytes: 100 // Very low threshold to trigger total bytes cap
      });

      assert.strictEqual(result.summary.truncated, true);
      assert.ok(result.summary.truncationReason.includes('MAX_TOTAL_BYTES_EXCEEDED'));
    });

    it('should reject non-existent or non-directory workspace paths', () => {
      assert.throws(
        () => inventoryService.scanWorkspace('/non/existent/path/12345'),
        (err) => err.message.includes('does not exist')
      );

      assert.throws(
        () => inventoryService.scanWorkspace(path.join(tempWorkspace, 'README.md')),
        (err) => err.message.includes('is not a directory')
      );
    });
  });

  // --------------------------------------------------------------------------
  // 3. Bounded Source Excerpt & Credential Redaction
  // --------------------------------------------------------------------------
  describe('Bounded Source Excerpt & Credential Redaction', () => {
    it('should extract bounded line range with surrounding context padding', () => {
      const excerpt = inventoryService.getFileExcerpt(tempWorkspace, 'src/index.js', 2, 2, {
        contextLines: 1
      });

      assert.strictEqual(excerpt.filePath, 'src/index.js');
      assert.strictEqual(excerpt.targetStartLine, 2);
      assert.strictEqual(excerpt.targetEndLine, 2);
      assert.ok(excerpt.lines.length >= 2);

      const targetLine = excerpt.lines.find((l) => l.isTarget);
      assert.ok(targetLine);
      assert.strictEqual(targetLine.line, 2);
      assert.ok(targetLine.content.includes('console.log'));
    });

    it('should automatically redact sensitive secrets from code excerpts', () => {
      const excerpt = inventoryService.getFileExcerpt(tempWorkspace, 'src/secret.js', 1, 3);

      assert.strictEqual(excerpt.isRedacted, true);
      assert.strictEqual(excerpt.lines.some((l) => l.content.includes('AKIA1234567890ABCDEF')), false);
      assert.strictEqual(excerpt.lines.some((l) => l.content.includes('SuperSecretPassword123!')), false);
      assert.ok(excerpt.lines.some((l) => l.content.includes('[REDACTED_AWS_KEY]')));
      assert.ok(excerpt.lines.some((l) => l.content.includes('[REDACTED_SECRET]')));
      assert.ok(excerpt.lines.some((l) => l.content.includes('[REDACTED_JWT]')));
    });

    it('should reject path traversal in getFileExcerpt', () => {
      assert.throws(
        () => inventoryService.getFileExcerpt(tempWorkspace, '../../etc/passwd', 1, 5),
        (err) => err.message.includes('traversal') || err.message.includes('Invalid file path')
      );

      assert.throws(
        () => inventoryService.getFileExcerpt(tempWorkspace, '/etc/shadow', 1, 5),
        (err) => err.message.includes('relative to the scan workspace') || err.message.includes('Invalid file path')
      );
    });
  });

  // --------------------------------------------------------------------------
  // 4. Repository Service Intake & Inventory Delegation
  // --------------------------------------------------------------------------
  describe('Repository Service Intake & Delegation', () => {
    it('should register a valid repository and list it', () => {
      const repo = repositoryService.registerRepository({
        sourceType: 'GITHUB',
        displayName: 'test-repo',
        sourceUrl: 'https://github.com/org/test-repo',
        defaultRef: 'main'
      });

      assert.ok(repo.id.startsWith('repo_'));
      assert.strictEqual(repo.displayName, 'test-repo');
      assert.strictEqual(repo.sanitizedSourceUrl, 'https://github.com/org/test-repo');

      const fetched = repositoryService.getRepositoryById(repo.id);
      assert.deepStrictEqual(fetched, repo);

      const all = repositoryService.listRepositories();
      assert.ok(all.some((r) => r.id === repo.id));
    });

    it('should reject invalid repository intake (e.g. private IP SSRF)', () => {
      assert.throws(
        () => repositoryService.registerRepository({
          sourceType: 'GITHUB',
          displayName: 'ssrf-repo',
          sourceUrl: 'https://192.168.1.1/exploit.git'
        }),
        (err) => err.code === 'INVALID_INPUT' && err.statusCode === 400
      );
    });

    it('should delegate scanWorkspace and getFileExcerpt correctly', () => {
      const result = repositoryService.scanWorkspace(tempWorkspace);
      assert.ok(result.totalFiles > 0);

      const excerpt = repositoryService.getFileExcerpt(tempWorkspace, 'src/index.js', 1, 1);
      assert.ok(excerpt.lines.length > 0);
    });
  });
});
