const fs = require('fs');
const path = require('path');
const { SafeRelativeFilePath } = require('../validators/canonical.schema');

/**
 * ============================================================================
 * VULNEX Bounded Source Inventory Service
 * 
 * Responsibilities:
 * 1. Read-only, bounded directory traversal of scan workspaces.
 * 2. Enforces hard resource bounds (max files, max total bytes, max file size, max depth).
 * 3. Identifies and catalogs dependency manifests (e.g. package.json, lockfiles).
 * 4. Filters out vendor dirs, build artifacts, media, and binary files.
 * 5. Provides bounded, redaction-safe source excerpt extraction for AI context.
 * 
 * Security:
 * - Read-only operations only. Never writes or modifies source trees.
 * - Strict path containment guards to prevent directory traversal and symlink escapes.
 * ============================================================================
 */

// Default Resource Bounds
const DEFAULT_MAX_FILES = 1000;
const DEFAULT_MAX_TOTAL_BYTES = 25 * 1024 * 1024; // 25 MB
const DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024;    // 1 MB per file
const DEFAULT_MAX_DEPTH = 15;

// Directories to ignore and skip during traversal
const IGNORED_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.output',
  'coverage',
  '.nyc_output',
  'vendor',
  'bower_components',
  'target',
  'bin',
  'obj',
  '.workspaces',
  '.cache',
  '.temp',
  '.tmp'
]);

// Binary file extensions that must not be ingested as source text
const BINARY_EXTENSIONS = new Set([
  // Images
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.bmp', '.tiff', '.psd',
  // Audio & Video
  '.mp3', '.wav', '.ogg', '.mp4', '.mov', '.avi', '.mkv', '.flv',
  // Archives & Compressed
  '.zip', '.tar', '.gz', '.tgz', '.7z', '.rar', '.jar', '.war', '.bz2',
  // Executables & Libraries
  '.exe', '.dll', '.so', '.dylib', '.class', '.pyc', '.o', '.a', '.wasm',
  // Fonts
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  // Database & Binary Data
  '.sqlite', '.sqlite3', '.db', '.bin', '.dat', '.iso'
]);

// Source file extensions mapped to recognized languages
const LANGUAGE_EXTENSIONS = {
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.tsx': 'typescript',
  '.json': 'json',
  '.html': 'html',
  '.htm': 'html',
  '.css': 'css',
  '.scss': 'css',
  '.sass': 'css',
  '.less': 'css',
  '.md': 'markdown',
  '.markdown': 'markdown',
  '.yaml': 'yaml',
  '.yml': 'yaml',
  '.sh': 'shell',
  '.bash': 'shell',
  '.sql': 'sql',
  '.py': 'python',
  '.go': 'go',
  '.rs': 'rust',
  '.java': 'java',
  '.php': 'php',
  '.rb': 'ruby',
  '.c': 'c',
  '.cpp': 'cpp',
  '.h': 'c',
  '.hpp': 'cpp'
};

// Known manifest file basenames
const MANIFEST_FILENAMES = {
  'package.json': 'npm',
  'package-lock.json': 'npm-lock',
  'npm-shrinkwrap.json': 'npm-shrinkwrap',
  'yarn.lock': 'yarn-lock',
  'pnpm-lock.yaml': 'pnpm-lock',
  'composer.json': 'composer',
  'Gemfile': 'bundler',
  'requirements.txt': 'pip',
  'Pipfile': 'pipenv',
  'go.mod': 'go-modules',
  'Cargo.toml': 'cargo'
};

/**
 * Check if a file is binary by extension or inspect the first 512 bytes for null chars.
 * @param {string} fullPath
 * @param {string} ext
 * @returns {boolean}
 */
function isBinary(fullPath, ext) {
  if (BINARY_EXTENSIONS.has(ext)) {
    return true;
  }

  try {
    const fd = fs.openSync(fullPath, 'r');
    const buffer = Buffer.alloc(512);
    const bytesRead = fs.readSync(fd, buffer, 0, 512, 0);
    fs.closeSync(fd);

    for (let i = 0; i < bytesRead; i++) {
      if (buffer[i] === 0) {
        return true;
      }
    }
  } catch {
    // If unreadable, treat safely as non-source
    return true;
  }

  return false;
}

/**
 * Count lines in a string or buffer safely
 * @param {string} content
 * @returns {number}
 */
function countLines(content) {
  if (!content) return 0;
  let lines = 1;
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') {
      lines++;
    }
  }
  return lines;
}

/**
 * Redact common credential patterns from code excerpts
 * @param {string} text
 * @returns {{ redactedText: string, hasRedactions: boolean }}
 */
function redactSecrets(text) {
  if (!text) return { redactedText: '', hasRedactions: false };

  let hasRedactions = false;
  let result = text;

  // Mask JWT / Bearer tokens
  result = result.replace(/Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g, () => {
    hasRedactions = true;
    return 'Bearer [REDACTED_JWT]';
  });

  // Mask AWS API Keys
  result = result.replace(/\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g, () => {
    hasRedactions = true;
    return '[REDACTED_AWS_KEY]';
  });

  // Mask private key headers
  result = result.replace(/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, () => {
    hasRedactions = true;
    return '-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY_BODY]\n-----END PRIVATE KEY-----';
  });

  // Mask password assignments (avoid re-redacting already masked placeholders)
  result = result.replace(/(password|passwd|pwd|secret|api_key|apikey|auth_token)\s*([:=])\s*(['"`])(?!\[REDACTED_)([^'"`\s]{4,})\3/gi, (match, key, op, quote) => {
    hasRedactions = true;
    return `${key} ${op} ${quote}[REDACTED_SECRET]${quote}`;
  });

  return { redactedText: result, hasRedactions };
}

/**
 * Perform a bounded, read-only inventory scan of a workspace directory.
 * @param {string} workspacePath - Absolute path to workspace root
 * @param {Object} [options={}]
 * @param {number} [options.maxFiles=1000]
 * @param {number} [options.maxTotalBytes=26214400]
 * @param {number} [options.maxFileSize=1048576]
 * @param {number} [options.maxDepth=15]
 * @returns {Object} Inventory result
 */
function scanWorkspace(workspacePath, options = {}) {
  if (!workspacePath || typeof workspacePath !== 'string') {
    throw new Error('workspacePath must be a non-empty string');
  }

  const resolvedRoot = path.resolve(workspacePath);

  if (!fs.existsSync(resolvedRoot)) {
    throw new Error(`Workspace path does not exist: ${resolvedRoot}`);
  }

  const rootStat = fs.statSync(resolvedRoot);
  if (!rootStat.isDirectory()) {
    throw new Error(`Workspace path is not a directory: ${resolvedRoot}`);
  }

  const maxFiles = options.maxFiles || DEFAULT_MAX_FILES;
  const maxTotalBytes = options.maxTotalBytes || DEFAULT_MAX_TOTAL_BYTES;
  const maxFileSize = options.maxFileSize || DEFAULT_MAX_FILE_SIZE;
  const maxDepth = options.maxDepth || DEFAULT_MAX_DEPTH;

  const sourceFiles = [];
  const manifests = [];
  const skippedFiles = [];
  const languageCounts = {};

  let totalFiles = 0;
  let totalBytes = 0;
  let isTruncated = false;
  let truncationReason = null;

  function traverse(currentDir, currentDepth) {
    if (isTruncated) return;

    if (currentDepth > maxDepth) {
      skippedFiles.push({
        relativePath: path.relative(resolvedRoot, currentDir) || '.',
        reason: 'MAX_DEPTH_EXCEEDED'
      });
      return;
    }

    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (err) {
      skippedFiles.push({
        relativePath: path.relative(resolvedRoot, currentDir),
        reason: `READ_ERROR: ${err.message}`
      });
      return;
    }

    // Sort entries deterministically for reproducible scans
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (isTruncated) break;

      const fullPath = path.join(currentDir, entry.name);
      const relativePath = path.relative(resolvedRoot, fullPath);

      // Handle symlinks safely: prevent path traversal outside workspace root
      if (entry.isSymbolicLink()) {
        try {
          const realTarget = fs.realpathSync(fullPath);
          if (!realTarget.startsWith(resolvedRoot)) {
            skippedFiles.push({
              relativePath,
              reason: 'SYMLINK_OUTSIDE_WORKSPACE'
            });
            continue;
          }
        } catch {
          skippedFiles.push({
            relativePath,
            reason: 'BROKEN_SYMLINK'
          });
          continue;
        }
      }

      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name)) {
          skippedFiles.push({
            relativePath,
            reason: 'IGNORED_DIRECTORY'
          });
          continue;
        }

        traverse(fullPath, currentDepth + 1);
        continue;
      }

      if (entry.isFile()) {
        // Enforce maximum file count limit
        if (totalFiles >= maxFiles) {
          isTruncated = true;
          truncationReason = `MAX_FILES_LIMIT_EXCEEDED (${maxFiles})`;
          break;
        }

        let stat;
        try {
          stat = fs.statSync(fullPath);
        } catch {
          skippedFiles.push({ relativePath, reason: 'STAT_ERROR' });
          continue;
        }

        const fileSize = stat.size;

        // Enforce maximum single file size limit
        if (fileSize > maxFileSize) {
          skippedFiles.push({
            relativePath,
            reason: 'FILE_TOO_LARGE',
            size: fileSize,
            maxSize: maxFileSize
          });
          continue;
        }

        // Enforce total workspace bytes limit
        if (totalBytes + fileSize > maxTotalBytes) {
          isTruncated = true;
          truncationReason = `MAX_TOTAL_BYTES_EXCEEDED (${maxTotalBytes} bytes)`;
          break;
        }

        const ext = path.extname(entry.name).toLowerCase();

        // Skip binary files
        if (isBinary(fullPath, ext)) {
          skippedFiles.push({
            relativePath,
            reason: 'BINARY_FILE',
            size: fileSize
          });
          continue;
        }

        // Check if file is a package/dependency manifest
        if (MANIFEST_FILENAMES[entry.name]) {
          manifests.push({
            path: relativePath,
            name: entry.name,
            type: MANIFEST_FILENAMES[entry.name],
            size: fileSize
          });
        }

        // Read line count safely
        let lines = 0;
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          lines = countLines(content);
        } catch {
          // If read fails, fallback lines to 0
          lines = 0;
        }

        const language = LANGUAGE_EXTENSIONS[ext] || 'other';
        languageCounts[language] = (languageCounts[language] || 0) + 1;

        sourceFiles.push({
          path: relativePath,
          extension: ext || '',
          language,
          size: fileSize,
          lines
        });

        totalFiles++;
        totalBytes += fileSize;
      }
    }
  }

  traverse(resolvedRoot, 0);

  return {
    workspacePath: resolvedRoot,
    totalFiles,
    totalBytes,
    manifests,
    sourceFiles,
    skippedFiles,
    summary: {
      fileCountByLanguage: languageCounts,
      manifestCount: manifests.length,
      hasPackageJson: manifests.some((m) => m.name === 'package.json'),
      hasLockfile: manifests.some((m) => m.type.includes('lock')),
      isBounded: true,
      truncated: isTruncated,
      truncationReason: truncationReason
    }
  };
}

/**
 * Retrieve a bounded, line-numbered source excerpt with surrounding context and secrets redacted.
 * Safe against path traversal.
 * 
 * @param {string} workspacePath - Absolute path to workspace root
 * @param {string} relativeFilePath - Relative path within workspace
 * @param {number} startLine - 1-based start line number
 * @param {number} endLine - 1-based end line number
 * @param {Object} [options={}]
 * @param {number} [options.contextLines=5] - Number of lines to pad before and after
 * @param {number} [options.maxLines=60] - Hard cap on total lines returned
 * @returns {Object} Bounded excerpt DTO
 */
function getFileExcerpt(workspacePath, relativeFilePath, startLine, endLine, options = {}) {
  // Validate path against traversal
  const pathValidation = SafeRelativeFilePath.safeParse(relativeFilePath);
  if (!pathValidation.success) {
    throw new Error(`Invalid file path: ${pathValidation.error.issues[0]?.message || 'Path traversal rejected'}`);
  }

  const resolvedRoot = path.resolve(workspacePath);
  const fullPath = path.resolve(resolvedRoot, relativeFilePath);

  // Containment assertion
  if (!fullPath.startsWith(resolvedRoot)) {
    throw new Error('Access denied: Target path traverses outside the workspace directory.');
  }

  if (!fs.existsSync(fullPath)) {
    throw new Error(`Source file does not exist: ${relativeFilePath}`);
  }

  const contextLines = typeof options.contextLines === 'number' ? Math.max(0, options.contextLines) : 5;
  const maxLines = typeof options.maxLines === 'number' ? Math.max(1, options.maxLines) : 60;

  const content = fs.readFileSync(fullPath, 'utf8');
  const allLines = content.split('\n');
  const totalFileLines = allLines.length;

  const targetStart = Math.max(1, parseInt(startLine, 10) || 1);
  const targetEnd = Math.max(targetStart, parseInt(endLine, 10) || targetStart);

  const boundedStart = Math.max(1, targetStart - contextLines);
  const boundedEnd = Math.min(totalFileLines, targetEnd + contextLines);

  const requestedCount = (boundedEnd - boundedStart) + 1;
  const effectiveEnd = requestedCount > maxLines ? boundedStart + maxLines - 1 : boundedEnd;

  const excerptLines = [];
  let anyRedactions = false;

  for (let i = boundedStart; i <= effectiveEnd; i++) {
    const rawLine = allLines[i - 1] || '';
    const { redactedText, hasRedactions } = redactSecrets(rawLine);
    if (hasRedactions) {
      anyRedactions = true;
    }

    excerptLines.push({
      line: i,
      content: redactedText,
      isTarget: i >= targetStart && i <= targetEnd
    });
  }

  return {
    filePath: relativeFilePath,
    totalFileLines,
    startLine: boundedStart,
    endLine: effectiveEnd,
    targetStartLine: targetStart,
    targetEndLine: targetEnd,
    lines: excerptLines,
    rawExcerpt: excerptLines.map((l) => `${l.line}: ${l.content}`).join('\n'),
    isRedacted: anyRedactions
  };
}

module.exports = {
  DEFAULT_MAX_FILES,
  DEFAULT_MAX_TOTAL_BYTES,
  DEFAULT_MAX_FILE_SIZE,
  DEFAULT_MAX_DEPTH,
  IGNORED_DIRECTORIES,
  BINARY_EXTENSIONS,
  LANGUAGE_EXTENSIONS,
  MANIFEST_FILENAMES,
  isBinary,
  countLines,
  redactSecrets,
  scanWorkspace,
  getFileExcerpt
};
