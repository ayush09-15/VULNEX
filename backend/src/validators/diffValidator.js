/**
 * VULNEX Independent Unified Diff & Changed-File Path Validator
 *
 * Implements:
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

const fs = require('fs');
const path = require('path');

// ----------------------------------------------------------------------------
// 1. Custom Error Classes
// ----------------------------------------------------------------------------

class DiffValidationError extends Error {
  constructor(message, details = {}) {
    super(message || 'Unified diff validation failed');
    this.name = 'DiffValidationError';
    this.details = details;
  }
}

class WorkspacePathEscapeError extends DiffValidationError {
  constructor(message, details = {}) {
    super(message || 'Target path escapes workspace boundaries', details);
    this.name = 'WorkspacePathEscapeError';
  }
}

class SymlinkEscapeError extends DiffValidationError {
  constructor(message, details = {}) {
    super(message || 'Target path escapes workspace via symbolic link', details);
    this.name = 'SymlinkEscapeError';
  }
}

class MalformedDiffError extends DiffValidationError {
  constructor(message, details = {}) {
    super(message || 'Malformed unified diff structure', details);
    this.name = 'MalformedDiffError';
  }
}

class InconsistentLineCountError extends DiffValidationError {
  constructor(message, details = {}) {
    super(message || 'Hunk line count is inconsistent with header declaration', details);
    this.name = 'InconsistentLineCountError';
  }
}

class DeclaredFilesMismatchError extends DiffValidationError {
  constructor(message, details = {}) {
    super(message || 'Diff changed files do not match declared changed files', details);
    this.name = 'DeclaredFilesMismatchError';
  }
}

class OutOfScopeDiffError extends DiffValidationError {
  constructor(message, details = {}) {
    super(message || 'Diff modifies files outside finding scope', details);
    this.name = 'OutOfScopeDiffError';
  }
}

// ----------------------------------------------------------------------------
// 2. Path Normalization & Workspace Confinement Validator
// ----------------------------------------------------------------------------

/**
 * Normalizes a raw diff file path string.
 * Strips leading a/ or b/ markers, tabbed metadata, quotes, and converts backslashes to forward slashes.
 *
 * @param {string} rawPath
 * @returns {string} Normalized path string
 */
function normalizeDiffFilePath(rawPath) {
  if (typeof rawPath !== 'string') return '';
  let clean = rawPath.trim();
  // Strip quotes if present
  if ((clean.startsWith('"') && clean.endsWith('"')) || (clean.startsWith("'") && clean.endsWith("'"))) {
    clean = clean.slice(1, -1);
  }
  // Strip trailing tab comments/timestamps (e.g. "path/to/file\t2026-10-31 12:00:00")
  clean = clean.split('\t')[0].trim();
  // Strip leading a/ or b/
  clean = clean.replace(/^[ab]\//, '');
  // Normalize backslashes
  clean = clean.replace(/\\/g, '/');
  return clean;
}

/**
 * Validates a relative file path against a repository workspace.
 * Detects absolute paths, null bytes, .. traversal, and symlink escapes.
 *
 * @param {string} relativeFilePath - Relative path within repository
 * @param {string} [workspacePath] - Optional workspace root on disk
 * @param {Object} [options={}]
 * @returns {{ valid: boolean, normalizedPath?: string, resolvedPath?: string, error?: string, code?: string }}
 */
function validateWorkspacePath(relativeFilePath, workspacePath = '', options = {}) {
  if (typeof relativeFilePath !== 'string' || !relativeFilePath.trim()) {
    return { valid: false, code: 'EMPTY_PATH', error: 'File path cannot be empty' };
  }

  const raw = relativeFilePath.trim();

  // 1. Prohibit null bytes
  if (raw.includes('\0')) {
    return { valid: false, code: 'NULL_BYTE', error: `File path contains prohibited null byte: "${raw}"` };
  }

  // 2. Reject absolute paths
  if (raw.startsWith('/') || raw.startsWith('\\') || /^[A-Za-z]:[\\/]/.test(raw) || /^\\\\[^\\]+\\/.test(raw)) {
    return { valid: false, code: 'ABSOLUTE_PATH', error: `Absolute paths are not permitted: "${raw}"` };
  }

  // 3. Reject special path expansions (~, env vars)
  if (raw.startsWith('~') || /^\$[A-Za-z_]/.test(raw) || /^%[A-Za-z_]+%/.test(raw)) {
    return { valid: false, code: 'SPECIAL_PATH_PREFIX', error: `Special path expansion prefix not permitted: "${raw}"` };
  }

  // 3b. Check percent-encoded traversal & null bytes
  let decoded = raw;
  try {
    while (decoded.includes('%')) {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    }
  } catch {
    return { valid: false, code: 'PATH_TRAVERSAL', error: `Malformed percent-encoded path: "${raw}"` };
  }

  if (decoded.includes('\0')) {
    return { valid: false, code: 'NULL_BYTE', error: `File path contains prohibited null byte: "${raw}"` };
  }

  if (decoded.startsWith('/') || decoded.startsWith('\\') || /^[A-Za-z]:[\\/]/.test(decoded) || /^\\\\[^\\]+\\/.test(decoded)) {
    return { valid: false, code: 'ABSOLUTE_PATH', error: `Absolute paths are not permitted: "${raw}"` };
  }

  const decodedNormalized = normalizeDiffFilePath(decoded);
  const decodedSegments = decodedNormalized.split('/');
  if (decodedSegments.includes('..') || decodedSegments.some((s) => s === '..' || /^\.\.[/\\]/.test(s))) {
    return { valid: false, code: 'PATH_TRAVERSAL', error: `Path traversal ("..") is not permitted: "${raw}"` };
  }

  const normalized = normalizeDiffFilePath(raw);

  // 4. Reject directory traversal sequences
  const segments = normalized.split('/');
  if (segments.includes('..') || segments.some(s => s === '..' || /^\.\.[/\\]/.test(s))) {
    return { valid: false, code: 'PATH_TRAVERSAL', error: `Path traversal ("..") is not permitted: "${raw}"` };
  }

  // If no workspace path is provided on disk, path-level checks are sufficient
  if (!workspacePath || typeof workspacePath !== 'string') {
    return { valid: true, normalizedPath: normalized };
  }

  // 5. Workspace Canonicalization & Confinement
  let resolvedWorkspace;
  let realWorkspaceRoot;
  try {
    resolvedWorkspace = path.resolve(workspacePath);
    if (fs.existsSync(resolvedWorkspace)) {
      realWorkspaceRoot = fs.realpathSync(resolvedWorkspace);
    } else {
      realWorkspaceRoot = resolvedWorkspace;
    }
  } catch (err) {
    return { valid: false, code: 'INVALID_WORKSPACE', error: `Failed to resolve workspace path: ${err.message}` };
  }

  const resolvedTarget = path.resolve(resolvedWorkspace, normalized);

  const wsPrefix = resolvedWorkspace.endsWith(path.sep) ? resolvedWorkspace : resolvedWorkspace + path.sep;
  if (!resolvedTarget.startsWith(wsPrefix) && resolvedTarget !== resolvedWorkspace) {
    return {
      valid: false,
      code: 'PATH_ESCAPES_WORKSPACE',
      error: `Target path "${raw}" escapes workspace boundary "${workspacePath}"`
    };
  }

  // 6. Symlink Escape Verification
  try {
    if (fs.existsSync(resolvedTarget)) {
      const realTarget = fs.realpathSync(resolvedTarget);
      const realWsPrefix = realWorkspaceRoot.endsWith(path.sep) ? realWorkspaceRoot : realWorkspaceRoot + path.sep;
      if (!realTarget.startsWith(realWsPrefix) && realTarget !== realWorkspaceRoot) {
        return {
          valid: false,
          code: 'SYMLINK_WORKSPACE_ESCAPE',
          error: `Target file "${raw}" resolves via symlink outside workspace to "${realTarget}"`
        };
      }
    } else {
      // For paths that do not yet exist, inspect all existing parent directories
      const parts = normalized.split('/').filter(Boolean);
      let curr = resolvedWorkspace;
      for (let i = 0; i < parts.length; i++) {
        curr = path.join(curr, parts[i]);
        if (fs.existsSync(curr)) {
          const realCurr = fs.realpathSync(curr);
          const realWsPrefix = realWorkspaceRoot.endsWith(path.sep) ? realWorkspaceRoot : realWorkspaceRoot + path.sep;
          if (!realCurr.startsWith(realWsPrefix) && realCurr !== realWorkspaceRoot) {
            return {
              valid: false,
              code: 'SYMLINK_WORKSPACE_ESCAPE',
              error: `Path component "${parts.slice(0, i + 1).join('/')}" resolves via symlink outside workspace to "${realCurr}"`
            };
          }
        } else {
          break;
        }
      }
    }
  } catch (err) {
    return {
      valid: false,
      code: 'SYMLINK_INSPECTION_FAILED',
      error: `Failed to verify symlink safety for path "${raw}": ${err.message}`
    };
  }

  return {
    valid: true,
    normalizedPath: normalized,
    resolvedPath: resolvedTarget
  };
}

// ----------------------------------------------------------------------------
// 3. Unified Diff Structure & Path Validator
// ----------------------------------------------------------------------------

/**
 * Validates unified diff structure and changed-file paths independently of AI claims.
 *
 * @param {string} diffString - Unified diff text content
 * @param {Object} [options={}] - Validation options
 * @param {string} [options.workspacePath] - Allowed workspace directory root
 * @param {string[]} [options.declaredChangedFiles] - Declared changedFiles from proposal
 * @param {Object} [options.finding] - Associated finding to verify target scope
 * @param {string[]} [options.allowedFiles] - Explicit allowlist of permissible file paths
 * @param {boolean} [options.allowCreation=false] - Whether file creation (--- /dev/null) is permitted
 * @param {boolean} [options.allowDeletion=false] - Whether file deletion (+++ /dev/null) is permitted
 * @param {boolean} [options.allowRename=false] - Whether file renames are permitted
 * @param {boolean} [options.allowBinary=false] - Whether binary diffs are permitted
 * @param {boolean} [options.allowMultiFile=true] - Whether diffs modifying multiple files are permitted
 * @returns {Object} Structured validation result
 */
function validateDiffAndPaths(diffString, options = {}) {
  const errors = [];
  const errorDetails = [];
  const rejectedPaths = new Set();
  const detectedFilesSet = new Set();
  const fileDetails = [];

  const addError = (code, message, meta = {}) => {
    errors.push(message);
    errorDetails.push({ code, message, ...meta });
    if (meta.file) {
      rejectedPaths.add(meta.file);
    }
  };

  // 1. Initial string checks
  if (typeof diffString !== 'string' || !diffString.trim()) {
    addError('EMPTY_DIFF', 'Diff content cannot be empty');
    return {
      valid: false,
      errors,
      errorDetails,
      detectedFiles: [],
      changedFiles: [],
      rejectedPaths: [],
      hunksCount: 0,
      stats: { additions: 0, deletions: 0, filesCount: 0 },
      fileDetails: []
    };
  }

  const cleanDiff = diffString.replace(/\r\n/g, '\n').replace(/\n$/, '');
  const lines = cleanDiff.split('\n');
  let totalHunks = 0;
  let totalAdditions = 0;
  let totalDeletions = 0;

  // File patch state machine
  let currentFilePatch = null;
  let currentHunk = null;

  const completeCurrentHunk = (lineIndex) => {
    if (!currentHunk) return;

    // Check line count consistency
    if (currentHunk.actualOld !== currentHunk.expectedOld || currentHunk.actualNew !== currentHunk.expectedNew) {
      addError(
        'INCONSISTENT_LINE_COUNT',
        `Inconsistent line count in hunk at line ${currentHunk.headerLineNum}: declared -${currentHunk.expectedOld},+${currentHunk.expectedNew} but found -${currentHunk.actualOld},+${currentHunk.actualNew}`,
        { line: currentHunk.headerLineNum, file: currentFilePatch?.file }
      );
    }

    if (currentFilePatch) {
      currentFilePatch.hunks.push(currentHunk);
      currentFilePatch.additions += currentHunk.additions;
      currentFilePatch.deletions += currentHunk.deletions;
    }
    totalHunks++;
    totalAdditions += currentHunk.additions;
    totalDeletions += currentHunk.deletions;
    currentHunk = null;
  };

  const completeCurrentFilePatch = (lineIndex) => {
    completeCurrentHunk(lineIndex);

    if (!currentFilePatch) return;

    if (currentFilePatch.hunks.length === 0) {
      addError(
        'NO_HUNKS_IN_FILE',
        `Unified diff for file "${currentFilePatch.file || 'unknown'}" contains no hunk headers (@@)`,
        { file: currentFilePatch.file }
      );
    } else if (currentFilePatch.additions + currentFilePatch.deletions === 0) {
      addError(
        'NO_MODIFICATIONS',
        `Diff for file "${currentFilePatch.file}" contains zero additions or deletions`,
        { file: currentFilePatch.file }
      );
    }

    fileDetails.push({
      file: currentFilePatch.file,
      oldFile: currentFilePatch.oldFile,
      newFile: currentFilePatch.newFile,
      hunksCount: currentFilePatch.hunks.length,
      additions: currentFilePatch.additions,
      deletions: currentFilePatch.deletions
    });

    if (currentFilePatch.file) {
      detectedFilesSet.add(currentFilePatch.file);
    }

    currentFilePatch = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Check for binary diffs
    if (line.startsWith('Binary files ') || line.startsWith('GIT binary patch')) {
      if (!options.allowBinary) {
        addError('UNSUPPORTED_BINARY_DIFF', 'Binary diffs are not supported by patch contract', { line: lineNum });
      }
      continue;
    }

    // Check for git extended headers indicating file lifecycle changes
    if (line.startsWith('new file mode')) {
      if (!options.allowCreation) {
        addError('UNSUPPORTED_FILE_CREATION', 'File creation is not supported by patch contract', { line: lineNum });
      }
      continue;
    }

    if (line.startsWith('deleted file mode')) {
      if (!options.allowDeletion) {
        addError('UNSUPPORTED_FILE_DELETION', 'File deletion is not supported by patch contract', { line: lineNum });
      }
      continue;
    }

    if (line.startsWith('rename from ') || line.startsWith('rename to ') || line.startsWith('similarity index ')) {
      if (!options.allowRename) {
        addError('UNSUPPORTED_FILE_RENAME', 'File rename operations are not supported by patch contract', { line: lineNum });
      }
      continue;
    }

    // Git diff header starting a new file
    if (line.startsWith('diff --git ')) {
      if (currentFilePatch) {
        completeCurrentFilePatch(lineNum);
      }
      currentFilePatch = {
        diffHeader: line,
        oldFile: null,
        newFile: null,
        file: null,
        hunks: [],
        additions: 0,
        deletions: 0
      };
      continue;
    }

    // Standard old file header
    if (line.startsWith('--- ')) {
      // If we already had an active file patch (with hunks, active hunk, or oldFile), complete it
      if (currentFilePatch && (currentHunk !== null || currentFilePatch.hunks.length > 0 || currentFilePatch.oldFile !== null)) {
        completeCurrentFilePatch(lineNum);
      }
      if (!currentFilePatch) {
        currentFilePatch = {
          diffHeader: null,
          oldFile: null,
          newFile: null,
          file: null,
          hunks: [],
          additions: 0,
          deletions: 0
        };
      }

      const match = line.match(/^---\s+(?:[ab]\/)?(.+?)(?:\t.*)?$/);
      const rawOld = match ? match[1].trim() : line.substring(4).trim();
      currentFilePatch.oldFile = rawOld;

      if (rawOld === '/dev/null') {
        if (!options.allowCreation) {
          addError('UNSUPPORTED_FILE_CREATION', 'File creation (source is /dev/null) is not supported by patch contract', { line: lineNum });
        }
      } else {
        const pathCheck = validateWorkspacePath(rawOld, options.workspacePath, options);
        if (!pathCheck.valid) {
          addError(pathCheck.code || 'INVALID_PATH', pathCheck.error || `Invalid old file path: "${rawOld}"`, { line: lineNum, file: rawOld });
        }
      }
      continue;
    }

    // Standard new file header
    if (line.startsWith('+++ ')) {
      if (!currentFilePatch) {
        currentFilePatch = {
          diffHeader: null,
          oldFile: null,
          newFile: null,
          file: null,
          hunks: [],
          additions: 0,
          deletions: 0
        };
      }

      const match = line.match(/^\+\+\+\s+(?:[ab]\/)?(.+?)(?:\t.*)?$/);
      const rawNew = match ? match[1].trim() : line.substring(4).trim();
      currentFilePatch.newFile = rawNew;

      if (rawNew === '/dev/null') {
        if (!options.allowDeletion) {
          addError('UNSUPPORTED_FILE_DELETION', 'File deletion (target is /dev/null) is not supported by patch contract', { line: lineNum });
        }
      } else {
        const pathCheck = validateWorkspacePath(rawNew, options.workspacePath, options);
        if (!pathCheck.valid) {
          addError(pathCheck.code || 'INVALID_PATH', pathCheck.error || `Invalid new file path: "${rawNew}"`, { line: lineNum, file: rawNew });
        }
      }

      // Resolve primary changed file name
      const targetRaw = rawNew !== '/dev/null' ? rawNew : currentFilePatch.oldFile;
      const normalizedTarget = normalizeDiffFilePath(targetRaw);
      currentFilePatch.file = normalizedTarget;

      // Check for file renaming between oldFile and newFile
      if (currentFilePatch.oldFile && currentFilePatch.newFile && currentFilePatch.oldFile !== '/dev/null' && currentFilePatch.newFile !== '/dev/null') {
        const normOld = normalizeDiffFilePath(currentFilePatch.oldFile);
        const normNew = normalizeDiffFilePath(currentFilePatch.newFile);
        if (normOld !== normNew && !options.allowRename) {
          addError(
            'UNSUPPORTED_FILE_RENAME',
            `File rename from "${normOld}" to "${normNew}" is not supported by patch contract`,
            { line: lineNum, file: normNew }
          );
        }
      }
      continue;
    }

    // Hunk header
    if (line.startsWith('@@')) {
      completeCurrentHunk(lineNum);

      if (!currentFilePatch) {
        addError('ORPHAN_HUNK', `Hunk header found without preceding file headers at line ${lineNum}`, { line: lineNum });
        continue;
      }

      const hunkMatch = line.match(/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$/);
      if (!hunkMatch) {
        addError('MALFORMED_HUNK_HEADER', `Malformed hunk header at line ${lineNum}: "${line}"`, { line: lineNum });
        continue;
      }

      const oldStart = parseInt(hunkMatch[1], 10);
      const expectedOld = hunkMatch[2] !== undefined ? parseInt(hunkMatch[2], 10) : 1;
      const newStart = parseInt(hunkMatch[3], 10);
      const expectedNew = hunkMatch[4] !== undefined ? parseInt(hunkMatch[4], 10) : 1;

      currentHunk = {
        header: line,
        headerLineNum: lineNum,
        oldStart,
        expectedOld,
        newStart,
        expectedNew,
        actualOld: 0,
        actualNew: 0,
        additions: 0,
        deletions: 0
      };
      continue;
    }

    // Lines inside a hunk
    if (currentHunk) {
      if (line.startsWith(' ')) {
        currentHunk.actualOld++;
        currentHunk.actualNew++;
      } else if (line.startsWith('-')) {
        currentHunk.actualOld++;
        currentHunk.deletions++;
      } else if (line.startsWith('+')) {
        currentHunk.actualNew++;
        currentHunk.additions++;
      } else if (line.startsWith('\\')) {
        // e.g. \ No newline at end of file - does not count toward old/new line counts
      } else if (line.trim() === '') {
        // Empty lines inside hunk count as space context lines in standard unified diff
        currentHunk.actualOld++;
        currentHunk.actualNew++;
      } else {
        addError(
          'MALFORMED_HUNK_LINE',
          `Invalid diff hunk line prefix at line ${lineNum}: "${line[0]}". Must be '+', '-', ' ', or '\\'`,
          { line: lineNum }
        );
      }
    }
  }

  // Complete any active hunk and file patch at EOF
  completeCurrentFilePatch(lines.length);

  // If no file patches were detected at all
  if (fileDetails.length === 0) {
    addError('NO_FILE_HEADERS', 'Diff does not contain valid unified diff file headers (--- and +++)');
  }

  const detectedFiles = Array.from(detectedFilesSet);

  // 2. Multi-file boundary constraint check
  if (detectedFiles.length > 1 && options.allowMultiFile === false) {
    addError(
      'UNSUPPORTED_MULTI_FILE_DIFF',
      `Diff modifies multiple files (${detectedFiles.length}) but multi-file diffs are not permitted: ${detectedFiles.join(', ')}`
    );
  }

  // 3. Match against declared changedFiles
  if (Array.isArray(options.declaredChangedFiles)) {
    const declaredNormalized = options.declaredChangedFiles.map(normalizeDiffFilePath).filter(Boolean);
    const declaredSet = new Set(declaredNormalized);

    // Actual diff files must match declared files
    for (const f of detectedFiles) {
      if (!declaredSet.has(f)) {
        addError(
          'DECLARED_FILES_MISMATCH',
          `Diff modifies file "${f}" not declared in proposal changedFiles: [${declaredNormalized.join(', ')}]`,
          { file: f }
        );
      }
    }

    for (const d of declaredNormalized) {
      if (!detectedFilesSet.has(d)) {
        addError(
          'DECLARED_FILES_MISMATCH',
          `Proposal declared changedFile "${d}" is not modified in the diff`,
          { file: d }
        );
      }
    }
  }

  // 4. Match against finding scope
  const targetScope = [];
  if (options.finding && typeof options.finding === 'object') {
    const findingPath = options.finding.filePath || options.finding.path;
    if (findingPath) {
      targetScope.push(normalizeDiffFilePath(findingPath));
    }
  }
  if (Array.isArray(options.allowedFiles)) {
    for (const af of options.allowedFiles) {
      targetScope.push(normalizeDiffFilePath(af));
    }
  }

  if (targetScope.length > 0) {
    for (const f of detectedFiles) {
      if (!targetScope.includes(f)) {
        addError(
          'OUT_OF_SCOPE_MODIFICATION',
          `Patch modifies file "${f}" outside permitted finding scope: [${targetScope.join(', ')}]`,
          { file: f }
        );
      }
    }
  }

  const isValid = errors.length === 0;

  return {
    valid: isValid,
    errors,
    errorDetails,
    detectedFiles,
    changedFiles: detectedFiles,
    rejectedPaths: Array.from(rejectedPaths),
    hunksCount: totalHunks,
    stats: {
      additions: totalAdditions,
      deletions: totalDeletions,
      filesCount: detectedFiles.length
    },
    fileDetails
  };
}

/**
 * Asserts that a diff is valid, throwing a DiffValidationError if validation fails.
 *
 * @param {string} diffString
 * @param {Object} [options={}]
 * @returns {Object} Structured validation result
 */
function assertValidDiff(diffString, options = {}) {
  const result = validateDiffAndPaths(diffString, options);
  if (!result.valid) {
    const firstErr = result.errors[0] || 'Unified diff validation failed';
    throw new DiffValidationError(firstErr, result);
  }
  return result;
}

module.exports = {
  DiffValidationError,
  WorkspacePathEscapeError,
  SymlinkEscapeError,
  MalformedDiffError,
  InconsistentLineCountError,
  DeclaredFilesMismatchError,
  OutOfScopeDiffError,

  normalizeDiffFilePath,
  validateWorkspacePath,
  validateDiffAndPaths,
  assertValidDiff
};