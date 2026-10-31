/**
 * VULNEX Syntax-Aware Unified Diff Parser & Validator
 *
 * Implements:
 * - Deterministic parsing of unified diffs (hunk headers @@, additions +, deletions -, context)
 * - Line numbering for both original (old) and modified (new) sides
 * - Accurate addition/deletion statistics computation
 * - Safety validation: detects path traversals (..) and malformed hunk lines
 * - Pure JavaScript for seamless node --test and browser execution
 */

/**
 * Validate whether a raw path is safe and strictly relative before normalization
 * @param {string} rawPath
 * @returns {{ valid: boolean, error?: string }}
 */
export function validatePathSafety(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') {
    return { valid: false, error: 'File path cannot be empty' };
  }

  const raw = rawPath.trim().replace(/^["']|["']$/g, '');

  if (raw === '/dev/null') {
    return { valid: true };
  }

  // 1. Prohibit null bytes
  if (raw.includes('\0')) {
    return { valid: false, error: `File path contains prohibited null byte: "${raw}"` };
  }

  // 2. Reject absolute paths
  if (raw.startsWith('/') || raw.startsWith('\\') || /^[A-Za-z]:[\\/]/.test(raw) || /^\\\\[^\\]+\\/.test(raw)) {
    return { valid: false, error: `Absolute paths are not permitted: "${raw}"` };
  }

  // 3. Normalize git prefixes a/, b/, i/, w/
  let normalized = raw;
  if (/^[abwi][\\/]/.test(normalized)) {
    normalized = normalized.substring(2);
  }
  normalized = normalized.replace(/\\/g, '/');

  // 4. Reject directory traversal sequences
  const segments = normalized.split('/');
  if (segments.includes('..') || segments.some(s => s === '..' || /^\.\.[/\\]/.test(s))) {
    return { valid: false, error: `Path traversal ("..") is not permitted: "${raw}"` };
  }

  return { valid: true, normalizedPath: normalized };
}

/**
 * Clean Git/diff prefix (a/, b/) or host paths
 * @param {string} rawPath
 * @returns {string} Normalized relative path
 */
export function normalizeDiffPath(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') return '';
  let clean = rawPath.trim().replace(/^["']|["']$/g, '');
  if (clean === '/dev/null') return clean;
  if (/^[abwi][\\/]/.test(clean)) {
    clean = clean.substring(2);
  }
  return clean.replace(/\\/g, '/').replace(/^\/+/, '');
}

/**
 * Validate that a file path in a diff is safe and strictly relative
 * @param {string} filePath
 * @returns {boolean}
 */
export function isSafeFilePath(filePath) {
  return validatePathSafety(filePath).valid;
}

/**
 * Parse unified diff hunk header: @@ -oldStart,oldLines +newStart,newLines @@ [optional section]
 * @param {string} headerLine
 * @returns {object|null}
 */
export function parseHunkHeader(headerLine) {
  const match = headerLine.match(/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(?:(.*))?$/);
  if (!match) return null;

  return {
    oldStart: parseInt(match[1], 10),
    oldLines: match[2] !== undefined ? parseInt(match[2], 10) : 1,
    newStart: parseInt(match[3], 10),
    newLines: match[4] !== undefined ? parseInt(match[4], 10) : 1,
    section: (match[5] || '').trim(),
    raw: headerLine
  };
}

/**
 * Parse full unified diff string into structured representation
 * @param {string} diffText
 * @returns {{
 *   valid: boolean,
 *   files: Array<{ oldFile: string, newFile: string }>,
 *   hunks: Array<object>,
 *   stats: { additions: number, deletions: number, totalChanges: number, filesCount: number },
 *   error?: string
 * }}
 */
export function parseUnifiedDiff(diffText) {
  if (!diffText || typeof diffText !== 'string' || !diffText.trim()) {
    return {
      valid: false,
      files: [],
      hunks: [],
      stats: { additions: 0, deletions: 0, totalChanges: 0, filesCount: 0 },
      error: 'Empty or missing diff content'
    };
  }

  const rawLines = diffText.replace(/\r\n/g, '\n').split('\n');
  const files = [];
  const hunks = [];
  let additions = 0;
  let deletions = 0;

  let currentOldRaw = null;
    let currentOldFile = null;
  let currentNewFile = null;
  let currentHunk = null;
  let currentOldLine = 0;
  let currentNewLine = 0;

  for (let i = 0; i < rawLines.length; i++) {
    const line = rawLines[i];

    // Check for "--- a/path"
    if (line.startsWith('--- ')) {
      currentOldRaw = line.substring(4).split('\t')[0].trim();
      currentOldFile = normalizeDiffPath(currentOldRaw);
      continue;
    }

    // Check for "+++ b/path"
    if (line.startsWith('+++ ')) {
      const currentNewRaw = line.substring(4).split('\t')[0].trim();
      currentNewFile = normalizeDiffPath(currentNewRaw);

      if (currentOldRaw && currentNewRaw) {
        // Check safety of both headers
        const oldCheck = validatePathSafety(currentOldRaw);
        if (!oldCheck.valid) {
          return {
            valid: false,
            files,
            hunks,
            stats: { additions, deletions, totalChanges: additions + deletions, filesCount: files.length },
            error: `Unsafe file path detected in diff: "${currentOldRaw}"`
          };
        }
        const newCheck = validatePathSafety(currentNewRaw);
        if (!newCheck.valid) {
          return {
            valid: false,
            files,
            hunks,
            stats: { additions, deletions, totalChanges: additions + deletions, filesCount: files.length },
            error: `Unsafe file path detected in diff: "${currentNewRaw}"`
          };
        }

        files.push({
          oldFile: currentOldFile,
          newFile: currentNewFile
        });
      }
      continue;
    }

    // Check for hunk marker "@@ -x,y +x,y @@"
    if (line.startsWith('@@ ')) {
      const parsedHunk = parseHunkHeader(line);
      if (!parsedHunk) {
        return {
          valid: false,
          files,
          hunks,
          stats: { additions, deletions, totalChanges: additions + deletions, filesCount: files.length },
          error: `Malformed hunk header at line ${i + 1}: ${line}`
        };
      }

      currentHunk = {
        ...parsedHunk,
        file: currentNewFile || currentOldFile || 'unknown',
        lines: []
      };
      hunks.push(currentHunk);
      currentOldLine = parsedHunk.oldStart;
      currentNewLine = parsedHunk.newStart;
      continue;
    }

    // If we are inside a hunk, parse diff lines
    if (currentHunk) {
      if (line.startsWith('+')) {
        additions++;
        currentHunk.lines.push({
          type: 'add',
          prefix: '+',
          content: line.substring(1),
          oldLineNumber: null,
          newLineNumber: currentNewLine++,
          raw: line
        });
      } else if (line.startsWith('-')) {
        deletions++;
        currentHunk.lines.push({
          type: 'delete',
          prefix: '-',
          content: line.substring(1),
          oldLineNumber: currentOldLine++,
          newLineNumber: null,
          raw: line
        });
      } else if (line.startsWith(' ') || line === '') {
        currentHunk.lines.push({
          type: 'context',
          prefix: ' ',
          content: line.startsWith(' ') ? line.substring(1) : '',
          oldLineNumber: currentOldLine++,
          newLineNumber: currentNewLine++,
          raw: line
        });
      } else if (line.startsWith('\\')) {
        // e.g. "\ No newline at end of file"
        currentHunk.lines.push({
          type: 'meta',
          prefix: '\\',
          content: line.substring(1).trim(),
          oldLineNumber: null,
          newLineNumber: null,
          raw: line
        });
      }
    }
  }

  // Structural sanity validation
  if (files.length === 0 && hunks.length === 0) {
    return {
      valid: false,
      files: [],
      hunks: [],
      stats: { additions: 0, deletions: 0, totalChanges: 0, filesCount: 0 },
      error: 'Diff lacks valid unified diff headers (--- / +++) and hunks (@@)'
    };
  }

  if (hunks.length === 0) {
    return {
      valid: false,
      files,
      hunks: [],
      stats: { additions: 0, deletions: 0, totalChanges: 0, filesCount: files.length },
      error: 'Diff contains file headers but no hunks'
    };
  }

  if (additions === 0 && deletions === 0) {
    return {
      valid: false,
      files,
      hunks,
      stats: { additions: 0, deletions: 0, totalChanges: 0, filesCount: files.length },
      error: 'Diff contains zero additions and zero deletions'
    };
  }

  return {
    valid: true,
    files,
    hunks,
    stats: {
      additions,
      deletions,
      totalChanges: additions + deletions,
      filesCount: files.length
    }
  };
}

/**
 * Validate unified diff against scope (e.g. expected finding file)
 * @param {string} diffText
 * @param {string} expectedFilePath
 * @returns {{ valid: boolean, error?: string, stats?: object }}
 */
export function validateDiffScope(diffText, expectedFilePath) {
  const result = parseUnifiedDiff(diffText);
  if (!result.valid) {
    return { valid: false, error: result.error, stats: result.stats };
  }

  if (expectedFilePath) {
    const normalizedExpected = normalizeDiffPath(expectedFilePath);
    for (const f of result.files) {
      const matchOld = f.oldFile === normalizedExpected || f.oldFile === '/dev/null';
      const matchNew = f.newFile === normalizedExpected || f.newFile === '/dev/null';
      if (!matchOld && !matchNew) {
        return {
          valid: false,
          error: `Diff modifies out-of-scope file "${f.newFile || f.oldFile}". Expected: "${normalizedExpected}"`,
          stats: result.stats
        };
      }
    }
  }

  return { valid: true, stats: result.stats, files: result.files };
}
