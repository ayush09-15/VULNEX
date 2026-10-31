const crypto = require('crypto');
const path = require('path');
const { validateCommonFinding, CommonFindingSchema } = require('../validators/commonFinding.schema');

/**
 * ============================================================================
 * VULNEX Common Finding Normalizer
 *
 * Converts disparate scanner outputs (such as Semgrep parser results,
 * custom SAST pattern findings, and other security linters) into the canonical
 * VULNEX Common Finding Schema.
 *
 * Required Normalized Fields:
 * - rule: Rule ID / identifier
 * - path: Normalized relative workspace file path
 * - startLine: 1-indexed start line integer (>= 1)
 * - endLine: 1-indexed end line integer (>= startLine)
 * - message: Finding description / message
 * - evidence: Code snippet or matched evidence
 * - severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
 * - confidence: HIGH | MEDIUM | LOW | UNKNOWN
 * - fingerprint: Deterministic, stable 64-character SHA-256 hex string
 * ============================================================================
 */
class FindingNormalizer {
  constructor() {
    this.validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    this.validConfidences = ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  }

  /**
   * Normalize code evidence into a consistent, stable string representation.
   * Strips transient formatting differences and collapses whitespace.
   *
   * @param {string|Object|any} rawEvidence
   * @returns {string}
   */
  normalizeEvidence(rawEvidence) {
    if (!rawEvidence) return '';

    let text = '';
    if (typeof rawEvidence === 'string') {
      text = rawEvidence;
    } else if (typeof rawEvidence === 'object') {
      text = rawEvidence.codeSnippet || rawEvidence.snippet || rawEvidence.lines || JSON.stringify(rawEvidence);
    } else {
      text = String(rawEvidence);
    }

    return text
      .replace(/\r\n/g, '\n')
      .split('\n')
      .map(line => line.trim())
      .filter(Boolean)
      .join(' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Normalize finding message into a stable string representation.
   * Scrubs dynamic line numbers and transient character offsets.
   *
   * @param {string|any} rawMessage
   * @returns {string}
   */
  normalizeMessage(rawMessage) {
    if (!rawMessage) return '';
    return String(rawMessage)
      .replace(/\bline\s+\d+\b/gi, '')
      .replace(/:\d+:\d+/g, '')
      .replace(/:\d+/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Generate a stable, deterministic SHA-256 fingerprint for a finding.
   *
   * Stability Invariants:
   * 1. Deterministic across repeated runs.
   * 2. Independent of volatile line numbers (line shifts due to unrelated edits do not change fingerprint).
   * 3. Built from stable issue identity: normalized rule ID, normalized file path,
   *    normalized code evidence, and normalized message.
   * 4. Distinct vulnerabilities sharing a file or rule retain distinct fingerprints.
   *
   * @param {Object|string} paramOrRule Finding object or rule ID string
   * @param {string} [path] File path (if first arg is rule string)
   * @param {string|Object} [evidence=''] Evidence (if first arg is rule string)
   * @param {string} [message=''] Message (if first arg is rule string)
   * @param {Object} [metadata={}] Metadata (if first arg is rule string)
   * @returns {string} 64-character lowercase hex SHA-256 string
   */
  generateFingerprint(paramOrRule, path = '', evidence = '', message = '', metadata = {}) {
    let ruleVal;
    let pathVal;
    let evidenceVal;
    let messageVal;

    if (paramOrRule && typeof paramOrRule === 'object') {
      ruleVal = paramOrRule.rule || paramOrRule.ruleId || paramOrRule.check_id;
      pathVal = paramOrRule.path || paramOrRule.filePath || paramOrRule.file;
      evidenceVal = paramOrRule.evidence !== undefined
        ? paramOrRule.evidence
        : (paramOrRule.codeSnippet || paramOrRule.extra?.lines || paramOrRule.snippet);
      messageVal = paramOrRule.message !== undefined
        ? paramOrRule.message
        : (paramOrRule.extra?.message || paramOrRule.description);
    } else {
      ruleVal = paramOrRule;
      pathVal = path;
      evidenceVal = evidence;
      messageVal = message;
    }

    const normRule = String(ruleVal || '').trim().toLowerCase();
    const normPath = this.normalizePath(pathVal || '');
    const normEvidence = this.normalizeEvidence(evidenceVal);
    const normMessage = this.normalizeMessage(messageVal);

    const components = [normRule, normPath];

    if (normEvidence) {
      components.push(normEvidence);
    }
    if (normMessage) {
      components.push(normMessage);
    }

    const payload = components.join('::');
    return crypto.createHash('sha256').update(payload).digest('hex');
  }

  /**
   * Deterministically map scanner-specific severity values to the existing VULNEX severity convention.
   *
   * @param {string|number|any} rawSeverity
   * @param {Object} [metadata={}]
   * @returns {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO'}
   */
  mapSeverity(rawSeverity = 'INFO', metadata = {}) {
    const meta = metadata && typeof metadata === 'object' ? metadata : {};
    const norm = String(rawSeverity || '').trim().toUpperCase();

    // Check impact in metadata first if present
    const impact = String(meta.impact || '').toUpperCase();
    if (impact === 'CRITICAL') {
      return 'CRITICAL';
    }

    // Check numeric security score if present in metadata
    const numericScore = parseFloat(meta['security-severity'] || meta.cvss || meta.score);
    if (!Number.isNaN(numericScore)) {
      if (numericScore >= 9.0) return 'CRITICAL';
      if (numericScore >= 7.0) return 'HIGH';
      if (numericScore >= 4.0) return 'MEDIUM';
      if (numericScore > 0.0) return 'LOW';
    }

    switch (norm) {
      case 'CRITICAL':
      case 'FATAL':
      case 'BLOCKER':
        return 'CRITICAL';

      case 'HIGH':
      case 'ERROR':
      case 'MAJOR':
        return 'HIGH';

      case 'MEDIUM':
      case 'WARNING':
      case 'WARN':
      case 'MODERATE':
        return 'MEDIUM';

      case 'LOW':
      case 'MINOR':
        return 'LOW';

      case 'INFO':
      case 'INFORMATIONAL':
      case 'NOTE':
      case 'NOTICE':
      case 'EXPERIMENT':
      case 'INVENTORY':
        return 'INFO';

      default:
        return 'INFO';
    }
  }

  /**
   * Assign confidence using available scanner metadata or an explicitly documented deterministic mapping.
   *
   * CRITICAL REQUIREMENT: NEVER INVENT CONFIDENCE.
   * If scanner provides a recognized confidence tier (HIGH, MEDIUM, LOW), normalize and preserve it.
   * If confidence is omitted, empty, or unrecognized, map it deterministically to 'UNKNOWN'.
   * Never default to HIGH or MEDIUM when unverified.
   *
   * @param {Object} [metadata={}] Scanner metadata object
   * @param {string} [explicitConfidence=null] Explicit confidence from finding record
   * @returns {'HIGH'|'MEDIUM'|'LOW'|'UNKNOWN'}
   */
  mapConfidence(metadata = {}, explicitConfidence = null) {
    const meta = metadata && typeof metadata === 'object' ? metadata : {};

    // 1. Check explicit confidence property on finding record
    if (explicitConfidence !== null && explicitConfidence !== undefined) {
      const explicitNorm = String(explicitConfidence).trim().toUpperCase();
      if (this.validConfidences.includes(explicitNorm)) {
        return explicitNorm;
      }
    }

    // 2. Check metadata confidence (e.g. Semgrep extra.metadata.confidence)
    if (meta.confidence !== null && meta.confidence !== undefined) {
      const metaNorm = String(meta.confidence).trim().toUpperCase();
      if (['HIGH', 'MEDIUM', 'LOW'].includes(metaNorm)) {
        return metaNorm;
      }
      if (metaNorm === 'UNKNOWN') {
        return 'UNKNOWN';
      }
    }

    // 3. Fallback deterministic mapping when unprovided: UNKNOWN
    return 'UNKNOWN';
  }

  /**
   * Safely normalize relative file path against workspace root
   * Ensures relative forward-slash paths and strips redundant prefixes
   *
   * @param {string} rawPath Raw file path
   * @param {string} [workspaceRoot=''] Root workspace path to make relative against
   * @returns {string} Normalized relative path
   */
  normalizePath(rawPath, workspaceRoot = '') {
    if (typeof rawPath !== 'string') return '';

    let normalized = rawPath.trim();

    // If absolute and contains workspaceRoot, make relative
    if (workspaceRoot && normalized.startsWith(workspaceRoot)) {
      normalized = path.relative(workspaceRoot, normalized);
    }

    // Normalize Windows backslashes to standard forward slashes
    normalized = normalized.replace(/\\/g, '/');

    // Strip Windows drive letters (e.g. C:/)
    normalized = normalized.replace(/^[A-Za-z]:\//, '');

    // Normalize posix path (resolves redundant slashes and . segments)
    normalized = path.posix.normalize(normalized);

    // Strip leading ./ and leading slashes
    normalized = normalized.replace(/^\.\//, '').replace(/^\/+/, '');

    return normalized;
  }

  /**
   * Normalize an individual raw finding or parser finding into the Common Finding Schema.
   * Generates a stable deterministic fingerprint.
   *
   * @param {Object} rawFinding Finding record from Semgrep parser or scanner
   * @param {Object} [options={}] Normalization options
   * @param {string} [options.workspaceRoot=''] Workspace root for relative path resolution
   * @param {string} [options.defaultScanner='semgrep'] Default scanner name if unspecified
   * @returns {{ success: boolean, data: Object|null, error: string|null }}
   */
  normalizeFinding(rawFinding, options = {}) {
    if (!rawFinding || typeof rawFinding !== 'object' || Array.isArray(rawFinding)) {
      return {
        success: false,
        data: null,
        error: 'Record must be a non-null object'
      };
    }

    // 1. Extract rule ID (support rule, ruleId, check_id)
    const rule = String(rawFinding.rule || rawFinding.ruleId || rawFinding.check_id || '').trim();
    if (!rule) {
      return {
        success: false,
        data: null,
        error: 'Rule identifier is required (missing rule, ruleId, or check_id)'
      };
    }

    // 2. Extract file path (support path, filePath, file)
    const rawPath = rawFinding.path || rawFinding.filePath || rawFinding.file || '';
    if (!rawPath || typeof rawPath !== 'string' || !rawPath.trim()) {
      return {
        success: false,
        data: null,
        error: 'File path is required (missing path, filePath, or file)'
      };
    }

    const normalizedPath = this.normalizePath(rawPath, options.workspaceRoot);

    // 3. Extract line coordinates (support startLine/endLine and start.line/end.line)
    const rawStartLine = rawFinding.startLine !== undefined
      ? rawFinding.startLine
      : rawFinding.start?.line;

    const rawEndLine = rawFinding.endLine !== undefined
      ? rawFinding.endLine
      : (rawFinding.end?.line !== undefined ? rawFinding.end.line : rawStartLine);

    const startLineNum = parseInt(rawStartLine, 10);
    const endLineNum = parseInt(rawEndLine, 10);

    if (Number.isNaN(startLineNum) || startLineNum < 1) {
      return {
        success: false,
        data: null,
        error: `Invalid startLine: "${rawStartLine}". Must be an integer >= 1`
      };
    }

    if (Number.isNaN(endLineNum) || endLineNum < startLineNum) {
      return {
        success: false,
        data: null,
        error: `Invalid endLine: "${rawEndLine}". Must be an integer >= startLine (${startLineNum})`
      };
    }

    // 4. Extract metadata & references
    const rawMetadata = rawFinding.metadata !== undefined
      ? rawFinding.metadata
      : rawFinding.extra?.metadata;

    const metadata = (rawMetadata && typeof rawMetadata === 'object' && !Array.isArray(rawMetadata))
      ? rawMetadata
      : null;

    const references = Array.isArray(rawFinding.references)
      ? rawFinding.references
      : (Array.isArray(metadata?.references) ? metadata.references : []);

    // 5. Extract message
    const rawMsg = rawFinding.message !== undefined
      ? rawFinding.message
      : (rawFinding.extra?.message !== undefined ? rawFinding.extra.message : rawFinding.description);
    const message = rawMsg ? String(rawMsg).trim() : `Security finding detected by rule ${rule}`;

    // 6. Extract evidence (support evidence, codeSnippet, extra.lines, snippet)
    let evidence = '';
    if (rawFinding.evidence !== undefined && rawFinding.evidence !== null) {
      evidence = rawFinding.evidence;
    } else if (rawFinding.codeSnippet) {
      evidence = String(rawFinding.codeSnippet);
    } else if (rawFinding.extra?.lines) {
      evidence = String(rawFinding.extra.lines);
    } else if (rawFinding.snippet) {
      evidence = String(rawFinding.snippet);
    }

    // 7. Deterministic severity and confidence mapping
    const rawSeverity = rawFinding.severity !== undefined
      ? rawFinding.severity
      : rawFinding.extra?.severity;
    const severity = this.mapSeverity(rawSeverity, metadata || {});

    const explicitConfidence = rawFinding.confidence;
    const confidence = this.mapConfidence(metadata || {}, explicitConfidence);

    // 8. Generate stable deterministic fingerprint
    const fingerprint = this.generateFingerprint({
      rule,
      path: normalizedPath,
      evidence,
      message,
      metadata
    });

    // 9. Extract optional columns and contextual fields
    const startCol = rawFinding.startCol !== undefined
      ? rawFinding.startCol
      : (rawFinding.start?.col !== undefined ? rawFinding.start.col : null);

    const endCol = rawFinding.endCol !== undefined
      ? rawFinding.endCol
      : (rawFinding.end?.col !== undefined ? rawFinding.end.col : null);

    const codeSnippet = rawFinding.codeSnippet || (typeof evidence === 'string' && evidence ? evidence : null);

    const scanner = rawFinding.scanner || options.defaultScanner || 'semgrep';

    // Construct common finding object preserving any custom scanner attributes
    // (excluding database/orchestrator entity fields: id, scanId)
    const { id, scanId, ...extraProperties } = rawFinding;

    const candidate = {
      ...extraProperties,

      // Required Normalized Fields
      rule,
      path: normalizedPath,
      startLine: startLineNum,
      endLine: endLineNum,
      message,
      evidence,
      severity,
      confidence,
      fingerprint,

      // Scanner-specific metadata preserved without breaking common schema
      metadata,
      scanner,
      references,
      startCol: typeof startCol === 'number' ? startCol : null,
      endCol: typeof endCol === 'number' ? endCol : null,
      codeSnippet: typeof codeSnippet === 'string' ? codeSnippet : null
    };

    if (rawFinding.category) candidate.category = String(rawFinding.category);
    if (rawFinding.title) candidate.title = String(rawFinding.title);

    // Validate against Common Finding Schema
    const validation = validateCommonFinding(candidate);
    if (!validation.success) {
      return {
        success: false,
        data: null,
        error: `Common schema validation failed: ${validation.error.message}`
      };
    }

    return {
      success: true,
      data: validation.data,
      error: null
    };
  }

  /**
   * Normalize a collection of scanner findings into Common Finding Schema with fingerprint deduplication.
   *
   * Deduplication Behavior (options.deduplicate !== false):
   * - Uses stable SHA-256 fingerprint as identity.
   * - Duplicate issues are merged: references combined, metadata merged, duplicateCount tracked.
   * - Distinct vulnerabilities sharing a file or rule are preserved.
   *
   * @param {Array<Object>|Object} input Semgrep parser result or array of raw findings
   * @param {Object} [options={}] Normalization options
   * @param {boolean} [options.deduplicate=true] Whether to deduplicate by fingerprint
   * @returns {{
   *   success: boolean,
   *   findings: Array<Object>,
   *   errors: Array<string>,
   *   metadata: { total: number, valid: number, duplicates: number, unique: number, invalid: number }
   * }}
   */
  normalize(input, options = {}) {
    const deduplicate = options.deduplicate !== false;
    const errors = [];

    // Handle null or undefined input
    if (input === null || input === undefined) {
      return {
        success: false,
        findings: [],
        errors: ['Input to normalize cannot be null or undefined'],
        metadata: { total: 0, valid: 0, duplicates: 0, unique: 0, invalid: 1 }
      };
    }

    let recordsToProcess = [];

    // Check if input is a parser output object with a findings array
    if (input && typeof input === 'object' && Array.isArray(input.findings)) {
      recordsToProcess = input.findings;
      // Preserve existing parser errors if any
      if (Array.isArray(input.errors) && input.errors.length > 0) {
        input.errors.forEach(err => errors.push(`Parser error: ${err}`));
      }
    } else if (Array.isArray(input)) {
      recordsToProcess = input;
    } else if (typeof input === 'object') {
      recordsToProcess = [input];
    } else {
      return {
        success: false,
        findings: [],
        errors: ['Invalid input type: expected an array, finding object, or parser output object'],
        metadata: { total: 0, valid: 0, duplicates: 0, unique: 0, invalid: 1 }
      };
    }

    const total = recordsToProcess.length;
    const uniqueFindingsByFp = new Map();
    const rawValidFindings = [];
    let duplicatesCount = 0;

    for (let i = 0; i < recordsToProcess.length; i++) {
      const rawRecord = recordsToProcess[i];
      const result = this.normalizeFinding(rawRecord, options);

      if (result.success) {
        const finding = result.data;
        const fp = finding.fingerprint;
        rawValidFindings.push(finding);

        if (deduplicate) {
          if (uniqueFindingsByFp.has(fp)) {
            duplicatesCount++;
            const existing = uniqueFindingsByFp.get(fp);

            // Merge references (set union)
            if (Array.isArray(finding.references) && finding.references.length > 0) {
              const combined = new Set([...(existing.references || []), ...finding.references]);
              existing.references = Array.from(combined);
            }

            // Merge metadata if finding has keys not present in existing
            if (finding.metadata && typeof finding.metadata === 'object') {
              existing.metadata = {
                ...(finding.metadata || {}),
                ...(existing.metadata || {})
              };
            }

            // Preserve codeSnippet if existing was empty but duplicate has one
            if (!existing.codeSnippet && finding.codeSnippet) {
              existing.codeSnippet = finding.codeSnippet;
            }

            // Increment occurrence counter
            existing.duplicateCount = (existing.duplicateCount || 1) + 1;
          } else {
            finding.duplicateCount = 1;
            uniqueFindingsByFp.set(fp, finding);
          }
        }
      } else {
        errors.push(`Record index [${i}] rejected: ${result.error}`);
      }
    }

    const finalFindings = deduplicate
      ? Array.from(uniqueFindingsByFp.values())
      : rawValidFindings;

    const validTotal = rawValidFindings.length;

    return {
      success: errors.length === 0,
      findings: finalFindings,
      errors,
      metadata: {
        total,
        valid: validTotal,
        duplicates: duplicatesCount,
        unique: finalFindings.length,
        invalid: total - validTotal
      }
    };
  }
}

// Singleton export
const findingNormalizer = new FindingNormalizer();
findingNormalizer.FindingNormalizer = FindingNormalizer;

module.exports = findingNormalizer;
