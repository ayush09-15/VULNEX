const path = require('path');
const crypto = require('crypto');
const {
  validateRawSemgrepOutput,
  validateNormalizedFinding
} = require('../validators/semgrep.schema');

class SemgrepParser {
  /**
   * Safely normalize relative file path against workspace root
   * Never leaks host filesystem paths, removes leading slashes and traversal segments
   * @param {string} rawPath
   * @param {string} [workspacePath]
   * @returns {string} Normalized relative path
   */
  normalizeFilePath(rawPath, workspacePath = '') {
    if (!rawPath || typeof rawPath !== 'string') return 'unknown_file';

    let normalized = rawPath.trim();

    // If workspacePath provided and rawPath starts with it, make relative
    if (workspacePath && normalized.startsWith(workspacePath)) {
      normalized = path.relative(workspacePath, normalized);
    }

    // Replace Windows backslashes with POSIX forward slashes
    normalized = normalized.replace(/\\/g, '/');

    // Strip leading drive letters (e.g. C:)
    normalized = normalized.replace(/^[A-Za-z]:\//, '');

    // Canonicalize path traversal segments
    normalized = path.posix.normalize(normalized);

    // Strip any remaining leading / or ../
    normalized = normalized.replace(/^(\.\.\/)+/, '');
    normalized = normalized.replace(/^\/+/, '');

    return normalized || 'unknown_file';
  }

  /**
   * Map Semgrep severity to VULNEX canonical severity enum
   * @param {string} rawSeverity
   * @param {Object} [metadata]
   * @returns {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO'}
   */
  mapSeverity(rawSeverity, metadata = {}) {
    // Check numeric security-severity if present (e.g., CVSS-like score)
    const secSev = metadata['security-severity'];
    if (secSev !== undefined && secSev !== null) {
      const score = parseFloat(secSev);
      if (!isNaN(score)) {
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        return 'LOW';
      }
    }

    const sev = String(rawSeverity || '').toUpperCase();
    switch (sev) {
      case 'CRITICAL':
        return 'CRITICAL';
      case 'ERROR':
        if (String(metadata.impact || '').toUpperCase() === 'CRITICAL') return 'CRITICAL';
        return 'HIGH';
      case 'WARNING':
        return 'MEDIUM';
      case 'INFO':
        return 'INFO';
      case 'LOW':
        return 'LOW';
      default:
        return 'INFO';
    }
  }

  /**
   * Map Semgrep confidence to canonical confidence enum
   * Never conflate severity with confidence
   * @param {Object} [metadata]
   * @returns {'HIGH'|'MEDIUM'|'LOW'|'UNKNOWN'}
   */
  mapConfidence(metadata = {}) {
    const rawConf = String(metadata.confidence || '').toUpperCase();
    if (['HIGH', 'MEDIUM', 'LOW'].includes(rawConf)) {
      return rawConf;
    }
    return 'UNKNOWN';
  }

  /**
   * Derive standardized vulnerability category
   * @param {string} checkId
   * @param {Object} [metadata]
   * @returns {string} Category string
   */
  deriveCategory(checkId = '', metadata = {}) {
    const rawCheckId = String(checkId || '').toLowerCase();
    const meta = metadata && typeof metadata === 'object' ? metadata : {};

    // 1. Extract explicit CWEs from metadata (string or array)
    const cweEntries = [];
    if (meta.cwe) {
      if (Array.isArray(meta.cwe)) cweEntries.push(...meta.cwe);
      else cweEntries.push(String(meta.cwe));
    }
    if (meta.cwe_id) {
      if (Array.isArray(meta.cwe_id)) cweEntries.push(...meta.cwe_id);
      else cweEntries.push(String(meta.cwe_id));
    }
    const cweCombined = cweEntries.join(' ').toLowerCase();

    // Explicit CWE mapping takes highest priority
    if (/cwe-89\b/i.test(cweCombined)) return 'SQL_INJECTION';
    if (/cwe-78\b/i.test(cweCombined)) return 'COMMAND_INJECTION';
    if (/cwe-(?:94|95)\b/i.test(cweCombined)) return 'CODE_INJECTION';
    if (/cwe-79\b/i.test(cweCombined)) return 'XSS';
    if (/cwe-(?:22|23)\b/i.test(cweCombined)) return 'PATH_TRAVERSAL';
    if (/cwe-(?:798|259|312)\b/i.test(cweCombined)) return 'HARDCODED_SECRET';
    if (/cwe-(?:327|328)\b/i.test(cweCombined)) return 'INSECURE_CRYPTO';
    if (/cwe-942\b/i.test(cweCombined)) return 'SECURITY_MISCONFIG';
    if (/cwe-(?:287|306)\b/i.test(cweCombined)) return 'BROKEN_AUTH';

    // 2. Inspect rule ID and metadata (exclude 'author' to avoid false auth matches)
    const metaSafe = { ...meta };
    delete metaSafe.author;

    const metaString = JSON.stringify(metaSafe).toLowerCase();
    const combined = `${rawCheckId} ${metaString}`;

    // SQL Injection
    if (/\b(?:sql[_-]?injection|sqli)\b/i.test(combined) || combined.includes('cwe-89')) {
      return 'SQL_INJECTION';
    }

    // Code Injection (CWE-95 / CWE-94: dynamic eval, Function constructor)
    if (
      /\b(?:code[_-]?injection|eval[_-]?injection|eval[_-]with[_-]expression|detect[_-]eval)\b/i.test(combined) ||
      combined.includes('cwe-95') || combined.includes('cwe-94')
    ) {
      return 'CODE_INJECTION';
    }

    // Command Injection (CWE-78: shell execution, child_process OS commands)
    // NEVER match regex-exec or bare 'exec'
    if (
      !rawCheckId.includes('regex') &&
      (/\b(?:command[_-]?injection|shell[_-]?injection|os[_-]?command|shell[_-]?exec|child_process)\b/i.test(combined) ||
       combined.includes('cwe-78'))
    ) {
      return 'COMMAND_INJECTION';
    }

    // Cross-Site Scripting (XSS)
    if (/\b(?:xss|cross[_-]?site[_-]?scripting)\b/i.test(combined) || combined.includes('cwe-79')) {
      return 'XSS';
    }

    // Path Traversal
    if (/\b(?:path[_-]?traversal|directory[_-]?traversal)\b/i.test(combined) || combined.includes('cwe-22')) {
      return 'PATH_TRAVERSAL';
    }

    // Hardcoded Secret
    if (/\b(?:hardcoded[_-]?secret|api[_-]?key|jwt[_-]?secret|credential)\b/i.test(combined) || combined.includes('cwe-798')) {
      return 'HARDCODED_SECRET';
    }

    // Insecure Cryptography
    if (/\b(?:insecure[_-]?hash|insecure[_-]?crypto|broken[_-]?crypto)\b/i.test(combined) || combined.includes('cwe-328')) {
      return 'INSECURE_CRYPTO';
    }

    // Security Misconfiguration
    if (/\b(?:cors[_-]?wildcard|misconfig|security[_-]?misconfig)\b/i.test(combined) || combined.includes('cwe-942')) {
      return 'SECURITY_MISCONFIG';
    }

    // Broken Authentication (word boundary only)
    if (/\b(?:broken[_-]?auth|jwt[_-]?verification|session[_-]?fixation|missing[_-]?auth)\b/i.test(combined)) {
      return 'BROKEN_AUTH';
    }

    if (meta.category && typeof meta.category === 'string') {
      return meta.category.toUpperCase().replace(/[\s-]+/g, '_');
    }

    return 'OTHER';
  }

  /**
   * Extract human-readable title from Semgrep rule ID or metadata
   * @param {string} checkId
   * @param {Object} [metadata]
   * @returns {string}
   */
  deriveTitle(checkId, metadata = {}) {
    const parts = checkId.split('.');
    const ruleBase = parts[parts.length - 1] || checkId;
    const formatted = ruleBase.replace(/[-_]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    return formatted.length > 5 ? formatted : `Security Issue (${checkId})`;
  }

  /**
   * Generate a stable, deterministic SHA-256 fingerprint for cross-scan identification
   * @param {string} ruleId
   * @param {string} filePath
   * @param {string} evidence
   * @param {number} startLine
   * @returns {string} 64-char hex SHA-256
   */
  generateFingerprint(ruleId, filePath, evidence, startLine) {
    const normalizedEvidence = (evidence || '').trim().replace(/\s+/g, ' ');
    const hash = crypto.createHash('sha256');
    hash.update(`${ruleId}:${filePath}:${startLine}:${normalizedEvidence}`);
    return hash.digest('hex');
  }

  /**
   * Redact sensitive tokens/passwords from evidence snippet
   * @param {string} rawEvidence
   * @returns {string} Safe evidence excerpt
   */
  sanitizeEvidence(rawEvidence = '') {
    if (typeof rawEvidence !== 'string') return '';
    let sanitized = rawEvidence.replace(/(['"`])([A-Za-z0-9_\-\.]{16,})(['"`])/g, '$1[REDACTED_SECRET]$3');
    if (sanitized.length > 1000) {
      sanitized = sanitized.slice(0, 1000) + '... [TRUNCATED]';
    }
    return sanitized;
  }

  /**
   * Parse Semgrep JSON output into structured VULNEX scanner findings and metadata
   *
   * @param {string|Object} rawOutput Raw Semgrep stdout string or parsed JSON object
   * @param {Object} [options]
   * @param {string} [options.workspacePath] Root workspace path to normalize file paths
   * @param {string} [options.scanId] Associated scan ID
   * @returns {{success: boolean, isValidJson: boolean, findings: Array, errors: Array, metadata: Object|null}}
   */
  parse(rawOutput, options = {}) {
    const errors = [];
    const findings = [];
    const workspacePath = options.workspacePath || '';
    const nowIso = new Date().toISOString();

    if (rawOutput === null || rawOutput === undefined || rawOutput === '') {
      return {
        success: false,
        isValidJson: false,
        findings: [],
        errors: ['Semgrep output is empty or null'],
        metadata: null
      };
    }

    let parsedJson;
    if (typeof rawOutput === 'string') {
      try {
        parsedJson = JSON.parse(rawOutput);
      } catch (err) {
        return {
          success: false,
          isValidJson: false,
          findings: [],
          errors: [`Failed to parse Semgrep JSON output: ${err.message}`],
          metadata: null
        };
      }
    } else if (typeof rawOutput === 'object') {
      parsedJson = rawOutput;
    } else {
      return {
        success: false,
        isValidJson: false,
        findings: [],
        errors: ['Invalid Semgrep output type (expected JSON string or object)'],
        metadata: null
      };
    }

    // Valid JSON confirmed
    const rawValidation = validateRawSemgrepOutput(parsedJson);
    if (!rawValidation.success) {
      errors.push(`Raw Semgrep output schema validation warning: ${rawValidation.error.message}`);
    }

    const rawData = rawValidation.success ? rawValidation.data : parsedJson;
    const rawResults = Array.isArray(rawData?.results) ? rawData.results : [];

    // Capture any Semgrep runtime errors/warnings from output
    if (Array.isArray(rawData?.errors) && rawData.errors.length > 0) {
      rawData.errors.forEach(err => {
        const errMsg = typeof err === 'string' ? err : err.message || JSON.stringify(err);
        errors.push(`Semgrep scanner warning/error: ${errMsg}`);
      });
    }

    for (const item of rawResults) {
      try {
        const checkId = item.check_id || 'unknown.rule';
        const rawPath = item.path || 'unknown_file';
        const normalizedFilePath = this.normalizeFilePath(rawPath, workspacePath);

        const startLine = item.start?.line && item.start.line >= 1 ? item.start.line : 1;
        const endLine = item.end?.line && item.end.line >= startLine ? item.end.line : startLine;
        const startCol = item.start?.col !== undefined ? item.start.col : null;
        const endCol = item.end?.col !== undefined ? item.end.col : null;

        const extra = item.extra || {};
        const metadata = (extra.metadata && typeof extra.metadata === 'object' && Object.keys(extra.metadata).length > 0)
          ? extra.metadata
          : null;
        const references = (metadata && Array.isArray(metadata.references))
          ? metadata.references
          : [];

        const severity = this.mapSeverity(extra.severity, metadata || {});
        const confidence = this.mapConfidence(metadata || {});
        const category = this.deriveCategory(checkId, metadata || {});
        const title = this.deriveTitle(checkId, metadata || {});
        const message = (extra.message || '').trim() || `Security finding detected by rule ${checkId}`;
        const codeSnippet = extra.lines ? String(extra.lines) : null;
        const evidence = codeSnippet ? this.sanitizeEvidence(codeSnippet) : '';

        const fingerprint = extra.fingerprint && /^[a-f0-9]{32,64}$/i.test(extra.fingerprint)
          ? extra.fingerprint
          : this.generateFingerprint(checkId, normalizedFilePath, evidence, startLine);

        const findingId = `find_${crypto.randomBytes(8).toString('hex')}`;

        const structuredFinding = {
          // Explicit Parser Extracted Fields (Requirement 2)
          ruleId: checkId,
          severity,
          message,
          filePath: normalizedFilePath,
          startLine,
          endLine,
          startCol,
          endCol,
          codeSnippet,
          metadata,
          references,

          // Canonical VULNEX Contract Fields
          id: findingId,
          scanner: 'semgrep',
          title,
          category,
          confidence,
          evidence,
          fingerprint,
          status: 'DETECTED',
          createdAt: nowIso
        };

        // Validate individual normalized finding
        const validResult = validateNormalizedFinding(structuredFinding);
        if (validResult.success) {
          findings.push(validResult.data);
        } else {
          // If strict validation fails on some field, preserve finding with raw fields
          findings.push(structuredFinding);
          errors.push(`Validation warning for finding ${checkId} in ${normalizedFilePath}: ${validResult.error.message}`);
        }
      } catch (itemErr) {
        errors.push(`Failed to parse finding item: ${itemErr.message}`);
      }
    }

    // Preserve useful Semgrep metadata without inventing values (Requirement 6)
    const scannerMetadata = {
      semgrepVersion: rawData?.version || null,
      version: rawData?.version || null,
      pathsScanned: Array.isArray(rawData?.paths?.scanned) ? rawData.paths.scanned : [],
      pathsSkipped: Array.isArray(rawData?.paths?.skipped) ? rawData.paths.skipped : [],
      pathsScannedCount: Array.isArray(rawData?.paths?.scanned) ? rawData.paths.scanned.length : 0,
      pathsSkippedCount: Array.isArray(rawData?.paths?.skipped) ? rawData.paths.skipped.length : 0,
      rulesRunCount: rawData?.time?.rules ? Object.keys(rawData.time.rules).length : null,
      rulesCount: rawData?.time?.rules ? Object.keys(rawData.time.rules).length : null
    };

    return {
      success: true,
      isValidJson: true,
      findings,
      errors,
      metadata: scannerMetadata
    };
  }
}

module.exports = new SemgrepParser();
