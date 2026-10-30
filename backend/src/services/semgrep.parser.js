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
        // Check if rule metadata indicates critical severity
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
    const combined = `${checkId} ${JSON.stringify(metadata)}`.toLowerCase();

    if (combined.includes('cwe-89') || combined.includes('sql-injection') || combined.includes('sqli')) {
      return 'SQL_INJECTION';
    }
    if (combined.includes('cwe-78') || combined.includes('command-injection') || combined.includes('rce') || combined.includes('exec')) {
      return 'COMMAND_INJECTION';
    }
    if (combined.includes('cwe-79') || combined.includes('xss') || combined.includes('cross-site-scripting')) {
      return 'XSS';
    }
    if (combined.includes('cwe-22') || combined.includes('path-traversal') || combined.includes('directory-traversal')) {
      return 'PATH_TRAVERSAL';
    }
    if (combined.includes('cwe-798') || combined.includes('secret') || combined.includes('api-key') || combined.includes('credential')) {
      return 'HARDCODED_SECRET';
    }
    if (combined.includes('cwe-328') || combined.includes('crypto') || combined.includes('insecure-hash')) {
      return 'INSECURE_CRYPTO';
    }
    if (combined.includes('cwe-942') || combined.includes('cors') || combined.includes('misconfig')) {
      return 'SECURITY_MISCONFIG';
    }
    if (combined.includes('auth') || combined.includes('jwt') || combined.includes('session')) {
      return 'BROKEN_AUTH';
    }

    if (metadata.category && typeof metadata.category === 'string') {
      return metadata.category.toUpperCase().replace(/[\s-]+/g, '_');
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
    if (metadata.shortlink) {
      // Use clean title if metadata has it
    }
    // Convert dot-separated checkId to title (e.g. javascript.express.security.audit.sqli)
    const parts = checkId.split('.');
    const ruleBase = parts[parts.length - 1] || checkId;
    const formatted = ruleBase.replace(/[-_]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    return formatted.length > 5 ? formatted : `Security Issue (${checkId})`;
  }

  /**
   * Generate a stable, deterministic SHA-256 fingerprint for deduplication
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
    // Redact hardcoded strings that look like secrets/keys
    let sanitized = rawEvidence.replace(/(['"`])([A-Za-z0-9_\-\.]{16,})(['"`])/g, '$1[REDACTED_SECRET]$3');
    // Truncate to reasonable length (max 1000 characters) to prevent memory bloat
    if (sanitized.length > 1000) {
      sanitized = sanitized.slice(0, 1000) + '... [TRUNCATED]';
    }
    return sanitized;
  }

  /**
   * Parse and normalize raw Semgrep JSON output
   * @param {string|Object} rawOutput Raw string or pre-parsed object
   * @param {Object} options
   * @param {string} [options.workspacePath] Root workspace path to make file paths relative
   * @param {string} [options.scanId] Associated scan ID
   * @returns {{findings: Array, errors: Array, metadata: Object}}
   */
  parse(rawOutput, options = {}) {
    const errors = [];
    const findings = [];
    const workspacePath = options.workspacePath || '';
    const nowIso = new Date().toISOString();

    if (!rawOutput) {
      return { findings: [], errors: ['Semgrep output is empty'], metadata: {} };
    }

    let parsedJson;
    if (typeof rawOutput === 'string') {
      try {
        parsedJson = JSON.parse(rawOutput);
      } catch (err) {
        return {
          findings: [],
          errors: [`Failed to parse Semgrep JSON output: ${err.message}`],
          metadata: {}
        };
      }
    } else {
      parsedJson = rawOutput;
    }

    // Validate raw structure with Zod schema
    const rawValidation = validateRawSemgrepOutput(parsedJson);
    if (!rawValidation.success) {
      // Record validation warning but attempt to extract results if array exists
      errors.push(`Raw Semgrep output schema validation warning: ${rawValidation.error.message}`);
    }

    const rawData = rawValidation.success ? rawValidation.data : parsedJson;
    const rawResults = Array.isArray(rawData?.results) ? rawData.results : [];

    // Capture Semgrep errors from the output if any
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

        const extra = item.extra || {};
        const metadata = extra.metadata || {};

        const severity = this.mapSeverity(extra.severity, metadata);
        const confidence = this.mapConfidence(metadata);
        const category = this.deriveCategory(checkId, metadata);
        const title = this.deriveTitle(checkId, metadata);
        const message = (extra.message || '').trim() || `Security finding detected by rule ${checkId}`;
        const evidence = this.sanitizeEvidence(extra.lines || '');

        const fingerprint = extra.fingerprint && /^[a-f0-9]{32,64}$/i.test(extra.fingerprint)
          ? extra.fingerprint
          : this.generateFingerprint(checkId, normalizedFilePath, evidence, startLine);

        const findingId = `find_${crypto.randomBytes(8).toString('hex')}`;

        const normalizedFinding = {
          id: findingId,
          scanner: 'semgrep',
          ruleId: checkId,
          title,
          category,
          severity,
          confidence,
          filePath: normalizedFilePath,
          startLine,
          endLine,
          message,
          evidence,
          fingerprint,
          status: 'DETECTED',
          createdAt: nowIso
        };

        // Validate individual normalized finding
        const validResult = validateNormalizedFinding(normalizedFinding);
        if (validResult.success) {
          findings.push(validResult.data);
        } else {
          errors.push(`Validation failed for finding ${checkId} in ${normalizedFilePath}: ${validResult.error.message}`);
        }
      } catch (itemErr) {
        errors.push(`Failed to parse finding item: ${itemErr.message}`);
      }
    }

    const scannerMetadata = {
      semgrepVersion: rawData?.version || null,
      pathsScannedCount: Array.isArray(rawData?.paths?.scanned) ? rawData.paths.scanned.length : null,
      pathsSkippedCount: Array.isArray(rawData?.paths?.skipped) ? rawData.paths.skipped.length : null,
      rulesRunCount: rawData?.time?.rules ? Object.keys(rawData.time.rules).length : null
    };

    return {
      findings,
      errors,
      metadata: scannerMetadata
    };
  }
}

module.exports = new SemgrepParser();
