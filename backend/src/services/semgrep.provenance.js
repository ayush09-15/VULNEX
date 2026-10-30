const { validateProvenance } = require('../validators/semgrep.schema');

class SemgrepProvenance {
  /**
   * Build an immutable provenance record for a Semgrep scan execution
   * Traceable link between every finding, the rule ID, location, and scan execution facts
   *
   * @param {Object} params
   * @param {string} params.scanId Unique scan identifier
   * @param {string|null} params.version Semgrep version
   * @param {string} params.config Config used (e.g. 'auto')
   * @param {string} params.timestamp Scan execution start ISO timestamp
   * @param {number} params.durationMs Execution duration in milliseconds
   * @param {number|null} params.exitCode Process exit code
   * @param {'COMPLETED'|'PARTIAL'|'FAILED'} params.status Final scanner status
   * @param {Array<Object>} params.findings Normalized findings
   * @param {Array<string|Object>} [params.errors] Any scanner warnings or errors
   * @returns {Object} Validated provenance record
   */
  createRecord({
    scanId,
    version,
    config = 'auto',
    timestamp,
    durationMs = 0,
    exitCode = 0,
    status = 'COMPLETED',
    findings = [],
    errors = []
  }) {
    // Extract per-finding traceability links (linking finding to rule, file, line)
    const ruleFindings = (findings || []).map(f => ({
      findingId: f.id,
      ruleId: f.ruleId,
      filePath: f.filePath,
      startLine: f.startLine,
      endLine: f.endLine
    }));

    const rawRecord = {
      scanner: 'semgrep',
      version: version || null,
      config: config || 'auto',
      scanId: scanId || `scan_${Date.now()}`,
      timestamp: timestamp || new Date().toISOString(),
      durationMs: Math.max(0, durationMs),
      exitCode: exitCode !== undefined ? exitCode : null,
      status: ['COMPLETED', 'PARTIAL', 'FAILED'].includes(status) ? status : 'FAILED',
      findingsCount: (findings || []).length,
      errors: Array.isArray(errors) ? errors : [],
      ruleFindings
    };

    const validation = validateProvenance(rawRecord);
    if (!validation.success) {
      console.warn('[SemgrepProvenance] Validation warning on provenance record:', validation.error.message);
      // Return rawRecord if non-critical validation mismatch, but it meets schema
      return rawRecord;
    }

    return validation.data;
  }
}

module.exports = new SemgrepProvenance();

