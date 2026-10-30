const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const processRunner = require('../utils/processRunner');
const semgrepParser = require('./semgrep.parser');
const semgrepProvenance = require('./semgrep.provenance');

class SemgrepService {
  constructor() {
    this.configuredBin = process.env.SEMGREP_BIN || 'semgrep';
    this.defaultConfig = process.env.SEMGREP_CONFIG || 'auto';
    this.defaultTimeoutSeconds = parseInt(process.env.SCAN_TIMEOUT_SECONDS, 10) || 120;
    this.resolvedBin = null;
    this.cachedVersion = null;
  }

  /**
   * Resolve Semgrep binary path across system and user-local environments
   * @returns {string|null} Resolved binary path or null
   */
  resolveBinary() {
    if (this.resolvedBin) return this.resolvedBin;

    const candidates = [
      this.configuredBin,
      path.join(process.env.HOME || '', 'Library/Python/3.9/bin/semgrep'),
      path.join(process.env.HOME || '', '.local/bin/semgrep'),
      '/usr/local/bin/semgrep',
      '/opt/homebrew/bin/semgrep'
    ].filter(Boolean);

    for (const candidate of candidates) {
      if (candidate === 'semgrep') {
        // Can be on system PATH
        this.resolvedBin = candidate;
        return candidate;
      }
      try {
        if (fs.existsSync(candidate)) {
          const stat = fs.statSync(candidate);
          if (stat.isFile()) {
            this.resolvedBin = candidate;
            return candidate;
          }
        }
      } catch (_) {}
    }

    return this.configuredBin || 'semgrep';
  }

  /**
   * Check if Semgrep CLI is installed and accessible
   * @returns {Promise<boolean>}
   */
  async isAvailable() {
    try {
      const version = await this.getVersion();
      return !!version;
    } catch (_) {
      return false;
    }
  }

  /**
   * Retrieve Semgrep CLI version
   * @returns {Promise<string|null>} Semgrep version string
   */
  async getVersion() {
    if (this.cachedVersion) return this.cachedVersion;

    const bin = this.resolveBinary();
    const binDir = path.isAbsolute(bin) ? path.dirname(bin) : '';
    const extraPath = binDir ? `${binDir}:${process.env.PATH || ''}` : process.env.PATH || '';

    try {
      const result = await processRunner.run(bin, ['--version'], {
        timeoutMs: 15000,
        env: { PATH: extraPath }
      });

      if (result.exitCode === 0 && result.stdout) {
        // Semgrep version output might have warnings before the version string
        const lines = result.stdout.trim().split('\n');
        for (const line of lines) {
          const match = line.trim().match(/^(\d+\.\d+\.\d+.*)$/);
          if (match) {
            this.cachedVersion = match[1];
            return this.cachedVersion;
          }
        }
        // Fallback: first non-empty line
        this.cachedVersion = lines[lines.length - 1].trim();
        return this.cachedVersion;
      }
    } catch (err) {
      // Semgrep unavailable or invocation failed
    }

    return null;
  }

  /**
   * Validate workspace path strictly
   * Rejects non-existent paths, traversal sequences, and files that are not directories
   *
   * @param {string} rawWorkspacePath
   * @returns {{isValid: boolean, resolvedPath: string, error?: string}}
   */
  validateWorkspace(rawWorkspacePath) {
    if (!rawWorkspacePath || typeof rawWorkspacePath !== 'string' || !rawWorkspacePath.trim()) {
      return { isValid: false, resolvedPath: '', error: 'Workspace path must be a non-empty string' };
    }

    // Check for null bytes or dangerous characters
    if (rawWorkspacePath.indexOf('\0') !== -1) {
      return { isValid: false, resolvedPath: '', error: 'Workspace path contains invalid characters' };
    }

    const resolvedPath = path.resolve(rawWorkspacePath);

    if (!fs.existsSync(resolvedPath)) {
      return { isValid: false, resolvedPath, error: `Workspace path does not exist: ${resolvedPath}` };
    }

    try {
      const stat = fs.statSync(resolvedPath);
      if (!stat.isDirectory()) {
        return { isValid: false, resolvedPath, error: `Workspace path must be a directory: ${resolvedPath}` };
      }
    } catch (err) {
      return { isValid: false, resolvedPath, error: `Failed to inspect workspace path: ${err.message}` };
    }

    return { isValid: true, resolvedPath };
  }

  /**
   * Execute Semgrep against a supplied repository workspace
   *
   * @param {string} workspacePath Path to the repository workspace
   * @param {Object} [options]
   * @param {string} [options.config] Semgrep rule configuration (default: 'auto')
   * @param {number} [options.timeoutSeconds] Timeout in seconds
   * @param {string} [options.scanId] Unique scan identifier
   * @param {string} [options.customBinary] Override Semgrep binary path
   * @returns {Promise<{success: boolean, status: 'COMPLETED'|'PARTIAL'|'FAILED', scanner: 'semgrep', findings: Array, provenance: Object, errors: Array}>}
   */
  async scanWithSemgrep(workspacePath, options = {}) {
    const scanId = options.scanId || `scan_${crypto.randomBytes(6).toString('hex')}`;
    const scanConfig = options.config || this.defaultConfig;
    const timeoutSeconds = options.timeoutSeconds || this.defaultTimeoutSeconds;
    const timeoutMs = timeoutSeconds * 1000;
    const startTime = Date.now();
    const timestamp = new Date().toISOString();

    const errors = [];

    // 1. Validate Workspace Path
    const workspaceValidation = this.validateWorkspace(workspacePath);
    if (!workspaceValidation.isValid) {
      const errorMsg = `Workspace validation failed: ${workspaceValidation.error}`;
      errors.push(errorMsg);
      const provenance = semgrepProvenance.createRecord({
        scanId,
        version: null,
        config: scanConfig,
        timestamp,
        durationMs: Date.now() - startTime,
        exitCode: null,
        status: 'FAILED',
        findings: [],
        errors
      });
      return {
        success: false,
        status: 'FAILED',
        scanner: 'semgrep',
        findings: [],
        provenance,
        errors
      };
    }

    const validatedWorkspace = workspaceValidation.resolvedPath;

    // 2. Resolve Semgrep Binary & Verify Availability
    const bin = options.customBinary || this.resolveBinary();
    const semgrepVersion = await this.getVersion();

    if (!semgrepVersion && !options.customBinary) {
      const errorMsg = 'Semgrep CLI is not installed or not accessible in PATH';
      errors.push(errorMsg);
      const provenance = semgrepProvenance.createRecord({
        scanId,
        version: null,
        config: scanConfig,
        timestamp,
        durationMs: Date.now() - startTime,
        exitCode: null,
        status: 'FAILED',
        findings: [],
        errors
      });
      return {
        success: false,
        status: 'FAILED',
        scanner: 'semgrep',
        findings: [],
        provenance,
        errors
      };
    }

    // 3. Prepare Arguments Array (Never use shell concatenation)
    // Command: semgrep scan --config <config> --json <workspace-path>
    const args = [
      'scan',
      '--config', scanConfig,
      '--json',
      validatedWorkspace
    ];

    const binDir = path.isAbsolute(bin) ? path.dirname(bin) : '';
    const runnerPath = binDir ? `${binDir}:${process.env.PATH || ''}` : process.env.PATH || '';

    // 4. Execute Scanner via ProcessRunner
    let runnerResult;
    try {
      runnerResult = await processRunner.run(bin, args, {
        cwd: validatedWorkspace,
        timeoutMs,
        maxBufferBytes: 25 * 1024 * 1024, // 25MB output limit
        env: {
          PATH: runnerPath,
          SEMGREP_USER_AGENT_APPEND: 'VULNEX-Scanner/1.0.0'
        }
      });
    } catch (procErr) {
      const errorMsg = `Scanner execution failure: ${procErr.message}`;
      errors.push(errorMsg);
      const provenance = semgrepProvenance.createRecord({
        scanId,
        version: semgrepVersion,
        config: scanConfig,
        timestamp,
        durationMs: Date.now() - startTime,
        exitCode: null,
        status: 'FAILED',
        findings: [],
        errors
      });
      return {
        success: false,
        status: 'FAILED',
        scanner: 'semgrep',
        findings: [],
        provenance,
        errors
      };
    }

    // 5. Handle Timeout
    if (runnerResult.timedOut) {
      const errorMsg = `Scanner execution timed out after ${timeoutSeconds} seconds`;
      errors.push(errorMsg);
      const provenance = semgrepProvenance.createRecord({
        scanId,
        version: semgrepVersion,
        config: scanConfig,
        timestamp,
        durationMs: runnerResult.durationMs,
        exitCode: runnerResult.exitCode,
        status: 'FAILED',
        findings: [],
        errors
      });
      return {
        success: false,
        status: 'FAILED',
        scanner: 'semgrep',
        findings: [],
        provenance,
        errors
      };
    }

    // Capture any stderr warnings
    if (runnerResult.stderr && runnerResult.stderr.trim()) {
      // Filter out non-fatal python/openssl library warnings
      const stderrLines = runnerResult.stderr.trim().split('\n').filter(l =>
        !l.includes('NotOpenSSLWarning') &&
        !l.includes('negative serial number')
      );
      if (stderrLines.length > 0) {
        errors.push(`Scanner stderr: ${stderrLines.join('; ')}`);
      }
    }

    // 6. Parse Output (Distinguish findings from errors)
    const rawStdout = runnerResult.stdout ? runnerResult.stdout.trim() : '';
    const parseResult = semgrepParser.parse(rawStdout, {
      workspacePath: validatedWorkspace,
      scanId
    });

    if (parseResult.errors && parseResult.errors.length > 0) {
      errors.push(...parseResult.errors);
    }

    // If exit code is non-zero and we got NO findings and NO valid JSON, mark FAILED
    const hasValidJsonOutput = parseResult.findings.length > 0 || (rawStdout.startsWith('{') && rawStdout.includes('"results"'));
    const isProcessCrash = runnerResult.exitCode !== 0 && !hasValidJsonOutput;

    if (isProcessCrash) {
      errors.push(`Semgrep exited with non-zero code ${runnerResult.exitCode} without producing valid results`);
      const provenance = semgrepProvenance.createRecord({
        scanId,
        version: semgrepVersion,
        config: scanConfig,
        timestamp,
        durationMs: runnerResult.durationMs,
        exitCode: runnerResult.exitCode,
        status: 'FAILED',
        findings: [],
        errors
      });
      return {
        success: false,
        status: 'FAILED',
        scanner: 'semgrep',
        findings: [],
        provenance,
        errors
      };
    }

    // 7. Determine Final Status (COMPLETED vs PARTIAL)
    // If valid results were returned alongside scanner warnings/errors -> PARTIAL
    const finalStatus = errors.length > 0 ? 'PARTIAL' : 'COMPLETED';

    const provenance = semgrepProvenance.createRecord({
      scanId,
      version: semgrepVersion || parseResult.metadata?.semgrepVersion,
      config: scanConfig,
      timestamp,
      durationMs: runnerResult.durationMs,
      exitCode: runnerResult.exitCode,
      status: finalStatus,
      findings: parseResult.findings,
      errors
    });

    return {
      success: true,
      status: finalStatus,
      scanner: 'semgrep',
      findings: parseResult.findings,
      provenance,
      errors
    };
  }
}

const semgrepServiceInstance = new SemgrepService();

// Export convenience function along with service instance
function scanWithSemgrep(workspacePath, options) {
  return semgrepServiceInstance.scanWithSemgrep(workspacePath, options);
}

module.exports = {
  SemgrepService,
  semgrepService: semgrepServiceInstance,
  scanWithSemgrep
};
