const fs = require('fs');
const path = require('path');
const processRunner = require('../utils/processRunner');
const npmAuditParser = require('./npmAudit.parser');

/**
 * ============================================================================
 * VULNEX npm Dependency Audit Service
 *
 * Safe process wrapper for executing `npm audit --json` against a target
 * repository workspace.
 *
 * Responsibilities:
 * 1. Check if `npm` CLI is available in the host environment.
 * 2. Validate workspace and detect package manifests (`package.json`, `package-lock.json`).
 * 3. Execute `npm audit --json` safely via argument array (never shell string concatenation).
 * 4. Enforce configurable execution timeouts and buffer bounds.
 * 5. Pipe output to `npmAuditParser` and resolve lockfile dependencies.
 * 6. Return structured scanner results ({ success, status, findings, advisories, errors, durationMs }).
 * ============================================================================
 */
class NpmAuditService {
  constructor() {
    this.configuredBin = process.env.NPM_BIN || (process.platform === 'win32' ? 'npm.cmd' : 'npm');
    this.defaultTimeoutSeconds = parseInt(process.env.SCAN_TIMEOUT_SECONDS, 10) || 120;
    this.cachedVersion = null;
    this.runner = processRunner;
    this.parser = npmAuditParser;
  }

  /**
   * Check if npm CLI is accessible and return its version
   * @returns {Promise<string|null>} Version string or null
   */
  async getVersion() {
    if (this.cachedVersion) return this.cachedVersion;

    try {
      const result = await this.runner.run(this.configuredBin, ['--version'], {
        timeoutMs: 5000
      });

      if (result.exitCode === 0 && result.stdout) {
        this.cachedVersion = result.stdout.trim();
        return this.cachedVersion;
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Check if npm CLI is available
   * @returns {Promise<boolean>}
   */
  async isAvailable() {
    const version = await this.getVersion();
    return Boolean(version);
  }

  /**
   * Execute dependency audit against a target repository workspace
   *
   * @param {string} workspacePath Path to the repository workspace
   * @param {Object} [options={}] Scan options
   * @param {number} [options.timeoutSeconds] Timeout in seconds
   * @param {string} [options.scanId] Associated scan ID
   * @returns {Promise<{
   *   success: boolean,
   *   status: 'COMPLETED'|'FAILED',
   *   scanner: 'npm-audit',
   *   findings: Array<Object>,
   *   advisories: Array<Object>,
   *   errors: Array<string>,
   *   durationMs: number,
   *   timedOut: boolean,
   *   exitCode: number|null,
   *   metadata: Object|null
   * }>}
   */
  async scanWorkspace(workspacePath, options = {}) {
    const startTime = Date.now();
    const timeoutSeconds = options.timeoutSeconds || this.defaultTimeoutSeconds;
    const timeoutMs = timeoutSeconds * 1000;

    // 1. Verify workspace exists
    if (!workspacePath || typeof workspacePath !== 'string') {
      return {
        success: false,
        status: 'FAILED',
        scanner: 'npm-audit',
        findings: [],
        advisories: [],
        errors: ['Invalid or missing workspacePath'],
        durationMs: 0,
        timedOut: false,
        exitCode: null,
        metadata: null
      };
    }

    const resolvedPath = path.resolve(workspacePath);
    if (!fs.existsSync(resolvedPath)) {
      return {
        success: false,
        status: 'FAILED',
        scanner: 'npm-audit',
        findings: [],
        advisories: [],
        errors: [`Workspace path does not exist: ${resolvedPath}`],
        durationMs: 0,
        timedOut: false,
        exitCode: null,
        metadata: null
      };
    }

    // 2. Check for package manifest
    const hasPackageJson = fs.existsSync(path.join(resolvedPath, 'package.json'));
    const hasPackageLock = fs.existsSync(path.join(resolvedPath, 'package-lock.json'));

    if (!hasPackageJson && !hasPackageLock) {
      return {
        success: true,
        status: 'COMPLETED',
        scanner: 'npm-audit',
        findings: [],
        advisories: [],
        errors: [],
        durationMs: Date.now() - startTime,
        timedOut: false,
        exitCode: 0,
        metadata: {
          skipped: true,
          reason: 'No package manifest (package.json / package-lock.json) found in workspace'
        }
      };
    }

    // 3. Execute `npm audit --json`
    let runnerResult;
    try {
      runnerResult = await this.runner.run(this.configuredBin, ['audit', '--json'], {
        cwd: resolvedPath,
        timeoutMs,
        maxBufferBytes: 25 * 1024 * 1024
      });
    } catch (spawnErr) {
      return {
        success: false,
        status: 'FAILED',
        scanner: 'npm-audit',
        findings: [],
        advisories: [],
        errors: [`Failed to execute npm binary: ${spawnErr.message}`],
        durationMs: Date.now() - startTime,
        timedOut: false,
        exitCode: null,
        metadata: null
      };
    }

    const durationMs = runnerResult.durationMs || (Date.now() - startTime);

    // 4. Handle Timeout
    if (runnerResult.timedOut) {
      return {
        success: false,
        status: 'FAILED',
        scanner: 'npm-audit',
        findings: [],
        advisories: [],
        errors: [`Dependency audit timed out after ${timeoutSeconds}s`],
        durationMs,
        timedOut: true,
        exitCode: runnerResult.exitCode,
        metadata: null
      };
    }

    // 5. Parse Output
    const rawStdout = runnerResult.stdout ? runnerResult.stdout.trim() : '';
    const parseResult = this.parser.parse(rawStdout, {
      workspacePath: resolvedPath,
      lockfilePath: hasPackageLock ? path.join(resolvedPath, 'package-lock.json') : null,
      exitCode: runnerResult.exitCode
    });

    // npm audit returns non-zero exit code (e.g. 1) when vulnerabilities are found
    // If output parsed valid JSON, it is a successful audit regardless of exitCode
    if (parseResult.isValidJson) {
      return {
        success: true,
        status: 'COMPLETED',
        scanner: 'npm-audit',
        findings: parseResult.findings,
        advisories: parseResult.advisories,
        errors: parseResult.errors,
        durationMs,
        timedOut: false,
        exitCode: runnerResult.exitCode,
        metadata: parseResult.metadata
      };
    }

    // Output was not valid JSON and process exited non-zero
    const errorMsg = runnerResult.stderr
      ? `npm audit error: ${runnerResult.stderr.trim().split('\n')[0]}`
      : `npm audit exited with code ${runnerResult.exitCode} without valid JSON output`;

    return {
      success: false,
      status: 'FAILED',
      scanner: 'npm-audit',
      findings: [],
      advisories: [],
      errors: [errorMsg],
      durationMs,
      timedOut: false,
      exitCode: runnerResult.exitCode,
      metadata: null
    };
  }
}

const npmAuditService = new NpmAuditService();
npmAuditService.NpmAuditService = NpmAuditService;

module.exports = npmAuditService;

