/**
 * VULNEX Restricted Targeted Test Runner
 *
 * Implements:
 * - Master Antigravity Execution Bible Section 8.7 Step 11 & Section 9
 * - Commit 36 Gate: "No arbitrary host scripts; timeout/resource controls."
 * - Strict argument array process execution (shell: false)
 * - Safe test command allowlist (node --test, npm test, npx jest)
 * - Rejection of arbitrary shell scripts (.sh, .bat, .cmd, .ps1) and shell operators
 * - Timeout enforcement (TEST_TIMEOUT_SECONDS) and max output buffer controls
 * - Environment credential scrubbing (never passes GEMINI_API_KEY or secrets)
 * - Confinement: Runs strictly inside disposable temporary workspace
 */

const fs = require('fs');
const path = require('path');
const processRunner = require('../utils/processRunner');
const config = require('../config/env');

const ALLOWED_TEST_BINARIES = Object.freeze(new Set([
  'node',
  'npm',
  'npx'
]));

const DISALLOWED_SCRIPT_EXTENSIONS = Object.freeze(new Set([
  '.sh',
  '.bash',
  '.bat',
  '.cmd',
  '.ps1',
  '.vbs',
  '.exe',
  '.py',
  '.rb'
]));

const DANGEROUS_SHELL_PATTERNS = /[;&|`$<>()\\]/;

class UnsafeExecutionError extends Error {
  constructor(message = 'Execution blocked by security policy') {
    super(message);
    this.name = 'UnsafeExecutionError';
    this.code = 'UNSAFE_EXECUTION_BLOCKED';
    this.statusCode = 400;
  }
}

class TestTimeoutError extends Error {
  constructor(timeoutMs) {
    super(`Test execution timed out after ${timeoutMs}ms`);
    this.name = 'TestTimeoutError';
    this.code = 'TEST_TIMEOUT';
    this.statusCode = 408;
  }
}

class RestrictedRunnerService {
  constructor() {
    this.UnsafeExecutionError = UnsafeExecutionError;
    this.TestTimeoutError = TestTimeoutError;
    this.allowedBinaries = ALLOWED_TEST_BINARIES;
  }

  /**
   * Validate binary, arguments, and workspace confinement
   * @param {string} binary
   * @param {string[]} args
   * @param {string} workspacePath
   */
  validateCommandSafety(binary, args = [], workspacePath) {
    if (!binary || typeof binary !== 'string') {
      throw new UnsafeExecutionError('Test binary must be a non-empty string');
    }

    const cleanBinary = path.basename(binary).toLowerCase().replace(/\.(exe|cmd|bat)$/i, '');
    if (!ALLOWED_TEST_BINARIES.has(cleanBinary)) {
      throw new UnsafeExecutionError(
        `Arbitrary binary "${binary}" is not permitted. Only [${Array.from(ALLOWED_TEST_BINARIES).join(', ')}] are allowed.`
      );
    }

    if (!Array.isArray(args)) {
      throw new UnsafeExecutionError('Command arguments must be an array of strings');
    }

    // Check for dangerous shell characters or prohibited extensions in arguments
    for (const arg of args) {
      if (typeof arg !== 'string') {
        throw new UnsafeExecutionError('All arguments must be strings');
      }

      if (DANGEROUS_SHELL_PATTERNS.test(arg)) {
        throw new UnsafeExecutionError(
          `Command injection character detected in argument: "${arg}"`
        );
      }

      const ext = path.extname(arg).toLowerCase();
      if (DISALLOWED_SCRIPT_EXTENSIONS.has(ext)) {
        throw new UnsafeExecutionError(
          `Arbitrary script execution (${ext}) is strictly prohibited: "${arg}"`
        );
      }

      // Check path traversal in file arguments
      if (arg.includes('..')) {
        throw new UnsafeExecutionError(`Path traversal is prohibited in test argument: "${arg}"`);
      }
    }

    if (workspacePath) {
      if (!fs.existsSync(workspacePath)) {
        throw new UnsafeExecutionError(`Target workspace directory does not exist: "${workspacePath}"`);
      }
    }
  }

  /**
   * Filter and sanitize environment variables
   * Strips API keys, passwords, and tokens.
   */
  sanitizeEnvironment(customEnv = {}) {
    const safeEnv = {
      PATH: process.env.PATH || '',
      HOME: process.env.HOME || process.env.USERPROFILE || '/tmp',
      TMPDIR: process.env.TMPDIR || process.env.TEMP || '/tmp',
      NODE_ENV: 'test',
      CI: 'true'
    };

    // Scrub any sensitive environment keys
    for (const [key, val] of Object.entries(customEnv)) {
      const lower = key.toLowerCase();
      if (
        lower.includes('key') ||
        lower.includes('secret') ||
        lower.includes('token') ||
        lower.includes('password') ||
        lower.includes('auth') ||
        lower.includes('gemini')
      ) {
        continue; // Redacted / excluded
      }
      safeEnv[key] = val;
    }

    return safeEnv;
  }

  /**
   * Execute restricted targeted test runner inside workspace
   *
   * @param {Object} options
   * @param {string} options.workspacePath Path to disposable temporary workspace
   * @param {string} [options.testFile] Specific test file to run (e.g. test/user.test.js)
   * @param {string} [options.command='node'] Test runner command ('node' or 'npm')
   * @param {string[]} [options.args] Custom command arguments
   * @param {number} [options.timeoutMs] Execution timeout in ms
   * @param {number} [options.maxBufferBytes=5242880] Max output size (5MB default)
   * @returns {Promise<{
   *   testsPassed: boolean,
   *   exitCode: number|null,
   *   stdout: string,
   *   stderr: string,
   *   durationMs: number,
   *   timedOut: boolean,
   *   command: string[]
   * }>}
   */
  async runTargetedTest(options = {}) {
    const {
      workspacePath,
      testFile,
      command = 'node',
      args = null,
      timeoutMs = (config.testTimeoutSeconds || 30) * 1000,
      maxBufferBytes = 5 * 1024 * 1024
    } = options;

    if (!workspacePath) {
      throw new UnsafeExecutionError('workspacePath is required for test execution');
    }

    // Determine arguments array
    let execArgs = [];
    if (Array.isArray(args) && args.length > 0) {
      execArgs = [...args];
    } else if (testFile) {
      execArgs = ['--test', testFile];
    } else {
      execArgs = ['--test'];
    }

    // Security & Confinement Validation
    this.validateCommandSafety(command, execArgs, workspacePath);

    // Sanitize Environment
    const sanitizedEnv = this.sanitizeEnvironment(options.env || {});

    // Execute via ProcessRunner
    const result = await processRunner.run(command, execArgs, {
      cwd: workspacePath,
      env: sanitizedEnv,
      timeoutMs,
      maxBufferBytes
    });

    const testsPassed = result.exitCode === 0 && !result.timedOut;

    return {
      testsPassed,
      exitCode: result.exitCode,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      durationMs: result.durationMs,
      timedOut: Boolean(result.timedOut),
      command: [command, ...execArgs]
    };
  }
}

const restrictedRunnerService = new RestrictedRunnerService();
module.exports = restrictedRunnerService;
