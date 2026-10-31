const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

/**
 * Semgrep Process Wrapper
 * Executes Semgrep CLI securely via child_process.spawn with argument arrays.
 * Enforces execution timeouts, output size bounds, safe environment isolation,
 * and segregated stdio capturing without dropping output on non-zero exit codes.
 */
class SemgrepProcessWrapper {
  constructor(options = {}) {
    this.configuredBin = options.binary || process.env.SEMGREP_BIN || 'semgrep';
    this.defaultConfig = options.config || process.env.SEMGREP_CONFIG || 'auto';
    this.defaultTimeoutMs = (parseInt(process.env.SCAN_TIMEOUT_SECONDS, 10) || 120) * 1000;
    this.defaultMaxBufferBytes = options.maxBufferBytes || 25 * 1024 * 1024; // 25MB
    this.resolvedBin = null;
  }

  /**
   * Resolve Semgrep binary path across system PATH and standard user installation directories
   * @returns {string} Resolved binary name or path
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
   * Validate target scan path
   * @param {string} targetPath
   * @returns {{isValid: boolean, resolvedPath: string, error?: string}}
   */
  validateTarget(targetPath) {
    if (!targetPath || typeof targetPath !== 'string' || !targetPath.trim()) {
      return { isValid: false, resolvedPath: '', error: 'Target path must be a non-empty string' };
    }

    if (targetPath.indexOf('\0') !== -1) {
      return { isValid: false, resolvedPath: '', error: 'Target path contains invalid null byte characters' };
    }

    const resolvedPath = path.resolve(targetPath);
    if (!fs.existsSync(resolvedPath)) {
      return { isValid: false, resolvedPath, error: `Target path does not exist: ${resolvedPath}` };
    }

    return { isValid: true, resolvedPath };
  }

  /**
   * Build argument array for Semgrep CLI invocation
   * Never concatenates shell strings
   *
   * @param {string} targetPath Target file or directory to scan
   * @param {Object} [options]
   * @param {string} [options.config] Semgrep rule configuration
   * @param {string[]} [options.extraArgs] Additional CLI flags
   * @returns {string[]} Argument array
   */
  buildArgs(targetPath, options = {}) {
    const config = options.config || this.defaultConfig;
    const args = ['scan', '--config', config, '--json'];

    if (Array.isArray(options.extraArgs)) {
      for (const arg of options.extraArgs) {
        if (typeof arg === 'string' && arg.trim()) {
          args.push(arg.trim());
        }
      }
    }

    args.push(targetPath);
    return args;
  }

  /**
   * Build sanitized environment variables
   * Strips sensitive secrets (API keys, database URLs) from child process environment
   *
   * @param {string} binary
   * @param {Object} [customEnv]
   * @returns {Object} Sanitized environment object
   */
  buildSanitizedEnv(binary, customEnv = {}) {
    const binDir = path.isAbsolute(binary) ? path.dirname(binary) : '';
    const basePath = binDir ? `${binDir}:${process.env.PATH || ''}` : process.env.PATH || '/usr/local/bin:/usr/bin:/bin';

    return {
      PATH: basePath,
      HOME: process.env.HOME || '/tmp',
      TMPDIR: process.env.TMPDIR || '/tmp',
      LANG: process.env.LANG || 'en_US.UTF-8',
      LC_ALL: process.env.LC_ALL || 'en_US.UTF-8',
      USER: process.env.USER || 'vulnex',
      SEMGREP_USER_AGENT_APPEND: 'VULNEX-Scanner/1.0.0',
      ...customEnv
    };
  }

  /**
   * Execute Semgrep CLI against a target workspace or file
   *
   * @param {string} targetPath File or directory path to scan
   * @param {Object} [options] Execution options
   * @param {string} [options.binary] Override executable binary
   * @param {string} [options.config] Semgrep rule configuration
   * @param {string[]} [options.args] Explicit arguments override
   * @param {string[]} [options.extraArgs] Additional flags
   * @param {number} [options.timeoutMs] Timeout in milliseconds
   * @param {number} [options.maxBufferBytes] Max buffer memory limit in bytes
   * @param {string} [options.cwd] Working directory
   * @param {Object} [options.env] Custom environment variables
   * @returns {Promise<{status: string, stdout: string, stderr: string, exitCode: number|null, signal: string|null, durationMs: number, timedOut: boolean, outputLimitExceeded: boolean, error: string|null, command: {binary: string, args: string[]}}>}
   */
  async execute(targetPath, options = {}) {
    const startTime = Date.now();

    // 1. Validate Target Path
    const validation = this.validateTarget(targetPath);
    if (!validation.isValid) {
      return {
        status: 'SPAWN_ERROR',
        stdout: '',
        stderr: '',
        exitCode: null,
        signal: null,
        durationMs: 0,
        timedOut: false,
        outputLimitExceeded: false,
        error: validation.error,
        command: { binary: options.binary || this.resolveBinary(), args: [] }
      };
    }

    const validatedPath = validation.resolvedPath;
    const binary = options.binary || this.resolveBinary();
    const args = Array.isArray(options.args)
      ? options.args
      : this.buildArgs(validatedPath, options);

    const timeoutMs = typeof options.timeoutMs === 'number' ? options.timeoutMs : this.defaultTimeoutMs;
    const maxBufferBytes = options.maxBufferBytes || this.defaultMaxBufferBytes;
    const cwd = options.cwd || (fs.statSync(validatedPath).isDirectory() ? validatedPath : path.dirname(validatedPath));
    const env = this.buildSanitizedEnv(binary, options.env);

    return new Promise((resolve) => {
      let child;
      let stdoutData = '';
      let stderrData = '';
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let timedOut = false;
      let outputLimitExceeded = false;
      let timeoutHandle = null;
      let killGraceHandle = null;

      try {
        child = spawn(binary, args, {
          cwd,
          env,
          shell: false, // MANDATORY: Never run through shell interpolation
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe']
        });
      } catch (spawnErr) {
        return resolve({
          status: 'SPAWN_ERROR',
          stdout: '',
          stderr: '',
          exitCode: null,
          signal: null,
          durationMs: Date.now() - startTime,
          timedOut: false,
          outputLimitExceeded: false,
          error: `Failed to spawn Semgrep process: ${spawnErr.message}`,
          command: { binary, args }
        });
      }

      // Configure execution timeout
      if (timeoutMs > 0) {
        timeoutHandle = setTimeout(() => {
          timedOut = true;
          try {
            child.kill('SIGTERM');
            killGraceHandle = setTimeout(() => {
              try {
                if (!child.killed) child.kill('SIGKILL');
              } catch (_) {}
            }, 2000);
          } catch (_) {}
        }, timeoutMs);
      }

      // Bound stdout consumption
      child.stdout.on('data', (chunk) => {
        stdoutBytes += chunk.length;
        if (stdoutBytes > maxBufferBytes && !outputLimitExceeded) {
          outputLimitExceeded = true;
          try {
            child.kill('SIGTERM');
          } catch (_) {}
        } else if (!outputLimitExceeded) {
          stdoutData += chunk.toString('utf8');
        }
      });

      // Bound stderr consumption
      child.stderr.on('data', (chunk) => {
        stderrBytes += chunk.length;
        if (stderrBytes > maxBufferBytes && !outputLimitExceeded) {
          outputLimitExceeded = true;
          try {
            child.kill('SIGTERM');
          } catch (_) {}
        } else if (!outputLimitExceeded) {
          stderrData += chunk.toString('utf8');
        }
      });

      // Handle spawn errors (e.g. binary not found)
      child.on('error', (err) => {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        if (killGraceHandle) clearTimeout(killGraceHandle);

        resolve({
          status: 'SPAWN_ERROR',
          stdout: stdoutData,
          stderr: stderrData,
          exitCode: null,
          signal: null,
          durationMs: Date.now() - startTime,
          timedOut: false,
          outputLimitExceeded: false,
          error: `Process error: ${err.message}`,
          command: { binary, args }
        });
      });

      // Handle process completion
      child.on('close', (code, signal) => {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        if (killGraceHandle) clearTimeout(killGraceHandle);
        const durationMs = Date.now() - startTime;

        let status = 'SUCCESS';
        let error = null;

        if (timedOut) {
          status = 'TIMEOUT';
          error = `Semgrep execution timed out after ${timeoutMs}ms`;
        } else if (outputLimitExceeded) {
          status = 'OUTPUT_LIMIT_EXCEEDED';
          error = `Semgrep output exceeded memory limit of ${maxBufferBytes} bytes`;
        } else if (code !== 0) {
          status = 'NON_ZERO_EXIT';
          error = `Semgrep exited with code ${code}`;
        }

        // Return structured result without throwing away stdout on non-zero exit codes
        resolve({
          status,
          stdout: stdoutData,
          stderr: stderrData,
          exitCode: code,
          signal,
          durationMs,
          timedOut,
          outputLimitExceeded,
          error,
          command: { binary, args }
        });
      });
    });
  }
}

const semgrepProcessWrapperInstance = new SemgrepProcessWrapper();

function executeSemgrepProcess(targetPath, options) {
  return semgrepProcessWrapperInstance.execute(targetPath, options);
}

module.exports = {
  SemgrepProcessWrapper,
  semgrepProcessWrapper: semgrepProcessWrapperInstance,
  executeSemgrepProcess
};
