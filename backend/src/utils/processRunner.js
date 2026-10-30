const { spawn } = require('child_process');

/**
 * Safe Child Process Runner
 * Executes external binaries using spawn with argument arrays (never shell interpolation).
 * Enforces execution timeouts, output-size limits, and segregated stdio capturing.
 */
class ProcessRunner {
  /**
   * Run an executable with argument array
   * @param {string} binary Path or name of executable binary
   * @param {string[]} args Array of command-line arguments
   * @param {Object} options Execution options
   * @param {string} [options.cwd] Working directory
   * @param {Object} [options.env] Environment variables
   * @param {number} [options.timeoutMs=120000] Timeout in milliseconds
   * @param {number} [options.maxBufferBytes=15728640] Max stdout/stderr size (15MB default)
   * @returns {Promise<{stdout: string, stderr: string, exitCode: number|null, signal: string|null, durationMs: number, timedOut: boolean}>}
   */
  async run(binary, args = [], options = {}) {
    if (typeof binary !== 'string' || !binary.trim()) {
      throw new Error('ProcessRunner: binary must be a non-empty string');
    }
    if (!Array.isArray(args)) {
      throw new Error('ProcessRunner: args must be an array of strings');
    }

    const timeoutMs = options.timeoutMs || 120000;
    const maxBufferBytes = options.maxBufferBytes || 15 * 1024 * 1024; // 15MB
    const startTime = Date.now();

    // Sanitize environment: pass essential system variables, never leak API keys
    const safeEnv = {
      PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
      HOME: process.env.HOME || '/tmp',
      TMPDIR: process.env.TMPDIR || '/tmp',
      LANG: process.env.LANG || 'en_US.UTF-8',
      LC_ALL: process.env.LC_ALL || 'en_US.UTF-8',
      ...(options.env || {})
    };

    return new Promise((resolve, reject) => {
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
          cwd: options.cwd || process.cwd(),
          env: safeEnv,
          shell: false, // MANDATORY: Never run through shell
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe']
        });
      } catch (err) {
        return reject(new Error(`Failed to spawn process "${binary}": ${err.message}`));
      }

      // Setup execution timeout
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

      child.on('error', (err) => {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        if (killGraceHandle) clearTimeout(killGraceHandle);
        const durationMs = Date.now() - startTime;
        reject(new Error(`Process execution error for "${binary}": ${err.message}`));
      });

      child.on('close', (code, signal) => {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        if (killGraceHandle) clearTimeout(killGraceHandle);
        const durationMs = Date.now() - startTime;

        if (outputLimitExceeded) {
          return reject(new Error(`Process output limit exceeded (${maxBufferBytes} bytes) for "${binary}"`));
        }

        resolve({
          stdout: stdoutData,
          stderr: stderrData,
          exitCode: code,
          signal,
          durationMs,
          timedOut
        });
      });
    });
  }
}

module.exports = new ProcessRunner();

