const { describe, it } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { SemgrepProcessWrapper, executeSemgrepProcess } = require('../src/services/semgrepProcess');

describe('SemgrepProcessWrapper (Safe Process Execution)', () => {
  const wrapper = new SemgrepProcessWrapper();
  const validTestPath = path.resolve(__dirname, 'fixtures', 'test-repo');

  it('1. should construct arguments as an array and never as a shell string', () => {
    const args = wrapper.buildArgs(validTestPath, {
      config: 'p/ci',
      extraArgs: ['--verbose', '--no-git-ignore']
    });

    assert.ok(Array.isArray(args), 'Arguments must be an array');
    assert.strictEqual(args[0], 'scan');
    assert.strictEqual(args[1], '--config');
    assert.strictEqual(args[2], 'p/ci');
    assert.strictEqual(args[3], '--json');
    assert.ok(args.includes('--verbose'));
    assert.ok(args.includes('--no-git-ignore'));
    assert.strictEqual(args[args.length - 1], validTestPath);
  });

  it('2. should reject invalid target paths before process spawn', async () => {
    // Non-existent directory
    const res1 = await wrapper.execute('/non/existent/vulnex/target/path');
    assert.strictEqual(res1.status, 'SPAWN_ERROR');
    assert.ok(res1.error.includes('does not exist'));

    // Empty string
    const res2 = await wrapper.execute('');
    assert.strictEqual(res2.status, 'SPAWN_ERROR');

    // Null byte injection attempt
    const res3 = await wrapper.execute('path\0withnull');
    assert.strictEqual(res3.status, 'SPAWN_ERROR');
    assert.ok(res3.error.includes('null byte'));
  });

  it('3. should sanitize environment variables and never pass sensitive API keys', () => {
    process.env.GEMINI_API_KEY = 'secret_gemini_token_to_strip';
    process.env.DATABASE_URL = 'postgres://user:pass@localhost:5432/db';

    const env = wrapper.buildSanitizedEnv('semgrep');

    assert.strictEqual(env.GEMINI_API_KEY, undefined, 'GEMINI_API_KEY must not be passed to scanner subprocess');
    assert.strictEqual(env.DATABASE_URL, undefined, 'DATABASE_URL must not be passed to scanner subprocess');
    assert.ok(env.PATH, 'PATH must be preserved');
    assert.ok(env.HOME, 'HOME must be preserved');
  });

  it('4. should capture stdout and stderr independently on successful execution', async () => {
    // Mock process using node executable with arguments array
    const result = await wrapper.execute(validTestPath, {
      binary: process.execPath,
      args: ['-e', 'console.log("MOCK_SCAN_STDOUT"); console.error("MOCK_SCAN_STDERR");']
    });

    assert.strictEqual(result.status, 'SUCCESS');
    assert.strictEqual(result.exitCode, 0);
    assert.strictEqual(result.timedOut, false);
    assert.ok(result.stdout.includes('MOCK_SCAN_STDOUT'));
    assert.ok(result.stderr.includes('MOCK_SCAN_STDERR'));
    assert.ok(result.durationMs >= 0);
  });

  it('5. should handle non-zero exit code without discarding stdout results', async () => {
    // Semgrep frequently returns code 1 when findings are discovered.
    // Stdout must be preserved completely!
    const result = await wrapper.execute(validTestPath, {
      binary: process.execPath,
      args: [
        '-e',
        'console.log(JSON.stringify({ results: [{ id: "find_1" }] })); process.exit(1);'
      ]
    });

    assert.strictEqual(result.status, 'NON_ZERO_EXIT');
    assert.strictEqual(result.exitCode, 1);
    assert.ok(result.stdout.includes('"results"'), 'Stdout must NOT be thrown away on non-zero exit code');
    assert.ok(result.error.includes('Semgrep exited with code 1'));
  });

  it('6. should enforce configurable execution timeout cleanly', async () => {
    const result = await wrapper.execute(validTestPath, {
      binary: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 10000);'],
      timeoutMs: 150 // Terminate after 150ms
    });

    assert.strictEqual(result.status, 'TIMEOUT');
    assert.strictEqual(result.timedOut, true);
    assert.ok(result.error.includes('timed out'));
  });

  it('7. should handle spawn errors cleanly without unhandled exceptions', async () => {
    const result = await wrapper.execute(validTestPath, {
      binary: '/usr/bin/guaranteed_non_existent_semgrep_binary_9999'
    });

    assert.strictEqual(result.status, 'SPAWN_ERROR');
    assert.strictEqual(result.exitCode, null);
    assert.ok(result.error.includes('Process error') || result.error.includes('Failed to spawn'));
  });

  it('8. should prevent unbounded stdout memory consumption by enforcing maxBufferBytes', async () => {
    const result = await wrapper.execute(validTestPath, {
      binary: process.execPath,
      args: [
        '-e',
        'for (let i = 0; i < 5000; i++) process.stdout.write("A".repeat(1024));'
      ],
      maxBufferBytes: 50 * 1024 // 50KB limit for test
    });

    assert.strictEqual(result.status, 'OUTPUT_LIMIT_EXCEEDED');
    assert.strictEqual(result.outputLimitExceeded, true);
    assert.ok(result.error.includes('memory limit'));
  });

  it('9. should provide module-level convenience function executeSemgrepProcess', async () => {
    const result = await executeSemgrepProcess(validTestPath, {
      binary: process.execPath,
      args: ['-e', 'console.log("DIRECT_WRAPPER_EXECUTION");']
    });

    assert.strictEqual(result.status, 'SUCCESS');
    assert.ok(result.stdout.includes('DIRECT_WRAPPER_EXECUTION'));
  });
});
