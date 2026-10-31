/**
 * VULNEX Restricted Targeted Test Runner Tests
 *
 * Verifies Commit 36 Gate:
 * - "No arbitrary host scripts; timeout/resource controls."
 * - Master Antigravity Execution Bible Section 8.7 Step 11 & Section 9
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const restrictedRunner = require('../src/services/restrictedRunner.service');

describe('Restricted Targeted Test Runner (Commit 36)', () => {
  let tempWorkspace;

  beforeEach(() => {
    tempWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex_test_runner_'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempWorkspace, { recursive: true, force: true });
    } catch (_) {}
  });

  it('1. rejects arbitrary binaries outside the allowlist (bash, sh, curl)', async () => {
    for (const badBinary of ['bash', 'sh', 'curl', 'python', 'powershell']) {
      assert.throws(
        () => restrictedRunner.validateCommandSafety(badBinary, ['--help'], tempWorkspace),
        (err) => {
          assert.strictEqual(err.name, 'UnsafeExecutionError');
          assert.strictEqual(err.code, 'UNSAFE_EXECUTION_BLOCKED');
          assert.match(err.message, /Arbitrary binary/i);
          return true;
        }
      );
    }
  });

  it('2. rejects execution of arbitrary script files (.sh, .bat, .cmd, .ps1)', async () => {
    for (const badExt of ['exploit.sh', 'run.bat', 'script.cmd', 'payload.ps1']) {
      assert.throws(
        () => restrictedRunner.validateCommandSafety('node', [badExt], tempWorkspace),
        (err) => {
          assert.strictEqual(err.name, 'UnsafeExecutionError');
          assert.match(err.message, /Arbitrary script execution/i);
          return true;
        }
      );
    }
  });

  it('3. rejects command injection characters and operators (&&, ;, |, `, $)', async () => {
    const maliciousArgs = [
      'test.js; rm -rf /',
      'test.js && cat /etc/passwd',
      'test.js | grep secret',
      '$(whoami)',
      '`id`'
    ];

    for (const badArg of maliciousArgs) {
      assert.throws(
        () => restrictedRunner.validateCommandSafety('node', [badArg], tempWorkspace),
        (err) => {
          assert.strictEqual(err.name, 'UnsafeExecutionError');
          assert.match(err.message, /Command injection character/i);
          return true;
        }
      );
    }
  });

  it('4. rejects path traversal in arguments (../)', async () => {
    assert.throws(
      () => restrictedRunner.validateCommandSafety('node', ['../../etc/passwd'], tempWorkspace),
      (err) => {
        assert.strictEqual(err.name, 'UnsafeExecutionError');
        assert.match(err.message, /Path traversal is prohibited/i);
        return true;
      }
    );
  });

  it('5. rejects non-existent workspace directory', async () => {
    assert.throws(
      () => restrictedRunner.validateCommandSafety('node', ['--test'], '/non/existent/workspace/dir'),
      (err) => {
        assert.strictEqual(err.name, 'UnsafeExecutionError');
        assert.match(err.message, /does not exist/i);
        return true;
      }
    );
  });

  it('6. sanitizes environment variables and redacts secrets/keys', () => {
    const dirtyEnv = {
      CUSTOM_VAR: 'hello',
      GEMINI_API_KEY: 'secret_key_12345',
      DATABASE_PASSWORD: 'super_secret_pw',
      AUTH_TOKEN: 'bearer_token_xyz',
      API_SECRET: 'top_secret'
    };

    const cleanEnv = restrictedRunner.sanitizeEnvironment(dirtyEnv);
    assert.strictEqual(cleanEnv.CUSTOM_VAR, 'hello');
    assert.strictEqual(cleanEnv.NODE_ENV, 'test');
    assert.strictEqual(cleanEnv.GEMINI_API_KEY, undefined);
    assert.strictEqual(cleanEnv.DATABASE_PASSWORD, undefined);
    assert.strictEqual(cleanEnv.AUTH_TOKEN, undefined);
    assert.strictEqual(cleanEnv.API_SECRET, undefined);
  });

  it('7. executes a safe targeted node test inside the workspace successfully', async () => {
    // Write a sample passing unit test in temp workspace
    const testFile = path.join(tempWorkspace, 'sample.test.js');
    fs.writeFileSync(
      testFile,
      `const { test } = require('node:test');
const assert = require('node:assert/strict');
test('sample test passes', () => {
  assert.strictEqual(1 + 1, 2);
});`,
      'utf8'
    );

    const result = await restrictedRunner.runTargetedTest({
      workspacePath: tempWorkspace,
      testFile: 'sample.test.js',
      command: 'node'
    });

    assert.strictEqual(result.testsPassed, true);
    assert.strictEqual(result.exitCode, 0);
    assert.strictEqual(result.timedOut, false);
    assert.ok(result.durationMs >= 0);
    assert.deepStrictEqual(result.command, ['node', '--test', 'sample.test.js']);
  });

  it('8. reports failure cleanly when a targeted test fails', async () => {
    // Write a failing test
    const testFile = path.join(tempWorkspace, 'failing.test.js');
    fs.writeFileSync(
      testFile,
      `const { test } = require('node:test');
const assert = require('node:assert/strict');
test('failing test', () => {
  assert.strictEqual(1, 2);
});`,
      'utf8'
    );

    const result = await restrictedRunner.runTargetedTest({
      workspacePath: tempWorkspace,
      testFile: 'failing.test.js',
      command: 'node'
    });

    assert.strictEqual(result.testsPassed, false);
    assert.notStrictEqual(result.exitCode, 0);
  });

  it('9. enforces execution timeout and terminates runaway processes', async () => {
    // Test execution timeout with short limit
    const longRunningTest = path.join(tempWorkspace, 'timeout.test.js');
    fs.writeFileSync(
      longRunningTest,
      `const { test } = require('node:test');
test('times out', async () => {
  await new Promise(r => setTimeout(r, 5000));
});`,
      'utf8'
    );

    const result = await restrictedRunner.runTargetedTest({
      workspacePath: tempWorkspace,
      testFile: 'timeout.test.js',
      timeoutMs: 300
    });

    assert.strictEqual(result.timedOut, true);
    assert.strictEqual(result.testsPassed, false);
  });
});
