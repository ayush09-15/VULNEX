const { describe, it } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const { SemgrepService, scanWithSemgrep } = require('../src/services/semgrep.service');
const processRunner = require('../src/utils/processRunner');

describe('Semgrep Service & Process Wrapper', () => {
  const service = new SemgrepService();
  const fixtureRepoPath = path.join(__dirname, 'fixtures', 'test-repo');

  it('1. should reject malicious or invalid workspace paths', async () => {
    // Non-existent path
    const res1 = service.validateWorkspace('/non/existent/path/for/vulnex/test');
    assert.strictEqual(res1.isValid, false);
    assert.ok(res1.error.includes('does not exist'));

    // Path traversal sequence
    const res2 = service.validateWorkspace('../../../outside/workspace');
    assert.strictEqual(res2.isValid, false);

    // Empty string
    const res3 = service.validateWorkspace('');
    assert.strictEqual(res3.isValid, false);

    // File instead of directory
    const filePath = path.join(__dirname, 'fixtures', 'sample-semgrep-output.json');
    const res4 = service.validateWorkspace(filePath);
    assert.strictEqual(res4.isValid, false);
    assert.ok(res4.error.includes('must be a directory'));

    // Null bytes
    const res5 = service.validateWorkspace('invalid\0path');
    assert.strictEqual(res5.isValid, false);
    assert.ok(res5.error.includes('invalid characters'));
  });

  it('2. should handle scanner execution against invalid workspace without crashing', async () => {
    const result = await service.scanWithSemgrep('/completely/invalid/directory/path');

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.status, 'FAILED');
    assert.strictEqual(result.scanner, 'semgrep');
    assert.strictEqual(result.findings.length, 0);
    assert.ok(result.errors.length > 0);
    assert.ok(result.errors[0].includes('Workspace validation failed'));
    assert.strictEqual(result.provenance.status, 'FAILED');
  });

  it('3. should handle missing or unavailable scanner binary gracefully', async () => {
    const customService = new SemgrepService();
    // Point binary to a guaranteed non-existent binary
    const result = await customService.scanWithSemgrep(fixtureRepoPath, {
      customBinary: '/usr/bin/non_existent_semgrep_bin_12345'
    });

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.status, 'FAILED');
    assert.ok(result.errors.length > 0);
    assert.strictEqual(result.provenance.status, 'FAILED');
  });

  it('4. should enforce scanner execution timeout', async () => {
    // Test ProcessRunner timeout mechanism directly with sleep command
    const timeoutResult = await processRunner.run('sleep', ['5'], {
      timeoutMs: 150
    });

    assert.strictEqual(timeoutResult.timedOut, true);
  });

  it('5. should enforce process output-size limits', async () => {
    // Process generating output larger than maxBufferBytes (limit to 100 bytes)
    await assert.rejects(
      async () => {
        await processRunner.run('yes', ['vulnex_security_payload_line'], {
          timeoutMs: 3000,
          maxBufferBytes: 150 // Very small limit for test
        });
      },
      (err) => {
        return err.message.includes('output limit exceeded');
      }
    );
  });

  it('6. should handle process crash or non-zero exit with invalid output', async () => {
    // Running a command that exits with code 1 and outputs invalid json
    const customService = new SemgrepService();
    // Using false or node -e "process.exit(1)"
    const result = await customService.scanWithSemgrep(fixtureRepoPath, {
      customBinary: 'node',
      config: 'none'
    });

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.status, 'FAILED');
    assert.ok(result.errors.length > 0);
  });

  it('7. should successfully execute against controlled fixture repository if semgrep available', async () => {
    const isInstalled = await service.isAvailable();
    if (!isInstalled) {
      console.log('Skipping live CLI test: Semgrep binary not available on this path');
      return;
    }

    const version = await service.getVersion();
    assert.ok(version, 'Semgrep version should be resolved');

    const result = await service.scanWithSemgrep(fixtureRepoPath, {
      config: 'auto',
      timeoutSeconds: 30
    });

    assert.ok(['COMPLETED', 'PARTIAL'].includes(result.status));
    assert.strictEqual(result.scanner, 'semgrep');
    assert.ok(Array.isArray(result.findings));
    assert.ok(result.provenance);
    assert.strictEqual(result.provenance.scanner, 'semgrep');
    assert.strictEqual(result.provenance.status, result.status);
  });
});

