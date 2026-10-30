const { describe, it } = require('node:test');
const assert = require('node:assert');
const semgrepProvenance = require('../src/services/semgrep.provenance');
const { validateProvenance } = require('../src/validators/semgrep.schema');

describe('Semgrep Provenance Generator', () => {
  it('1. should create a valid provenance record with complete scanner facts', () => {
    const timestamp = new Date().toISOString();
    const findings = [
      {
        id: 'find_001',
        ruleId: 'javascript.express.sqli',
        filePath: 'src/routes/user.js',
        startLine: 24,
        endLine: 24
      },
      {
        id: 'find_002',
        ruleId: 'generic.secrets.jwt',
        filePath: 'src/config/jwt.js',
        startLine: 12,
        endLine: 12
      }
    ];

    const record = semgrepProvenance.createRecord({
      scanId: 'scan_test_1001',
      version: '1.136.0',
      config: 'auto',
      timestamp,
      durationMs: 1420,
      exitCode: 0,
      status: 'COMPLETED',
      findings,
      errors: []
    });

    assert.strictEqual(record.scanner, 'semgrep');
    assert.strictEqual(record.version, '1.136.0');
    assert.strictEqual(record.config, 'auto');
    assert.strictEqual(record.scanId, 'scan_test_1001');
    assert.strictEqual(record.status, 'COMPLETED');
    assert.strictEqual(record.findingsCount, 2);
    assert.strictEqual(record.durationMs, 1420);
    assert.strictEqual(record.exitCode, 0);

    // Verify finding-to-rule traceability
    assert.strictEqual(record.ruleFindings.length, 2);
    assert.deepStrictEqual(record.ruleFindings[0], {
      findingId: 'find_001',
      ruleId: 'javascript.express.sqli',
      filePath: 'src/routes/user.js',
      startLine: 24,
      endLine: 24
    });

    // Validate with Zod schema
    const validation = validateProvenance(record);
    assert.ok(validation.success, `Provenance schema validation failed: ${validation.error?.message}`);
  });

  it('2. should capture scanner errors and warnings in provenance record', () => {
    const record = semgrepProvenance.createRecord({
      scanId: 'scan_warn_001',
      version: '1.136.0',
      config: 'p/default',
      timestamp: new Date().toISOString(),
      durationMs: 800,
      exitCode: 1,
      status: 'PARTIAL',
      findings: [],
      errors: ['Rule evaluation syntax warning on test.py']
    });

    assert.strictEqual(record.status, 'PARTIAL');
    assert.strictEqual(record.exitCode, 1);
    assert.strictEqual(record.errors.length, 1);
    assert.ok(record.errors[0].includes('syntax warning'));
  });

  it('3. should handle empty findings and null exit code safely', () => {
    const record = semgrepProvenance.createRecord({
      scanId: 'scan_empty_001',
      version: null,
      config: 'auto',
      timestamp: new Date().toISOString(),
      durationMs: 0,
      exitCode: null,
      status: 'FAILED',
      findings: [],
      errors: ['Scanner not found']
    });

    assert.strictEqual(record.status, 'FAILED');
    assert.strictEqual(record.findingsCount, 0);
    assert.strictEqual(record.exitCode, null);
    assert.strictEqual(record.version, null);
  });
});

