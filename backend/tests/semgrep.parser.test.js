const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const semgrepParser = require('../src/services/semgrep.parser');
const { validateNormalizedFindings, validateNormalizedFinding } = require('../src/validators/semgrep.schema');

describe('Semgrep JSON Parser', () => {
  const sampleFixturePath = path.join(__dirname, 'fixtures', 'sample-semgrep-output.json');
  const sampleRawJson = fs.readFileSync(sampleFixturePath, 'utf8');

  it('1. should parse valid Semgrep JSON output into normalized findings', () => {
    const result = semgrepParser.parse(sampleRawJson, {
      workspacePath: '/Users/host/project'
    });

    assert.strictEqual(result.errors.length, 0);
    assert.strictEqual(result.findings.length, 2);

    const first = result.findings[0];
    assert.strictEqual(first.scanner, 'semgrep');
    assert.strictEqual(first.ruleId, 'javascript.express.security.audit.sqli');
    assert.strictEqual(first.category, 'SQL_INJECTION');
    assert.strictEqual(first.severity, 'CRITICAL'); // mapped from security-severity 9.8
    assert.strictEqual(first.confidence, 'HIGH');
    assert.strictEqual(first.filePath, 'src/controllers/user.controller.js');
    assert.strictEqual(first.startLine, 42);
    assert.strictEqual(first.endLine, 42);
    assert.strictEqual(first.status, 'DETECTED');
    assert.ok(first.fingerprint && first.fingerprint.length === 64);

    // Validate entire array against Zod schema
    const validation = validateNormalizedFindings(result.findings);
    assert.ok(validation.success, `Schema validation failed: ${validation.error?.message}`);
  });

  it('2. should handle empty findings gracefully', () => {
    const emptyJson = JSON.stringify({
      version: '1.136.0',
      results: [],
      errors: [],
      paths: { scanned: ['index.js'] }
    });

    const result = semgrepParser.parse(emptyJson);
    assert.strictEqual(result.findings.length, 0);
    assert.strictEqual(result.errors.length, 0);
    assert.strictEqual(result.metadata.semgrepVersion, '1.136.0');
  });

  it('3. should handle multiple findings and preserve individual coordinates', () => {
    const multiJson = JSON.stringify({
      version: '1.136.0',
      results: [
        {
          check_id: 'rule.one',
          path: 'file1.js',
          start: { line: 10, col: 1 },
          end: { line: 12, col: 1 },
          extra: { severity: 'ERROR', message: 'First bug' }
        },
        {
          check_id: 'rule.two',
          path: 'file2.js',
          start: { line: 20, col: 1 },
          end: { line: 25, col: 1 },
          extra: { severity: 'WARNING', message: 'Second bug' }
        }
      ]
    });

    const result = semgrepParser.parse(multiJson);
    assert.strictEqual(result.findings.length, 2);
    assert.strictEqual(result.findings[0].ruleId, 'rule.one');
    assert.strictEqual(result.findings[0].startLine, 10);
    assert.strictEqual(result.findings[0].endLine, 12);
    assert.strictEqual(result.findings[1].ruleId, 'rule.two');
    assert.strictEqual(result.findings[1].startLine, 20);
    assert.strictEqual(result.findings[1].endLine, 25);
    assert.notStrictEqual(result.findings[0].id, result.findings[1].id);
  });

  it('4. should handle missing optional fields without failing', () => {
    const minimalJson = JSON.stringify({
      results: [
        {
          check_id: 'minimal.rule',
          path: 'test.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: {}
        }
      ]
    });

    const result = semgrepParser.parse(minimalJson);
    assert.strictEqual(result.findings.length, 1);
    const f = result.findings[0];
    assert.strictEqual(f.ruleId, 'minimal.rule');
    assert.strictEqual(f.severity, 'INFO');
    assert.strictEqual(f.confidence, 'UNKNOWN');
    assert.strictEqual(f.evidence, '');
    assert.ok(f.message.length > 0);
  });

  it('5. should handle invalid or malformed JSON safely without throwing', () => {
    const malformed = '{ invalid json string content :::';
    const result = semgrepParser.parse(malformed);

    assert.strictEqual(result.findings.length, 0);
    assert.strictEqual(result.errors.length, 1);
    assert.ok(result.errors[0].includes('Failed to parse Semgrep JSON output'));

    const emptyResult = semgrepParser.parse('');
    assert.strictEqual(emptyResult.findings.length, 0);
    assert.ok(emptyResult.errors.length > 0);
  });

  it('6. should map severity correctly and not conflate with confidence', () => {
    assert.strictEqual(semgrepParser.mapSeverity('ERROR'), 'HIGH');
    assert.strictEqual(semgrepParser.mapSeverity('WARNING'), 'MEDIUM');
    assert.strictEqual(semgrepParser.mapSeverity('INFO'), 'INFO');
    assert.strictEqual(semgrepParser.mapSeverity('LOW'), 'LOW');
    assert.strictEqual(semgrepParser.mapSeverity('CRITICAL'), 'CRITICAL');
    assert.strictEqual(semgrepParser.mapSeverity('ERROR', { 'security-severity': '9.5' }), 'CRITICAL');
    assert.strictEqual(semgrepParser.mapSeverity('ERROR', { 'security-severity': '4.5' }), 'MEDIUM');

    // Confidence mapping
    assert.strictEqual(semgrepParser.mapConfidence({ confidence: 'HIGH' }), 'HIGH');
    assert.strictEqual(semgrepParser.mapConfidence({ confidence: 'MEDIUM' }), 'MEDIUM');
    assert.strictEqual(semgrepParser.mapConfidence({ confidence: 'LOW' }), 'LOW');
    assert.strictEqual(semgrepParser.mapConfidence({}), 'UNKNOWN');
    assert.strictEqual(semgrepParser.mapConfidence({ severity: 'ERROR' }), 'UNKNOWN');
  });

  it('7. should normalize file paths relative to workspace and block path traversal', () => {
    const workspace = '/var/vulnex/workspaces/repo_001';

    // Absolute path containing workspace root
    const absPath = '/var/vulnex/workspaces/repo_001/src/routes/api.js';
    assert.strictEqual(
      semgrepParser.normalizeFilePath(absPath, workspace),
      'src/routes/api.js'
    );

    // Leading ./ or /
    assert.strictEqual(semgrepParser.normalizeFilePath('./src/index.js'), 'src/index.js');
    assert.strictEqual(semgrepParser.normalizeFilePath('/src/index.js'), 'src/index.js');

    // Windows backslashes
    assert.strictEqual(semgrepParser.normalizeFilePath('src\\utils\\helper.js'), 'src/utils/helper.js');

    // Path traversal removal
    assert.strictEqual(semgrepParser.normalizeFilePath('../../../etc/passwd'), 'etc/passwd');
    assert.strictEqual(semgrepParser.normalizeFilePath('src/../lib/index.js'), 'lib/index.js');
  });

  it('8. should produce stable, deterministic fingerprints', () => {
    const fp1 = semgrepParser.generateFingerprint('rule.sqli', 'src/db.js', 'SELECT *', 15);
    const fp2 = semgrepParser.generateFingerprint('rule.sqli', 'src/db.js', 'SELECT *', 15);
    const fpDiffLine = semgrepParser.generateFingerprint('rule.sqli', 'src/db.js', 'SELECT *', 16);
    const fpDiffFile = semgrepParser.generateFingerprint('rule.sqli', 'src/user.js', 'SELECT *', 15);

    assert.strictEqual(fp1, fp2, 'Fingerprints with same inputs must match exactly');
    assert.notStrictEqual(fp1, fpDiffLine, 'Fingerprints with different lines must differ');
    assert.notStrictEqual(fp1, fpDiffFile, 'Fingerprints with different files must differ');
  });

  it('9. should redact sensitive credential literals in evidence', () => {
    const raw = 'const secret = "super_secret_production_key_123456789";';
    const sanitized = semgrepParser.sanitizeEvidence(raw);
    assert.ok(!sanitized.includes('super_secret_production_key_123456789'));
    assert.ok(sanitized.includes('[REDACTED_SECRET]'));
  });
});
