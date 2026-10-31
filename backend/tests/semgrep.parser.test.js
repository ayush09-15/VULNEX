const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const semgrepParser = require('../src/services/semgrep.parser');
const { validateNormalizedFindings } = require('../src/validators/semgrep.schema');

describe('Semgrep JSON Parser (Recorded Fixtures)', () => {
  const fixturesDir = path.join(__dirname, 'fixtures');

  // Load recorded JSON fixtures
  const multipleFindingsJson = fs.readFileSync(path.join(fixturesDir, 'semgrep-multiple-findings.json'), 'utf8');
  const sqliXssJson = fs.readFileSync(path.join(fixturesDir, 'semgrep-sqli-xss.json'), 'utf8');
  const emptyJson = fs.readFileSync(path.join(fixturesDir, 'semgrep-empty.json'), 'utf8');
  const missingFieldsJson = fs.readFileSync(path.join(fixturesDir, 'semgrep-missing-fields.json'), 'utf8');
  const malformedJson = fs.readFileSync(path.join(fixturesDir, 'semgrep-malformed.json'), 'utf8');

  it('1. should parse recorded multiple-findings fixture extracting all required fields', () => {
    const result = semgrepParser.parse(multipleFindingsJson, {
      workspacePath: '/Users/host/project'
    });

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.isValidJson, true);
    assert.strictEqual(result.findings.length, 3);
    assert.strictEqual(result.errors.length, 0);

    const first = result.findings[0];
    assert.strictEqual(first.ruleId, 'javascript.express.security.audit.sqli');
    assert.strictEqual(first.severity, 'HIGH');
    assert.ok(first.message.includes('SQL query'));
    assert.strictEqual(first.filePath, 'src/controllers/user.controller.js');
    assert.strictEqual(first.startLine, 42);
    assert.strictEqual(first.endLine, 42);
    assert.strictEqual(first.startCol, 5);
    assert.strictEqual(first.endCol, 85);
    assert.ok(first.codeSnippet.includes('SELECT * FROM users'));
    assert.ok(first.metadata);
    assert.ok(Array.isArray(first.references));
    assert.ok(first.references.length > 0);

    // Validate with Zod canonical schema
    const validation = validateNormalizedFindings(result.findings);
    assert.ok(validation.success, `Schema validation failed: ${validation.error?.message}`);
  });

  it('2. should parse recorded SQL Injection and XSS fixture accurately', () => {
    const result = semgrepParser.parse(sqliXssJson, {
      workspacePath: 'fixtures'
    });

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.isValidJson, true);
    assert.strictEqual(result.findings.length, 2);

    // Verify SQLi finding
    const sqliFinding = result.findings.find(f => f.ruleId === 'javascript.express.security.audit.sqli');
    assert.ok(sqliFinding, 'SQLi finding must be parsed');
    assert.strictEqual(sqliFinding.category, 'SQL_INJECTION');
    assert.strictEqual(sqliFinding.severity, 'HIGH');
    assert.strictEqual(sqliFinding.startLine, 46);
    assert.ok(sqliFinding.codeSnippet.includes('SELECT id, username'));
    assert.ok(sqliFinding.references.some(r => r.includes('SQL_Injection')));

    // Verify XSS finding
    const xssFinding = result.findings.find(f => f.ruleId === 'javascript.express.security.injection.raw-html-format.raw-html-format');
    assert.ok(xssFinding, 'XSS finding must be parsed');
    assert.strictEqual(xssFinding.category, 'XSS');
    assert.strictEqual(xssFinding.severity, 'MEDIUM');
    assert.strictEqual(xssFinding.startLine, 79);
    assert.strictEqual(xssFinding.endLine, 80);
    assert.ok(xssFinding.codeSnippet.includes('send(htmlResponse)'));
    assert.ok(xssFinding.references.some(r => r.includes('xss')));
  });

  it('3. should distinguish valid empty JSON from invalid JSON', () => {
    const emptyResult = semgrepParser.parse(emptyJson);

    assert.strictEqual(emptyResult.success, true);
    assert.strictEqual(emptyResult.isValidJson, true);
    assert.strictEqual(emptyResult.findings.length, 0);
    assert.strictEqual(emptyResult.errors.length, 0);
    assert.ok(emptyResult.metadata);
    assert.strictEqual(emptyResult.metadata.version, '1.136.0');
    assert.strictEqual(emptyResult.metadata.pathsScanned.length, 2);

    // Malformed JSON should return isValidJson: false
    const malformedResult = semgrepParser.parse(malformedJson);
    assert.strictEqual(malformedResult.success, false);
    assert.strictEqual(malformedResult.isValidJson, false);
    assert.strictEqual(malformedResult.findings.length, 0);
    assert.ok(malformedResult.errors.length > 0);
    assert.strictEqual(malformedResult.metadata, null);
  });

  it('4. should handle missing optional fields safely without inventing values', () => {
    const result = semgrepParser.parse(missingFieldsJson);

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.isValidJson, true);
    assert.strictEqual(result.findings.length, 1);

    const f = result.findings[0];
    assert.strictEqual(f.ruleId, 'minimal.rule.no.optional.fields');
    assert.strictEqual(f.severity, 'INFO');
    assert.strictEqual(f.codeSnippet, null, 'codeSnippet must be null when lines missing');
    assert.strictEqual(f.metadata, null, 'metadata must be null when missing');
    assert.deepStrictEqual(f.references, [], 'references must be empty array when missing');
    assert.strictEqual(f.startCol, 1);
    assert.strictEqual(f.endCol, 10);
  });

  it('5. should handle null, undefined, and empty string input gracefully', () => {
    const nullRes = semgrepParser.parse(null);
    assert.strictEqual(nullRes.success, false);
    assert.strictEqual(nullRes.isValidJson, false);

    const emptyRes = semgrepParser.parse('');
    assert.strictEqual(emptyRes.success, false);
    assert.strictEqual(emptyRes.isValidJson, false);
  });

  it('6. should normalize relative file paths and prevent host path leakage', () => {
    const rawPath = '/var/vulnex/workspaces/app/src/utils/sanitize.js';
    const normalized = semgrepParser.normalizeFilePath(rawPath, '/var/vulnex/workspaces/app');
    assert.strictEqual(normalized, 'src/utils/sanitize.js');

    assert.strictEqual(semgrepParser.normalizeFilePath('./src/index.js'), 'src/index.js');
    assert.strictEqual(semgrepParser.normalizeFilePath('/src/index.js'), 'src/index.js');
    assert.strictEqual(semgrepParser.normalizeFilePath('../../../etc/passwd'), 'etc/passwd');
  });

  it('7. should map severity consistently without conflating with confidence', () => {
    assert.strictEqual(semgrepParser.mapSeverity('ERROR'), 'HIGH');
    assert.strictEqual(semgrepParser.mapSeverity('WARNING'), 'MEDIUM');
    assert.strictEqual(semgrepParser.mapSeverity('INFO'), 'INFO');
    assert.strictEqual(semgrepParser.mapSeverity('LOW'), 'LOW');
    assert.strictEqual(semgrepParser.mapSeverity('CRITICAL'), 'CRITICAL');
    assert.strictEqual(semgrepParser.mapSeverity('ERROR', { 'security-severity': '9.5' }), 'CRITICAL');

    assert.strictEqual(semgrepParser.mapConfidence({ confidence: 'HIGH' }), 'HIGH');
    assert.strictEqual(semgrepParser.mapConfidence({ confidence: 'LOW' }), 'LOW');
    assert.strictEqual(semgrepParser.mapConfidence({}), 'UNKNOWN');
  });
});
