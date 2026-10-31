const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const findingNormalizer = require('../src/services/finding.normalizer');
const semgrepParser = require('../src/services/semgrep.parser');
const {
  validateCommonFinding,
  validateCommonFindings,
  CommonFindingSchema
} = require('../src/validators/commonFinding.schema');

describe('VULNEX Common Finding Normalizer & Schema', () => {
  const fixturesDir = path.join(__dirname, 'fixtures');
  const multipleFindingsJson = fs.readFileSync(path.join(fixturesDir, 'semgrep-multiple-findings.json'), 'utf8');
  const sqliXssJson = fs.readFileSync(path.join(fixturesDir, 'semgrep-sqli-xss.json'), 'utf8');

  // --------------------------------------------------------------------------
  // 1. Valid Findings Normalization from Semgrep Parser Output
  // --------------------------------------------------------------------------
  describe('1. Valid Findings Normalization from Semgrep Parser Output', () => {
    it('should normalize Semgrep parser output object into Common Finding Schema with fingerprints', () => {
      const parseResult = semgrepParser.parse(multipleFindingsJson, {
        workspacePath: '/Users/host/project'
      });
      assert.strictEqual(parseResult.findings.length, 3);

      const normalizedResult = findingNormalizer.normalize(parseResult);

      assert.strictEqual(normalizedResult.success, true);
      assert.strictEqual(normalizedResult.findings.length, 3);
      assert.strictEqual(normalizedResult.errors.length, 0);
      assert.strictEqual(normalizedResult.metadata.total, 3);
      assert.strictEqual(normalizedResult.metadata.valid, 3);
      assert.strictEqual(normalizedResult.metadata.duplicates, 0);
      assert.strictEqual(normalizedResult.metadata.unique, 3);
      assert.strictEqual(normalizedResult.metadata.invalid, 0);

      // Verify each finding has all required normalized fields including fingerprint
      normalizedResult.findings.forEach((finding) => {
        assert.ok(typeof finding.rule === 'string' && finding.rule.length > 0, 'rule must be a non-empty string');
        assert.ok(typeof finding.path === 'string' && finding.path.length > 0, 'path must be a non-empty string');
        assert.ok(Number.isInteger(finding.startLine) && finding.startLine >= 1, 'startLine must be integer >= 1');
        assert.ok(Number.isInteger(finding.endLine) && finding.endLine >= finding.startLine, 'endLine must be integer >= startLine');
        assert.ok(typeof finding.message === 'string', 'message must be a string');
        assert.ok(finding.evidence !== undefined && finding.evidence !== null, 'evidence must be defined');
        assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(finding.severity), 'severity must be valid enum');
        assert.ok(['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].includes(finding.confidence), 'confidence must be valid enum');

        // Verify deterministic 64-char SHA-256 fingerprint
        assert.ok(typeof finding.fingerprint === 'string', 'fingerprint must be a string');
        assert.strictEqual(finding.fingerprint.length, 64, 'fingerprint must be 64-char hex string');
        assert.match(finding.fingerprint, /^[a-f0-9]{64}$/, 'fingerprint must be valid lowercase sha256 hex');

        // Validate individual record with CommonFindingSchema
        const validation = validateCommonFinding(finding);
        assert.strictEqual(validation.success, true, `Validation failed: ${validation.error?.message}`);
      });

      // Validate entire collection with validateCommonFindings
      const arrayVal = validateCommonFindings(normalizedResult.findings);
      assert.strictEqual(arrayVal.success, true);
    });

    it('should accurately preserve rule ID, relative path, line range, message, and evidence', () => {
      const parseResult = semgrepParser.parse(sqliXssJson, {
        workspacePath: 'fixtures'
      });
      const normalizedResult = findingNormalizer.normalize(parseResult);

      assert.strictEqual(normalizedResult.findings.length, 2);

      const sqli = normalizedResult.findings.find(f => f.rule === 'javascript.express.security.audit.sqli');
      assert.ok(sqli, 'SQLi finding must be present');
      assert.strictEqual(sqli.rule, 'javascript.express.security.audit.sqli');
      assert.strictEqual(sqli.path, 'server.js');
      assert.strictEqual(sqli.startLine, 46);
      assert.strictEqual(sqli.endLine, 46);
      assert.ok(sqli.message.includes('SQL query'));
      assert.ok(sqli.evidence.includes('SELECT id, username'));
      assert.strictEqual(sqli.severity, 'HIGH');
      assert.strictEqual(sqli.confidence, 'HIGH');
      assert.ok(sqli.fingerprint && sqli.fingerprint.length === 64);

      const xss = normalizedResult.findings.find(f => f.rule.includes('raw-html-format'));
      assert.ok(xss, 'XSS finding must be present');
      assert.strictEqual(xss.path, 'server.js');
      assert.strictEqual(xss.startLine, 79);
      assert.strictEqual(xss.endLine, 80);
      assert.ok(xss.evidence.includes('send(htmlResponse)'));
      assert.strictEqual(xss.severity, 'MEDIUM');
      assert.strictEqual(xss.confidence, 'MEDIUM');
      assert.ok(xss.fingerprint && xss.fingerprint.length === 64);
    });

    it('should normalize array of findings directly', () => {
      const parseResult = semgrepParser.parse(sqliXssJson);
      const normalized = findingNormalizer.normalize(parseResult.findings);

      assert.strictEqual(normalized.success, true);
      assert.strictEqual(normalized.findings.length, 2);
    });

    it('should accept raw Semgrep CLI result items directly', () => {
      const rawItem = {
        check_id: 'javascript.lang.security.audit.detect-eval-with-expr',
        path: 'src/eval.js',
        start: { line: 12, col: 3 },
        end: { line: 12, col: 25 },
        extra: {
          message: 'Detected eval() with dynamic expression',
          severity: 'ERROR',
          lines: 'eval(userInput);',
          metadata: {
            cwe: ['CWE-95'],
            confidence: 'HIGH'
          }
        }
      };

      const result = findingNormalizer.normalizeFinding(rawItem);
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.data.rule, 'javascript.lang.security.audit.detect-eval-with-expr');
      assert.strictEqual(result.data.path, 'src/eval.js');
      assert.strictEqual(result.data.startLine, 12);
      assert.strictEqual(result.data.endLine, 12);
      assert.strictEqual(result.data.startCol, 3);
      assert.strictEqual(result.data.endCol, 25);
      assert.strictEqual(result.data.severity, 'HIGH');
      assert.strictEqual(result.data.confidence, 'HIGH');
      assert.strictEqual(result.data.evidence, 'eval(userInput);');
      assert.ok(result.data.fingerprint && result.data.fingerprint.length === 64);
      assert.deepStrictEqual(result.data.metadata.cwe, ['CWE-95']);
    });
  });

  // --------------------------------------------------------------------------
  // 2. Safe Handling of Missing Optional Fields
  // --------------------------------------------------------------------------
  describe('2. Safe Handling of Missing Optional Fields', () => {
    it('should safely default optional fields when missing', () => {
      const minimalRecord = {
        rule: 'generic.rule.minimal',
        path: 'src/minimal.js',
        startLine: 10
      };

      const result = findingNormalizer.normalizeFinding(minimalRecord);
      assert.strictEqual(result.success, true);

      const f = result.data;
      assert.strictEqual(f.rule, 'generic.rule.minimal');
      assert.strictEqual(f.path, 'src/minimal.js');
      assert.strictEqual(f.startLine, 10);
      assert.strictEqual(f.endLine, 10, 'endLine must safely default to startLine');
      assert.strictEqual(f.message, 'Security finding detected by rule generic.rule.minimal');
      assert.strictEqual(f.evidence, '', 'evidence must safely default to empty string');
      assert.strictEqual(f.severity, 'INFO', 'severity must default safely to INFO');
      assert.strictEqual(f.confidence, 'UNKNOWN', 'confidence must default safely to UNKNOWN');
      assert.strictEqual(f.metadata, null, 'metadata must be null when omitted');
      assert.deepStrictEqual(f.references, [], 'references must default to empty array');
      assert.strictEqual(f.startCol, null);
      assert.strictEqual(f.endCol, null);
      assert.strictEqual(f.codeSnippet, null);
      assert.ok(f.fingerprint && f.fingerprint.length === 64, 'fingerprint must be generated even without evidence');
    });

    it('should handle record with empty metadata or empty strings safely', () => {
      const record = {
        ruleId: 'rule.test',
        filePath: 'test.js',
        startLine: 1,
        endLine: 2,
        message: '',
        evidence: '',
        metadata: {},
        references: []
      };

      const result = findingNormalizer.normalizeFinding(record);
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.data.startLine, 1);
      assert.strictEqual(result.data.endLine, 2);
      assert.ok(result.data.fingerprint && result.data.fingerprint.length === 64);
    });
  });

  // --------------------------------------------------------------------------
  // 3. Severity Mapping
  // --------------------------------------------------------------------------
  describe('3. Deterministic Severity Mapping', () => {
    it('should map exact VULNEX severities preserving values', () => {
      assert.strictEqual(findingNormalizer.mapSeverity('CRITICAL'), 'CRITICAL');
      assert.strictEqual(findingNormalizer.mapSeverity('HIGH'), 'HIGH');
      assert.strictEqual(findingNormalizer.mapSeverity('MEDIUM'), 'MEDIUM');
      assert.strictEqual(findingNormalizer.mapSeverity('LOW'), 'LOW');
      assert.strictEqual(findingNormalizer.mapSeverity('INFO'), 'INFO');
    });

    it('should map case-insensitively', () => {
      assert.strictEqual(findingNormalizer.mapSeverity('critical'), 'CRITICAL');
      assert.strictEqual(findingNormalizer.mapSeverity('High'), 'HIGH');
      assert.strictEqual(findingNormalizer.mapSeverity('medium'), 'MEDIUM');
      assert.strictEqual(findingNormalizer.mapSeverity('low'), 'LOW');
      assert.strictEqual(findingNormalizer.mapSeverity('info'), 'INFO');
    });

    it('should map scanner synonyms correctly', () => {
      assert.strictEqual(findingNormalizer.mapSeverity('ERROR'), 'HIGH');
      assert.strictEqual(findingNormalizer.mapSeverity('MAJOR'), 'HIGH');
      assert.strictEqual(findingNormalizer.mapSeverity('FATAL'), 'CRITICAL');
      assert.strictEqual(findingNormalizer.mapSeverity('BLOCKER'), 'CRITICAL');
      assert.strictEqual(findingNormalizer.mapSeverity('WARNING'), 'MEDIUM');
      assert.strictEqual(findingNormalizer.mapSeverity('WARN'), 'MEDIUM');
      assert.strictEqual(findingNormalizer.mapSeverity('MODERATE'), 'MEDIUM');
      assert.strictEqual(findingNormalizer.mapSeverity('MINOR'), 'LOW');
      assert.strictEqual(findingNormalizer.mapSeverity('NOTE'), 'INFO');
      assert.strictEqual(findingNormalizer.mapSeverity('INFORMATIONAL'), 'INFO');
      assert.strictEqual(findingNormalizer.mapSeverity('EXPERIMENT'), 'INFO');
      assert.strictEqual(findingNormalizer.mapSeverity('INVENTORY'), 'INFO');
    });

    it('should elevate ERROR to CRITICAL when metadata impact is CRITICAL', () => {
      assert.strictEqual(
        findingNormalizer.mapSeverity('ERROR', { impact: 'CRITICAL' }),
        'CRITICAL'
      );
      assert.strictEqual(
        findingNormalizer.mapSeverity('WARNING', { impact: 'CRITICAL' }),
        'CRITICAL'
      );
    });

    it('should elevate severity when CVSS or security-severity is high', () => {
      assert.strictEqual(
        findingNormalizer.mapSeverity('ERROR', { 'security-severity': '9.8' }),
        'CRITICAL'
      );
      assert.strictEqual(
        findingNormalizer.mapSeverity('INFO', { 'security-severity': '7.5' }),
        'HIGH'
      );
      assert.strictEqual(
        findingNormalizer.mapSeverity('INFO', { cvss: '5.5' }),
        'MEDIUM'
      );
      assert.strictEqual(
        findingNormalizer.mapSeverity('INFO', { score: '2.0' }),
        'LOW'
      );
    });

    it('should fallback to INFO for missing or unrecognizable severity', () => {
      assert.strictEqual(findingNormalizer.mapSeverity(null), 'INFO');
      assert.strictEqual(findingNormalizer.mapSeverity(undefined), 'INFO');
      assert.strictEqual(findingNormalizer.mapSeverity(''), 'INFO');
      assert.strictEqual(findingNormalizer.mapSeverity('unknown_level_123'), 'INFO');
    });
  });

  // --------------------------------------------------------------------------
  // 4. Confidence Mapping (Never Invent Confidence)
  // --------------------------------------------------------------------------
  describe('4. Deterministic Confidence Mapping (Never Invent Confidence)', () => {
    it('should map explicit confidence when provided', () => {
      assert.strictEqual(findingNormalizer.mapConfidence({}, 'HIGH'), 'HIGH');
      assert.strictEqual(findingNormalizer.mapConfidence({}, 'MEDIUM'), 'MEDIUM');
      assert.strictEqual(findingNormalizer.mapConfidence({}, 'LOW'), 'LOW');
      assert.strictEqual(findingNormalizer.mapConfidence({}, 'UNKNOWN'), 'UNKNOWN');
      assert.strictEqual(findingNormalizer.mapConfidence({}, 'high'), 'HIGH');
    });

    it('should map metadata confidence when explicit confidence is omitted', () => {
      assert.strictEqual(findingNormalizer.mapConfidence({ confidence: 'HIGH' }), 'HIGH');
      assert.strictEqual(findingNormalizer.mapConfidence({ confidence: 'medium' }), 'MEDIUM');
      assert.strictEqual(findingNormalizer.mapConfidence({ confidence: 'LOW' }), 'LOW');
    });

    it('should NEVER invent confidence when omitted: must map to UNKNOWN', () => {
      assert.strictEqual(
        findingNormalizer.mapConfidence({}),
        'UNKNOWN',
        'Must return UNKNOWN when confidence is absent from metadata'
      );
      assert.strictEqual(
        findingNormalizer.mapConfidence(null),
        'UNKNOWN',
        'Must return UNKNOWN when metadata is null'
      );
      assert.strictEqual(
        findingNormalizer.mapConfidence({}, null),
        'UNKNOWN',
        'Must return UNKNOWN when both metadata and explicit confidence are null'
      );
    });

    it('should return UNKNOWN for unrecognized confidence strings', () => {
      assert.strictEqual(findingNormalizer.mapConfidence({ confidence: 'ABSOLUTE' }), 'UNKNOWN');
      assert.strictEqual(findingNormalizer.mapConfidence({ confidence: 100 }), 'UNKNOWN');
      assert.strictEqual(findingNormalizer.mapConfidence({}, 'CERTAIN'), 'UNKNOWN');
    });
  });

  // --------------------------------------------------------------------------
  // 5. Graceful Handling of Malformed Scanner Records
  // --------------------------------------------------------------------------
  describe('5. Graceful Handling of Malformed Scanner Records', () => {
    it('should reject non-object records safely', () => {
      const resNull = findingNormalizer.normalizeFinding(null);
      assert.strictEqual(resNull.success, false);
      assert.ok(resNull.error.includes('non-null object'));

      const resStr = findingNormalizer.normalizeFinding('not an object');
      assert.strictEqual(resStr.success, false);

      const resArr = findingNormalizer.normalizeFinding([1, 2, 3]);
      assert.strictEqual(resArr.success, false);
    });

    it('should reject records missing rule identifier', () => {
      const res = findingNormalizer.normalizeFinding({
        path: 'src/app.js',
        startLine: 10
      });
      assert.strictEqual(res.success, false);
      assert.ok(res.error.includes('Rule identifier is required'));
    });

    it('should reject records missing file path', () => {
      const res = findingNormalizer.normalizeFinding({
        rule: 'test.rule',
        startLine: 10
      });
      assert.strictEqual(res.success, false);
      assert.ok(res.error.includes('File path is required'));
    });

    it('should reject records with path traversal sequences', () => {
      const res = findingNormalizer.normalizeFinding({
        rule: 'test.rule',
        path: '../../etc/passwd',
        startLine: 1
      });
      assert.strictEqual(res.success, false);
      assert.ok(res.error.includes('traversal sequences'));
    });

    it('should reject records with invalid startLine (zero or negative)', () => {
      const resZero = findingNormalizer.normalizeFinding({
        rule: 'test.rule',
        path: 'src/app.js',
        startLine: 0
      });
      assert.strictEqual(resZero.success, false);
      assert.ok(resZero.error.includes('startLine'));

      const resNeg = findingNormalizer.normalizeFinding({
        rule: 'test.rule',
        path: 'src/app.js',
        startLine: -5
      });
      assert.strictEqual(resNeg.success, false);
    });

    it('should reject records where endLine is less than startLine', () => {
      const res = findingNormalizer.normalizeFinding({
        rule: 'test.rule',
        path: 'src/app.js',
        startLine: 20,
        endLine: 10
      });
      assert.strictEqual(res.success, false);
      assert.ok(res.error.includes('endLine'));
    });

    it('should process a mixed batch, preserving valid findings and reporting errors', () => {
      const mixedBatch = [
        {
          rule: 'valid.rule.1',
          path: 'src/valid1.js',
          startLine: 5,
          endLine: 5,
          message: 'Valid finding 1'
        },
        null, // Malformed 1
        {
          rule: '', // Malformed 2: empty rule
          path: 'src/invalid.js',
          startLine: 1
        },
        {
          rule: 'valid.rule.2',
          path: 'src/valid2.js',
          startLine: 10,
          endLine: 15,
          message: 'Valid finding 2'
        },
        {
          rule: 'invalid.lines',
          path: 'src/lines.js',
          startLine: 50,
          endLine: 40 // Malformed 3: endLine < startLine
        }
      ];

      const result = findingNormalizer.normalize(mixedBatch);

      assert.strictEqual(result.success, false, 'Batch should report partial failure due to errors');
      assert.strictEqual(result.findings.length, 2, 'Must preserve 2 valid findings');
      assert.strictEqual(result.errors.length, 3, 'Must report 3 errors for invalid items');
      assert.strictEqual(result.metadata.total, 5);
      assert.strictEqual(result.metadata.valid, 2);
      assert.strictEqual(result.metadata.invalid, 3);

      assert.strictEqual(result.findings[0].rule, 'valid.rule.1');
      assert.strictEqual(result.findings[1].rule, 'valid.rule.2');
    });

    it('should handle null, undefined, or empty batch gracefully', () => {
      const nullBatch = findingNormalizer.normalize(null);
      assert.strictEqual(nullBatch.success, false);
      assert.strictEqual(nullBatch.findings.length, 0);

      const emptyBatch = findingNormalizer.normalize([]);
      assert.strictEqual(emptyBatch.success, true);
      assert.strictEqual(emptyBatch.findings.length, 0);
      assert.strictEqual(emptyBatch.metadata.total, 0);
    });
  });

  // --------------------------------------------------------------------------
  // 6. Preservation of Scanner-Specific Metadata & passthrough
  // --------------------------------------------------------------------------
  describe('6. Preservation of Scanner Metadata without Breaking Common Schema', () => {
    it('should preserve scanner metadata, references, column coordinates, and custom attributes', () => {
      const record = {
        ruleId: 'semgrep.audit.jwt',
        filePath: 'src/auth/jwt.js',
        startLine: 35,
        endLine: 38,
        startCol: 4,
        endCol: 42,
        scanner: 'semgrep',
        category: 'BROKEN_AUTH',
        title: 'Hardcoded JWT Secret',
        metadata: {
          cwe: ['CWE-798', 'CWE-259'],
          owasp: ['A02:2021 - Cryptographic Failures'],
          confidence: 'HIGH',
          impact: 'HIGH',
          technology: ['jwt', 'express']
        },
        references: [
          'https://cwe.mitre.org/data/definitions/798.html'
        ],
        customScannerFlag: true,
        executionPass: 1
      };

      const result = findingNormalizer.normalizeFinding(record);
      assert.strictEqual(result.success, true);

      const f = result.data;
      assert.strictEqual(f.rule, 'semgrep.audit.jwt');
      assert.strictEqual(f.path, 'src/auth/jwt.js');
      assert.strictEqual(f.startCol, 4);
      assert.strictEqual(f.endCol, 42);
      assert.strictEqual(f.scanner, 'semgrep');
      assert.strictEqual(f.category, 'BROKEN_AUTH');
      assert.strictEqual(f.title, 'Hardcoded JWT Secret');
      assert.deepStrictEqual(f.metadata.cwe, ['CWE-798', 'CWE-259']);
      assert.strictEqual(f.references[0], 'https://cwe.mitre.org/data/definitions/798.html');
      assert.strictEqual(f.customScannerFlag, true);
      assert.strictEqual(f.executionPass, 1);
      assert.ok(f.fingerprint && f.fingerprint.length === 64);
    });
  });

  // --------------------------------------------------------------------------
  // 7. Stable Fingerprints & Deduplication Invariants (Requirement 10)
  // --------------------------------------------------------------------------
  describe('7. Stable Fingerprints & Deduplication Invariants', () => {
    it('1. Same issue produces the same fingerprint across runs', () => {
      const issueA = {
        rule: 'javascript.express.security.audit.sqli',
        path: 'src/routes/users.js',
        startLine: 42,
        endLine: 42,
        message: 'Unsafe SQL query interpolation',
        evidence: 'const q = `SELECT * FROM users WHERE id = ${req.params.id}`;'
      };

      const issueB = {
        rule: 'javascript.express.security.audit.sqli',
        path: 'src/routes/users.js',
        startLine: 42,
        endLine: 42,
        message: 'Unsafe SQL query interpolation',
        evidence: 'const q = `SELECT * FROM users WHERE id = ${req.params.id}`;'
      };

      const resA = findingNormalizer.normalizeFinding(issueA);
      const resB = findingNormalizer.normalizeFinding(issueB);

      assert.strictEqual(resA.success, true);
      assert.strictEqual(resB.success, true);
      assert.strictEqual(resA.data.fingerprint, resB.data.fingerprint, 'Identical issues must have identical fingerprints');
    });

    it('2. Different issues produce different fingerprints', () => {
      const sqliIssue = {
        rule: 'javascript.express.security.audit.sqli',
        path: 'src/routes/users.js',
        startLine: 42,
        evidence: 'db.query(sql);'
      };

      const xssIssue = {
        rule: 'javascript.express.security.audit.xss',
        path: 'src/routes/users.js',
        startLine: 42,
        evidence: 'res.send(html);'
      };

      const resSqli = findingNormalizer.normalizeFinding(sqliIssue);
      const resXss = findingNormalizer.normalizeFinding(xssIssue);

      assert.notStrictEqual(resSqli.data.fingerprint, resXss.data.fingerprint, 'Different rules must produce different fingerprints');
    });

    it('3. Line-number changes do not automatically create a new fingerprint', () => {
      // Line shift caused by unrelated edits (e.g., adding imports or comments above)
      const findingOriginalLine = {
        rule: 'javascript.express.security.audit.sqli',
        path: 'src/controllers/order.controller.js',
        startLine: 25,
        endLine: 26,
        message: 'User input formatted into query string',
        evidence: 'const sql = "SELECT * FROM orders WHERE id = " + id;'
      };

      const findingShiftedLine = {
        rule: 'javascript.express.security.audit.sqli',
        path: 'src/controllers/order.controller.js',
        startLine: 78, // 53 lines lower due to unrelated changes
        endLine: 79,
        message: 'User input formatted into query string',
        evidence: 'const sql = "SELECT * FROM orders WHERE id = " + id;'
      };

      const res1 = findingNormalizer.normalizeFinding(findingOriginalLine);
      const res2 = findingNormalizer.normalizeFinding(findingShiftedLine);

      assert.strictEqual(res1.success, true);
      assert.strictEqual(res2.success, true);
      assert.strictEqual(
        res1.data.fingerprint,
        res2.data.fingerprint,
        'Fingerprint MUST remain stable when line numbers shift due to unrelated edits'
      );
    });

    it('4. Different files produce different fingerprints', () => {
      const fileA = {
        rule: 'security.hardcoded-key',
        path: 'src/auth/token.js',
        startLine: 10,
        evidence: 'const secret = "abc1234567890";'
      };

      const fileB = {
        rule: 'security.hardcoded-key',
        path: 'src/config/keys.js',
        startLine: 10,
        evidence: 'const secret = "abc1234567890";'
      };

      const resA = findingNormalizer.normalizeFinding(fileA);
      const resB = findingNormalizer.normalizeFinding(fileB);

      assert.notStrictEqual(
        resA.data.fingerprint,
        resB.data.fingerprint,
        'Same vulnerability in different files must have different fingerprints'
      );
    });

    it('5. Duplicate findings are removed while preserving useful metadata', () => {
      const originalFinding = {
        rule: 'javascript.express.security.audit.sqli',
        path: 'src/db.js',
        startLine: 15,
        endLine: 15,
        message: 'SQL injection detected',
        evidence: 'db.query(sql);',
        metadata: { scannerVersion: '1.136.0', cwe: ['CWE-89'] },
        references: ['https://cwe.mitre.org/data/definitions/89.html']
      };

      const duplicateFinding = {
        rule: 'javascript.express.security.audit.sqli',
        path: 'src/db.js',
        startLine: 35, // shifted line
        endLine: 35,
        message: 'SQL injection detected',
        evidence: 'db.query(sql);',
        metadata: { owasp: ['A03:2021-Injection'] }, // extra metadata
        references: ['https://owasp.org/Top10/A03_2021-Injection/'] // extra reference
      };

      const batch = [originalFinding, duplicateFinding];
      const result = findingNormalizer.normalize(batch);

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.findings.length, 1, 'Duplicate finding must be removed');
      assert.strictEqual(result.metadata.total, 2);
      assert.strictEqual(result.metadata.valid, 2);
      assert.strictEqual(result.metadata.duplicates, 1);
      assert.strictEqual(result.metadata.unique, 1);

      const merged = result.findings[0];
      assert.strictEqual(merged.duplicateCount, 2, 'Must record occurrence count');

      // Verify metadata was merged
      assert.ok(merged.metadata.cwe, 'Original metadata preserved');
      assert.ok(merged.metadata.owasp, 'Duplicate metadata merged');

      // Verify references were merged without duplicates
      assert.strictEqual(merged.references.length, 2, 'References must be combined');
      assert.ok(merged.references.includes('https://cwe.mitre.org/data/definitions/89.html'));
      assert.ok(merged.references.includes('https://owasp.org/Top10/A03_2021-Injection/'));
    });

    it('6. Distinct findings sharing a rule or file are preserved', () => {
      // Two distinct SQL injection vulnerabilities in the SAME file
      const vuln1 = {
        rule: 'javascript.express.security.audit.sqli',
        path: 'src/controllers/user.controller.js',
        startLine: 30,
        endLine: 30,
        message: 'Unsafe SQL query in findUser',
        evidence: 'const query = "SELECT * FROM users WHERE id = " + userId;'
      };

      const vuln2 = {
        rule: 'javascript.express.security.audit.sqli',
        path: 'src/controllers/user.controller.js',
        startLine: 65,
        endLine: 65,
        message: 'Unsafe SQL query in deleteUser',
        evidence: 'const query = "DELETE FROM users WHERE email = " + userEmail;'
      };

      const batch = [vuln1, vuln2];
      const result = findingNormalizer.normalize(batch);

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.findings.length, 2, 'Distinct vulnerabilities must NOT be merged');
      assert.notStrictEqual(
        result.findings[0].fingerprint,
        result.findings[1].fingerprint,
        'Distinct findings must have different fingerprints'
      );
      assert.strictEqual(result.metadata.duplicates, 0);
      assert.strictEqual(result.metadata.unique, 2);
    });

    it('7. Missing evidence and optional fields are handled safely and produce stable fingerprints', () => {
      const noEvidenceItem1 = {
        rule: 'audit.header.missing-csp',
        path: 'src/server.js',
        startLine: 5,
        message: 'Content-Security-Policy header is missing'
      };

      const noEvidenceItem2 = {
        rule: 'audit.header.missing-csp',
        path: 'src/server.js',
        startLine: 25, // different line, no evidence
        message: 'Content-Security-Policy header is missing'
      };

      const res1 = findingNormalizer.normalizeFinding(noEvidenceItem1);
      const res2 = findingNormalizer.normalizeFinding(noEvidenceItem2);

      assert.strictEqual(res1.success, true);
      assert.strictEqual(res2.success, true);
      assert.ok(res1.data.fingerprint && res1.data.fingerprint.length === 64);
      assert.strictEqual(
        res1.data.fingerprint,
        res2.data.fingerprint,
        'Findings without evidence should still produce stable, matching fingerprints based on rule/path/message'
      );
    });

    it('8. Whitespace formatting variations in evidence do not change fingerprint', () => {
      const evidenceTabs = {
        rule: 'security.check',
        path: 'src/app.js',
        startLine: 1,
        evidence: '\t\tconst  query  =\n\t\t\t"SELECT *";\n'
      };

      const evidenceSpaces = {
        rule: 'security.check',
        path: 'src/app.js',
        startLine: 1,
        evidence: '  const query = "SELECT *";  '
      };

      const resTabs = findingNormalizer.normalizeFinding(evidenceTabs);
      const resSpaces = findingNormalizer.normalizeFinding(evidenceSpaces);

      assert.strictEqual(resTabs.success, true);
      assert.strictEqual(resSpaces.success, true);
      assert.strictEqual(
        resTabs.data.fingerprint,
        resSpaces.data.fingerprint,
        'Whitespace formatting variations in code snippet must not alter the fingerprint'
      );
    });

    it('9. Deduplication can be disabled via options.deduplicate = false', () => {
      const identicalItem = {
        rule: 'duplicate.rule',
        path: 'src/app.js',
        startLine: 10,
        evidence: 'const a = 1;'
      };

      const batch = [identicalItem, identicalItem];
      const result = findingNormalizer.normalize(batch, { deduplicate: false });

      assert.strictEqual(result.findings.length, 2, 'Deduplication disabled must return both items');
      assert.strictEqual(result.findings[0].fingerprint, result.findings[1].fingerprint);
    });
  });
});
