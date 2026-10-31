const { describe, it } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');

const syntaxScanner = require('../src/services/syntaxAwareScanner');
const semgrepParser = require('../src/services/semgrep.parser');
const { scanOrchestrator, SCAN_STATES } = require('../src/orchestrator/scanOrchestrator');
const scannerService = require('../src/services/scanner.service');

describe('VULNEX Detection Accuracy & False-Positive Hardening Suite', () => {

  // ==========================================================================
  // 1. SQL Injection: Credible Database Sinks vs False Positives
  // ==========================================================================
  describe('1. SQL Injection Precision', () => {
    it('detects positive SQL injection via string concatenation with dynamic parameter', () => {
      const code = 'const sql = "SELECT * FROM users WHERE id = " + req.query.id;\ndb.query(sql);';
      const findings = syntaxScanner.scanFile(code, 'src/routes/users.js', 'scan_test');
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].category, 'SQL_INJECTION');
      assert.strictEqual(findings[0].ruleId, 'vulnex.javascript.sqli');
      assert.strictEqual(findings[0].severity, 'CRITICAL');
      assert.strictEqual(findings[0].confidence, 'HIGH');
    });

    it('detects positive SQL injection via template literal interpolation with dynamic parameter reaching DB sink', () => {
      const code = 'const query = `SELECT id, name FROM users WHERE id = ${userId}`;\ndb.query(query);';
      const findings = syntaxScanner.scanFile(code, 'src/models/user.js', 'scan_test');
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].category, 'SQL_INJECTION');
      assert.strictEqual(findings[0].startLine, 1);
    });

    it('rejects false positive: SQL query string in file without database execution sink', () => {
      const code = 'const queryDoc = `SELECT id, name FROM users WHERE id = ${userId}`;\nlogger.info("Generated query string: " + queryDoc);';
      const findings = syntaxScanner.scanFile(code, 'src/utils/logger.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'SQL query strings without a database execution sink must not be flagged');
    });

    it('rejects false positive: parameterized query with $1 bind parameters', () => {
      const code = 'const sql = "SELECT * FROM users WHERE id = $1";\ndb.query(sql, [req.query.id]);';
      const findings = syntaxScanner.scanFile(code, 'src/routes/users.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Parameterized queries with $1 must never be flagged as SQLi');
    });

    it('rejects false positive: parameterized prepared statement with ? placeholders', () => {
      const code = "pool.query('SELECT id, name FROM users WHERE role = ? AND active = ?', [userRole, true]);";
      const findings = syntaxScanner.scanFile(code, 'src/models/user.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Prepared statements with ? must never be flagged as SQLi');
    });

    it('rejects false positive: ordinary variable named "query"', () => {
      const code = 'const query = req.query.search;\nconst results = searchService.find(query);';
      const findings = syntaxScanner.scanFile(code, 'src/controllers/search.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Variables named query must not be classified as SQL sinks');
    });

    it('rejects false positive: GraphQL client query call', () => {
      const code = 'const response = await apolloClient.query({ query: GET_USER_PROFILE });';
      const findings = syntaxScanner.scanFile(code, 'src/services/api.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'GraphQL apolloClient.query must not be classified as SQLi');
    });

    it('rejects false positive: DOM query selector with template literal', () => {
      const code = 'const element = document.query(`#item-${itemId}`);';
      const findings = syntaxScanner.scanFile(code, 'src/views/dom.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'DOM selectors must not be classified as SQLi');
    });

    it('rejects false positive: safe string concatenation with SQL constant allowlist', () => {
      const code = 'const sql = "SELECT * FROM users ORDER BY " + DEFAULT_SORT;\ndb.query(sql);';
      const findings = syntaxScanner.scanFile(code, 'src/services/db.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Strict constant concatenation must not be flagged as SQLi');
    });
  });

  // ==========================================================================
  // 2. Command Injection (CWE-78) vs Code Injection (CWE-95)
  // ==========================================================================
  describe('2. Command Injection vs Code Injection Separation', () => {
    it('detects positive Command Injection (CWE-78) via child_process.exec template string', () => {
      const code = 'cp.exec(`ping -c 1 ${req.query.host}`);';
      const findings = syntaxScanner.scanFile(code, 'src/utils/ping.js', 'scan_test');
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].category, 'COMMAND_INJECTION');
      assert.strictEqual(findings[0].ruleId, 'vulnex.javascript.cmd-injection');
      assert.strictEqual(findings[0].severity, 'CRITICAL');
    });

    it('detects positive Command Injection (CWE-78) via destructured exec call', () => {
      const code = 'const { exec } = require("child_process");\nexec(`ls -la ${folderPath}`);';
      const findings = syntaxScanner.scanFile(code, 'src/utils/dir.js', 'scan_test');
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].category, 'COMMAND_INJECTION');
    });

    it('rejects false positive: safe child_process.execFile with argument array', () => {
      const code = "child_process.execFile('/bin/ping', ['-c', '1', req.query.host], (err, stdout) => {});";
      const findings = syntaxScanner.scanFile(code, 'src/utils/ping.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Safe execFile with argument array must not be flagged as Command Injection');
    });

    it('rejects false positive: safe child_process.spawn with argument array', () => {
      const code = "child_process.spawn('git', ['status'], { cwd: repoDir });";
      const findings = syntaxScanner.scanFile(code, 'src/utils/git.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Safe spawn with argument array must not be flagged as Command Injection');
    });

    it('rejects false positive: harmless import of child_process module', () => {
      const code = "const cp = require('child_process');\nmodule.exports = cp;";
      const findings = syntaxScanner.scanFile(code, 'src/utils/runner.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Importing child_process must not produce a vulnerability finding');
    });

    it('rejects false positive: safe RegExp.exec() method call', () => {
      const code = 'const match = /pattern/.exec(inputString);';
      const findings = syntaxScanner.scanFile(code, 'src/utils/parser.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'RegExp.exec must never be flagged as Command Injection');
    });

    it('detects positive Code Injection (CWE-95) with dynamic input and separates from Command Injection', () => {
      const code = 'const result = eval(req.body.userInput);';
      const findings = syntaxScanner.scanFile(code, 'src/utils/calc.js', 'scan_test');
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].category, 'CODE_INJECTION');
      assert.strictEqual(findings[0].ruleId, 'vulnex.javascript.code-injection');
      assert.notStrictEqual(findings[0].category, 'COMMAND_INJECTION', 'Code injection must not be classified as command injection');
    });

    it('rejects false positive: static math string eval("2 + 2")', () => {
      const code = 'const answer = eval("2 + 2");';
      const findings = syntaxScanner.scanFile(code, 'src/utils/math.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Static string literal eval must not be flagged as dynamic code injection');
    });

    it('rejects false positive: prose / docstrings mentioning exec() or eval()', () => {
      const code = 'const helpText = "Never pass untrusted user strings into eval() or exec() functions.";';
      const findings = syntaxScanner.scanFile(code, 'src/help.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Prose string literals mentioning eval()/exec() must not be flagged');
    });
  });

  // ==========================================================================
  // 3. Cross-Site Scripting (XSS) & React JSX Template Interpolation
  // ==========================================================================
  describe('3. Cross-Site Scripting (XSS) Precision', () => {
    it('detects positive DOM XSS via innerHTML assignment with dynamic input', () => {
      const code = 'element.innerHTML = "<p>" + req.body.profile + "</p>";';
      const findings = syntaxScanner.scanFile(code, 'src/views/profile.js', 'scan_test');
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].category, 'XSS');
      assert.strictEqual(findings[0].ruleId, 'vulnex.javascript.xss');
    });

    it('detects positive React dangerouslySetInnerHTML with unescaped HTML', () => {
      const code = 'return <div dangerouslySetInnerHTML={{ __html: userHtml }} />;';
      const findings = syntaxScanner.scanFile(code, 'src/components/View.jsx', 'scan_test');
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].category, 'XSS');
    });

    it('detects positive server-side HTML response template with dynamic input reaching res.send', () => {
      const code = 'const html = `<p>Welcome ${userName}</p>`;\nres.setHeader("Content-Type", "text/html");\nres.send(html);';
      const findings = syntaxScanner.scanFile(code, 'src/routes/web.js', 'scan_test');
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].category, 'XSS');
    });

    it('rejects false positive: HTML template interpolation alone without an HTML rendering sink', () => {
      const code = 'const template = `<p>Welcome ${userName}</p>`;\nconst len = template.length;\nreturn len;';
      const findings = syntaxScanner.scanFile(code, 'src/utils/parser.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'HTML template interpolation without an HTML rendering sink must not be flagged');
    });

    it('rejects false positive: React JSX component with template literal className', () => {
      const code = "function Badge({ active }) {\n  return <span className={`badge-${active ? 'on' : 'off'}`}>Status</span>;\n}";
      const findings = syntaxScanner.scanFile(code, 'src/components/Badge.jsx', 'scan_test');
      assert.strictEqual(findings.length, 0, 'React className template literals must not be classified as XSS');
    });

    it('rejects false positive: React JSX child text interpolation <p>Count: ${count}</p>', () => {
      const code = 'return <p>Count: ${count}</p>;';
      const findings = syntaxScanner.scanFile(code, 'src/components/Counter.jsx', 'scan_test');
      assert.strictEqual(findings.length, 0, 'React JSX text children are automatically encoded and must not be flagged as XSS');
    });
  });

  // ==========================================================================
  // 4. Comment & Docstring False-Positive Prevention
  // ==========================================================================
  describe('4. Lexical Comment & Docstring Filtering', () => {
    it('rejects false positives inside single-line comments', () => {
      const code = '// Avoid: cp.exec(`rm ${file}`)\nconsole.log("clean line");';
      const findings = syntaxScanner.scanFile(code, 'src/index.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Code inside single-line comments must never be flagged');
    });

    it('rejects false positives inside multi-line block comments', () => {
      const code = '/*\n * Security Warning:\n * SELECT * FROM users WHERE id = ${id}\n * Do not use direct interpolation!\n */\nconst app = express();';
      const findings = syntaxScanner.scanFile(code, 'src/app.js', 'scan_test');
      assert.strictEqual(findings.length, 0, 'Code inside multi-line block comments must never be flagged');
    });
  });

  // ==========================================================================
  // 5. Test File Scoping & isTestFile Classification (Requirement 6)
  // ==========================================================================
  describe('5. Test File & Fixture Scope Handling', () => {
    const testFileCode = "// tests/detector.test.js\nit('detects command injection', () => {\n  const payload = 'child_process.exec(`rm ${file}`);';\n  assert.ok(payload);\n});";

    it('correctly identifies test files using isTestFile helper', () => {
      assert.strictEqual(syntaxScanner.isTestFile('tests/app.test.js'), true);
      assert.strictEqual(syntaxScanner.isTestFile('src/components/__tests__/Button.spec.jsx'), true);
      assert.strictEqual(syntaxScanner.isTestFile('fixtures/vulnerable-app/server.js'), true);
      assert.strictEqual(syntaxScanner.isTestFile('src/controllers/user.controller.js'), false);
      assert.strictEqual(syntaxScanner.isTestFile('lib/database.js'), false);
    });

    it('excludes test mock findings when scan scope is SOURCE_ONLY (default)', () => {
      const findings = syntaxScanner.scanFile(testFileCode, 'tests/detector.test.js', 'scan_test', {
        scope: 'SOURCE_ONLY'
      });
      assert.strictEqual(findings.length, 0, 'SOURCE_ONLY scope must exclude test file mock exploits from production findings');
    });

    it('includes test mock findings with isTestFile: true when scan scope is ALL', () => {
      const findings = syntaxScanner.scanFile(testFileCode, 'tests/detector.test.js', 'scan_test', {
        scope: 'ALL'
      });
      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].isTestFile, true);
      assert.strictEqual(findings[0].scope, 'TEST');
      assert.strictEqual(findings[0].severity, 'LOW', 'Test findings must be capped at LOW severity');
      assert.strictEqual(findings[0].confidence, 'LOW');
    });
  });

  // ==========================================================================
  // 6. Semgrep Category Mapping Accuracy (Requirement 1)
  // ==========================================================================
  describe('6. Semgrep Parser Category Mapping', () => {
    it('does not classify regex execution rules as command injection', () => {
      const category = semgrepParser.deriveCategory('javascript.lang.best-practice.regex-exec', {
        message: 'Prefer String#match over RegExp#exec for simple matches'
      });
      assert.strictEqual(category, 'OTHER');
      assert.notStrictEqual(category, 'COMMAND_INJECTION');
    });

    it('maps explicit CWE-89 to SQL_INJECTION', () => {
      const category = semgrepParser.deriveCategory('custom.rule', { cwe: 'CWE-89' });
      assert.strictEqual(category, 'SQL_INJECTION');
    });

    it('maps explicit CWE-78 to COMMAND_INJECTION', () => {
      const category = semgrepParser.deriveCategory('custom.rule', { cwe: 'CWE-78' });
      assert.strictEqual(category, 'COMMAND_INJECTION');
    });

    it('maps explicit CWE-95 to CODE_INJECTION', () => {
      const category = semgrepParser.deriveCategory('custom.rule', { cwe: 'CWE-95' });
      assert.strictEqual(category, 'CODE_INJECTION');
    });

    it('does not classify rules with author in metadata as BROKEN_AUTH', () => {
      const category = semgrepParser.deriveCategory('javascript.express.security.audit.cors-wildcard', {
        author: 'Semgrep Security Team',
        message: 'CORS header contains wildcard',
        cwe: 'CWE-942'
      });
      assert.strictEqual(category, 'SECURITY_MISCONFIG');
      assert.notStrictEqual(category, 'BROKEN_AUTH');
    });
  });

  // ==========================================================================
  // 7. Stable Cross-Engine Deduplication (Requirement 7)
  // ==========================================================================
  describe('7. Cross-Engine Finding Deduplication', () => {
    it('generates identical cross-engine fingerprint for same flaw from different scanners', () => {
      const fp1 = syntaxScanner.generateCrossEngineFingerprint({
        category: 'SQL_INJECTION',
        filePath: 'src/routes/users.js',
        startLine: 42,
        evidence: 'const q = `SELECT * FROM users WHERE id = ${id}`;'
      });

      const fp2 = syntaxScanner.generateCrossEngineFingerprint({
        category: 'SQL_INJECTION',
        filePath: 'src/routes/users.js',
        startLine: 42,
        evidence: 'const q = `SELECT * FROM users WHERE id = ${id}`;'
      });

      assert.strictEqual(fp1, fp2, 'Cross-engine fingerprints must be identical for the same category, path, line, and evidence');
    });

    it('preserves distinct fingerprints for different categories on the same line', () => {
      const fpSql = syntaxScanner.generateCrossEngineFingerprint({
        category: 'SQL_INJECTION',
        filePath: 'src/routes/users.js',
        startLine: 42,
        evidence: 'statement();'
      });

      const fpCmd = syntaxScanner.generateCrossEngineFingerprint({
        category: 'COMMAND_INJECTION',
        filePath: 'src/routes/users.js',
        startLine: 42,
        evidence: 'statement();'
      });

      assert.notStrictEqual(fpSql, fpCmd, 'Different vulnerability categories must never merge into the same fingerprint');
    });
  });
});
