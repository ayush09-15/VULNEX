const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

/**
 * ============================================================================
 * VULNEX Syntax-Aware Detection Engine
 *
 * Implements lexical & syntactic awareness for SAST pattern detection:
 * 1. Distinguishes comments, docstrings, string literals, and executable code.
 * 2. Scopes SQL injection detection to credible database execution contexts.
 * 3. Differentiates safe argument array process execution from shell injection.
 * 4. Strictly separates Command Injection (CWE-78) from Code Injection (CWE-95).
 * 5. Eliminates JSX template literal false positives for Cross-Site Scripting.
 * 6. Supports scan scoping (SOURCE_ONLY vs ALL) and isTestFile classification.
 * 7. Generates stable cross-engine fingerprints for clean deduplication.
 * ============================================================================
 */

/**
 * Check if a file path belongs to a test suite, test fixture, or mock
 * @param {string} filePath
 * @returns {boolean}
 */
function isTestFile(filePath) {
  if (!filePath || typeof filePath !== 'string') return false;
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  return (
    /(?:^|\/)(?:tests?|__tests__|specs?|fixtures?|e2e|cypress)\//i.test(normalized) ||
    /\.(?:test|spec|cy)\.[a-z0-9]+$/i.test(normalized)
  );
}

/**
 * Generate a deterministic cross-engine fingerprint for finding deduplication.
 * Normalizes category, file path, line, and evidence to prevent duplicate reporting
 * across Semgrep and pattern-sast engines.
 *
 * @param {Object} input
 * @param {string} input.category
 * @param {string} input.filePath
 * @param {number} input.startLine
 * @param {string} input.evidence
 * @returns {string} 64-character SHA-256 hex string
 */
function generateCrossEngineFingerprint({ category, filePath, startLine, evidence }) {
  const normCat = String(category || 'OTHER').toUpperCase().trim();
  const normPath = String(filePath || '').replace(/\\/g, '/').replace(/^\/+/, '').trim();
  const line = parseInt(startLine, 10) || 1;
  const normEvidence = String(evidence || '').replace(/\s+/g, ' ').trim().slice(0, 100);

  const payload = `${normCat}::${normPath}::${line}::${normEvidence}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Analyze source code text to extract line-level lexical metadata.
 * Strips comments from evaluation lines while preserving original line text for evidence.
 *
 * @param {string} content
 * @returns {Array<{ line: number, original: string, codeWithoutComments: string, isFullComment: boolean }>}
 */
function analyzeLines(content) {
  if (typeof content !== 'string') return [];

  const rawLines = content.split('\n');
  const results = [];
  let inBlockComment = false;

  for (let i = 0; i < rawLines.length; i++) {
    const original = rawLines[i];
    let stripped = original;
    let isFullComment = false;

    // Check if currently inside block comment
    if (inBlockComment) {
      const closeIdx = stripped.indexOf('*/');
      if (closeIdx !== -1) {
        // Block comment ended on this line
        inBlockComment = false;
        stripped = stripped.slice(closeIdx + 2);
      } else {
        // Entire line is inside block comment
        results.push({
          line: i + 1,
          original,
          codeWithoutComments: '',
          isFullComment: true
        });
        continue;
      }
    }

    // Process block comments starting on this line
    while (stripped.includes('/*')) {
      const openIdx = stripped.indexOf('/*');
      const closeIdx = stripped.indexOf('*/', openIdx + 2);
      if (closeIdx !== -1) {
        stripped = stripped.slice(0, openIdx) + ' ' + stripped.slice(closeIdx + 2);
      } else {
        // Multi-line block comment starts and does not close on this line
        inBlockComment = true;
        stripped = stripped.slice(0, openIdx);
        break;
      }
    }

    // Process single line comment
    const singleCommentIdx = stripped.indexOf('//');
    if (singleCommentIdx !== -1) {
      // Ensure the // is not inside a string literal or template
      const beforeComment = stripped.slice(0, singleCommentIdx);
      const singleQuotes = (beforeComment.match(/'/g) || []).length;
      const doubleQuotes = (beforeComment.match(/"/g) || []).length;
      const backticks = (beforeComment.match(/`/g) || []).length;

      if (singleQuotes % 2 === 0 && doubleQuotes % 2 === 0 && backticks % 2 === 0) {
        stripped = beforeComment;
      }
    }

    if (!stripped.trim()) {
      isFullComment = original.trim().startsWith('//') || original.trim().startsWith('/*') || inBlockComment;
    }

    results.push({
      line: i + 1,
      original,
      codeWithoutComments: stripped.trim(),
      isFullComment: isFullComment || (!stripped.trim() && original.trim().length > 0)
    });
  }

  return results;
}

// Canonical rules supported by the syntax-aware pattern engine
const DETERMINISTIC_RULES = [
  {
    id: 'vulnex.javascript.sqli',
    title: 'SQL Injection via unsanitized query parameters',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    message: 'Direct concatenation or interpolation of untrusted input into SQL queries detected.'
  },
  {
    id: 'vulnex.javascript.cmd-injection',
    title: 'Command Injection via child_process execution',
    category: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    message: 'Dynamic untrusted argument passed to system shell or OS command execution.'
  },
  {
    id: 'vulnex.javascript.code-injection',
    title: 'Code Injection via dynamic code evaluation',
    category: 'CODE_INJECTION',
    cwe: 'CWE-95',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    message: 'Dynamic untrusted input evaluated as JavaScript code via eval() or new Function().'
  },
  {
    id: 'vulnex.javascript.hardcoded-secret',
    title: 'Hard-coded Secret / API Token',
    category: 'HARDCODED_SECRET',
    cwe: 'CWE-798',
    severity: 'HIGH',
    confidence: 'HIGH',
    message: 'Sensitive credential or secret key embedded directly into source code.'
  },
  {
    id: 'vulnex.javascript.path-traversal',
    title: 'Path Traversal via unsanitized file system access',
    category: 'PATH_TRAVERSAL',
    cwe: 'CWE-22',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    message: 'File read or write operation using unsanitized user path allows directory traversal.'
  },
  {
    id: 'vulnex.javascript.xss',
    title: 'Cross-Site Scripting (XSS) via unescaped HTML injection',
    category: 'XSS',
    cwe: 'CWE-79',
    severity: 'HIGH',
    confidence: 'HIGH',
    message: 'Direct insertion of untrusted data into DOM or unescaped HTML response without output encoding.'
  }
];

/**
 * Evaluate SQL Injection with database execution context
 */
function checkSqlInjection(codeLine, fullContent) {
  // Exclude non-database contexts: DOM query selectors, GraphQL clients, client routers, assertions
  if (
    /\b(?:document|element|\$|apolloClient)\.query\b/i.test(codeLine) ||
    /\b(?:router|url|req)\.query\s*\(/i.test(codeLine) ||
    /useQuery|\.query\s*\(\s*\{\s*query\s*:/i.test(codeLine) ||
    /\b(?:expect|assert)\./i.test(codeLine)
  ) {
    return false;
  }

  // 1. Parameterized query check (SAFE):
  // e.g. query('SELECT ... $1', [params]) or query({ text: '...', values: [ ... ] })
  if (
    /(?:query|execute)\s*\(\s*['"`][^'"`]*\$[0-9]+[^'"`]*['"`]\s*,\s*\[/i.test(codeLine) ||
    /(?:query|execute)\s*\(\s*['"`][^'"`]*\?[^'"`]*['"`]\s*,\s*\[/i.test(codeLine) ||
    /(?:query|execute)\s*\(\s*\{\s*text\s*:/i.test(codeLine)
  ) {
    return false; // Safely parameterized
  }

  // Require evidence of an actual database execution sink (on this line or in the file)
  const hasDbSink = (
    /(?:db|client|pool|conn|connection|knex|sequelize|prisma|sqlite|mysql|pg)\.(?:query|execute|raw|\$queryRaw)\s*\(/i.test(codeLine) ||
    (typeof fullContent === 'string' && (
      /(?:db|client|pool|conn|connection|knex|sequelize|prisma|sqlite|mysql|pg)\.(?:query|execute|raw|\$queryRaw)\s*\(/i.test(fullContent) ||
      /\b(?:query|execute|raw)\s*\(\s*(?:sql|query|[a-zA-Z0-9_]*query)/i.test(fullContent)
    ))
  );

  // 2. Unsafe SQL interpolation inside template string:
  // e.g. `SELECT * FROM users WHERE id = ${req.query.id}` or `SELECT * FROM users WHERE id = ${id}`
  const templateSqlMatch = /SELECT\s+.*?\s+FROM\s+.*?\$\{([^}]+)\}/i.test(codeLine) ||
                          /(?:INSERT\s+INTO|UPDATE\s+.*?\s+SET|DELETE\s+FROM)\s+.*?\$\{([^}]+)\}/i.test(codeLine);

  if (templateSqlMatch && hasDbSink) {
    // Check if the interpolated item is an obvious constant (e.g. ${TABLE_NAME} or ${1})
    const interp = codeLine.match(/\$\{([^}]+)\}/);
    if (interp && interp[1]) {
      const varName = interp[1].trim();
      if (/^[A-Z0-9_]{3,}$/.test(varName) || !isNaN(Number(varName))) {
        // Uppercase constant like ${TABLE_NAME} or static number
        return false;
      }
    }
    return true;
  }

  // 3. Unsafe SQL concatenation with dynamic variable:
  // e.g. "SELECT * FROM users WHERE id = " + req.query.id or "SELECT ... " + id
  const concatSqlMatch = /(?:SELECT\s+.*?\s+FROM|INSERT\s+INTO|UPDATE\s+.*?\s+SET|DELETE\s+FROM)\s+.*?\s*\+\s*([\w\.]+)/i.exec(codeLine);
  if (concatSqlMatch && hasDbSink) {
    const concatenated = concatSqlMatch[1].trim();
    // Exclude string literals ('ORDER BY', etc.) or strict uppercase constants (DEFAULT_SORT)
    if (/^[A-Z0-9_]{3,}$/.test(concatenated)) {
      return false; // Safe constant like DEFAULT_ORDER
    }
    return true;
  }

  // 4. Database driver method call with template string containing dynamic variable
  // e.g. db.query(`SELECT ... ${id}`) or pool.execute(`SELECT ... ${req.params.id}`)
  if (
    /(?:db|client|pool|conn|connection|knex|sequelize)\.(?:query|execute|raw)\s*\(\s*[`'"].*?\$\{([^}]+)\}/i.test(codeLine)
  ) {
    const interp = codeLine.match(/\$\{([^}]+)\}/);
    if (interp && interp[1] && (/^[A-Z0-9_]{3,}$/.test(interp[1].trim()) || !isNaN(Number(interp[1].trim())))) {
      return false;
    }
    return true;
  }

  return false;
}

/**
 * Evaluate Command Injection (CWE-78)
 */
function checkCommandInjection(codeLine, fullContent) {
  // Exclude docstrings and prose string literals
  if (/^['"`].*?['"`];?$/.test(codeLine.trim()) && (codeLine.includes('eval()') || codeLine.includes('exec()'))) {
    return false;
  }
  if (/const\s+\w+\s*=\s*['"`].*?(?:eval\(\)|exec\(\)).*?['"`];?/.test(codeLine)) {
    return false; // Docstring or text variable mentioning eval()/exec()
  }

  // Exclude safe argument-array executions: execFile and spawn without shell: true
  if (
    /(?:child_process|cp)\.(?:execFile|spawn)\s*\(/i.test(codeLine) &&
    !codeLine.includes('shell: true')
  ) {
    return false; // Safe argument array execution
  }

  // Check child_process.exec / execSync with dynamic interpolation or concatenation
  // e.g. cp.exec(`ping -c 1 ${req.query.host}`) or child_process.execSync("rm -rf " + dir)
  if (
    /(?:child_process|cp)\.(?:exec|execSync)\s*\(\s*[`'"].*?\$\{([^}]+)\}/.test(codeLine) ||
    /(?:child_process|cp)\.(?:exec|execSync)\s*\(\s*['"][^'"]*['"]\s*\+\s*[\w\.]+/i.test(codeLine)
  ) {
    return true;
  }

  // Check destructured exec/execSync call if file requires child_process
  if (
    fullContent.includes('require(\'child_process\')') ||
    fullContent.includes('require("child_process")') ||
    fullContent.includes('from \'child_process\'') ||
    fullContent.includes('from "child_process"')
  ) {
    if (
      /\b(?:exec|execSync)\s*\(\s*[`'"].*?\$\{([^}]+)\}/.test(codeLine) ||
      /\b(?:exec|execSync)\s*\(\s*['"][^'"]*['"]\s*\+\s*[\w\.]+/i.test(codeLine)
    ) {
      // Exclude regex.exec
      if (!/\.exec\s*\(/.test(codeLine) && !/RegExp|pattern|regex/i.test(codeLine)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Evaluate Code Injection (CWE-95)
 */
function checkCodeInjection(codeLine) {
  // Exclude docstrings and text descriptions
  if (/const\s+\w+\s*=\s*['"`].*?(?:eval\(\)|new Function).*?['"`];?/.test(codeLine)) {
    return false;
  }
  if (/summary|description|message|help|doc/i.test(codeLine) && /['"`].*?eval\(/.test(codeLine)) {
    return false;
  }

  // Check eval(dynamicVariable)
  const evalMatch = /\beval\s*\(\s*([^\)]+)\)/.exec(codeLine);
  if (evalMatch) {
    const arg = evalMatch[1].trim();
    // Exclude static math or string literals: eval("2 + 2"), eval('({})')
    if (/^['"`][^'"`]*['"`]$/.test(arg)) {
      return false; // Static string eval
    }
    return true; // Dynamic eval
  }

  // Check new Function(..., dynamic)
  if (/\bnew\s+Function\s*\(\s*[^)]*[\w\.]+\s*\)/.test(codeLine)) {
    // Only flag if argument is dynamic variable
    if (!/new\s+Function\s*\(\s*['"`][^'"`]*['"`]\s*\)/.test(codeLine)) {
      return true;
    }
  }

  return false;
}

/**
 * Evaluate Cross-Site Scripting (XSS) (CWE-79)
 */
function checkXss(codeLine, filePath = '', fullContent = '') {
  // 1. Direct DOM sinks: innerHTML or outerHTML assigned dynamic input
  if (/\b(?:innerHTML|outerHTML)\s*=/i.test(codeLine)) {
    const trimmed = codeLine.trim();
    const isStaticString = /\b(?:innerHTML|outerHTML)\s*=\s*(?:'[^']*'|"[^"]*")\s*;?\s*$/.test(trimmed);
    const isStaticBacktick = /\b(?:innerHTML|outerHTML)\s*=\s*`[^`$]*`\s*;?\s*$/.test(trimmed);
    if (!isStaticString && !isStaticBacktick) {
      return true;
    }
  }

  // 2. React dangerouslySetInnerHTML
  if (/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/i.test(codeLine)) {
    return true;
  }

  // 3. Server-side reflected HTML response with unescaped template string
  // e.g. res.send(`<h1>Search Results for ${req.query.q}</h1>`)
  if (
    /res\.(?:send|write)\s*\(\s*[`'"].*?<[a-z0-9_-]+>.*?\$\{([^}]+)\}/i.test(codeLine)
  ) {
    return true;
  }

  // 4. HTML template string with dynamic variable interpolation in non-JSX files
  // MUST reach an actual unsafe HTML rendering sink (res.send, res.write, innerHTML, etc.)
  // Template interpolation alone is insufficient evidence!
  const isJsxFile = filePath.endsWith('.jsx') || filePath.endsWith('.tsx');
  const isJsxReturn = /return\s+<[a-z0-9_-]+/i.test(codeLine.trim());
  if (!isJsxFile && !isJsxReturn) {
    if (/<[a-z0-9_-]+[^>]*>.*?\$\{([a-zA-Z0-9_\.]+)\}.*?<\/[a-z0-9_-]+>/i.test(codeLine)) {
      // Verify evidence of reaching an actual unsafe HTML rendering sink
      const hasHtmlRenderingSink = typeof fullContent === 'string' && (
        /res\.(?:send|write|end)\s*\(/i.test(fullContent) ||
        /response\.(?:send|write|end)\s*\(/i.test(fullContent) ||
        /\b(?:innerHTML|outerHTML)\s*=/i.test(fullContent) ||
        /\bdocument\.write\s*\(/i.test(fullContent) ||
        /setHeader\s*\(\s*['"]content-type['"]\s*,\s*['"]text\/html['"]/i.test(fullContent) ||
        /dangerouslySetInnerHTML/i.test(fullContent)
      );
      if (hasHtmlRenderingSink) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Evaluate Hardcoded Secrets (CWE-798)
 */
function checkHardcodedSecret(codeLine) {
  // Must match credential variable assignment with at least 16 alphanumeric characters
  const secretPattern = /(?:api_?key|secret|password|auth_?token|jwt_?secret)\s*[:=]\s*['"`]([A-Za-z0-9_\-\.]{16,})['"`]/i;
  const match = secretPattern.exec(codeLine);
  if (!match) return false;

  const token = match[1];
  // Exclude obvious test placeholders
  if (
    /placeholder|dummy|example|mock|test_token|replace_me|secret_here/i.test(token)
  ) {
    return false;
  }

  return true;
}

/**
 * Evaluate Path Traversal (CWE-22)
 */
function checkPathTraversal(codeLine) {
  return /fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync)\s*\(\s*(?:req\.(?:query|params|body)|path\.join\([^)]*req\.)/i.test(codeLine);
}

/**
 * Scan a single file's content using lexical and syntax awareness.
 *
 * @param {string} content - Raw source code of file
 * @param {string} filePath - Relative file path
 * @param {string} scanId - Associated scan ID
 * @param {Object} [options={}]
 * @param {'SOURCE_ONLY'|'ALL'} [options.scope='SOURCE_ONLY'] - Scan scope
 * @returns {Array<Object>} Canonical Finding objects
 */
function scanFile(content, filePath, scanId, options = {}) {
  const findings = [];
  const scope = options.scope || 'SOURCE_ONLY';
  const isTest = isTestFile(filePath);

  // If scan scope is SOURCE_ONLY and file is a test/fixture, do not produce production findings
  if (scope === 'SOURCE_ONLY' && isTest) {
    return [];
  }

  const lines = analyzeLines(content);

  for (const lineObj of lines) {
    // Ignore lines that are comments or empty
    if (lineObj.isFullComment || !lineObj.codeWithoutComments) {
      continue;
    }

    const code = lineObj.codeWithoutComments;
    const lineNumber = lineObj.line;
    const evidence = lineObj.original.trim();

    // 1. SQL Injection
    if (checkSqlInjection(code, content)) {
      const rule = DETERMINISTIC_RULES.find(r => r.category === 'SQL_INJECTION');
      const crossFp = generateCrossEngineFingerprint({
        category: 'SQL_INJECTION',
        filePath,
        startLine: lineNumber,
        evidence
      });

      findings.push({
        id: `find_${crypto.randomBytes(6).toString('hex')}`,
        scanId,
        scanner: 'pattern-sast',
        ruleId: rule.id,
        title: rule.title,
        category: rule.category,
        severity: isTest ? 'LOW' : rule.severity,
        confidence: isTest ? 'LOW' : rule.confidence,
        filePath: filePath.replace(/\\/g, '/'),
        startLine: lineNumber,
        endLine: lineNumber,
        message: rule.message,
        evidence,
        fingerprint: crossFp,
        isTestFile: isTest,
        scope: isTest ? 'TEST' : 'SOURCE',
        status: 'DETECTED',
        createdAt: new Date().toISOString()
      });
      continue;
    }

    // 2. Command Injection (CWE-78)
    if (checkCommandInjection(code, content)) {
      const rule = DETERMINISTIC_RULES.find(r => r.category === 'COMMAND_INJECTION');
      const crossFp = generateCrossEngineFingerprint({
        category: 'COMMAND_INJECTION',
        filePath,
        startLine: lineNumber,
        evidence
      });

      findings.push({
        id: `find_${crypto.randomBytes(6).toString('hex')}`,
        scanId,
        scanner: 'pattern-sast',
        ruleId: rule.id,
        title: rule.title,
        category: rule.category,
        severity: isTest ? 'LOW' : rule.severity,
        confidence: isTest ? 'LOW' : rule.confidence,
        filePath: filePath.replace(/\\/g, '/'),
        startLine: lineNumber,
        endLine: lineNumber,
        message: rule.message,
        evidence,
        fingerprint: crossFp,
        isTestFile: isTest,
        scope: isTest ? 'TEST' : 'SOURCE',
        status: 'DETECTED',
        createdAt: new Date().toISOString()
      });
      continue;
    }

    // 3. Code Injection (CWE-95)
    if (checkCodeInjection(code)) {
      const rule = DETERMINISTIC_RULES.find(r => r.category === 'CODE_INJECTION');
      const crossFp = generateCrossEngineFingerprint({
        category: 'CODE_INJECTION',
        filePath,
        startLine: lineNumber,
        evidence
      });

      findings.push({
        id: `find_${crypto.randomBytes(6).toString('hex')}`,
        scanId,
        scanner: 'pattern-sast',
        ruleId: rule.id,
        title: rule.title,
        category: rule.category,
        severity: isTest ? 'LOW' : rule.severity,
        confidence: isTest ? 'LOW' : rule.confidence,
        filePath: filePath.replace(/\\/g, '/'),
        startLine: lineNumber,
        endLine: lineNumber,
        message: rule.message,
        evidence,
        fingerprint: crossFp,
        isTestFile: isTest,
        scope: isTest ? 'TEST' : 'SOURCE',
        status: 'DETECTED',
        createdAt: new Date().toISOString()
      });
      continue;
    }

    // 4. Cross-Site Scripting (XSS)
    if (checkXss(code, filePath, content)) {
      const rule = DETERMINISTIC_RULES.find(r => r.category === 'XSS');
      const crossFp = generateCrossEngineFingerprint({
        category: 'XSS',
        filePath,
        startLine: lineNumber,
        evidence
      });

      findings.push({
        id: `find_${crypto.randomBytes(6).toString('hex')}`,
        scanId,
        scanner: 'pattern-sast',
        ruleId: rule.id,
        title: rule.title,
        category: rule.category,
        severity: isTest ? 'LOW' : rule.severity,
        confidence: isTest ? 'LOW' : rule.confidence,
        filePath: filePath.replace(/\\/g, '/'),
        startLine: lineNumber,
        endLine: lineNumber,
        message: rule.message,
        evidence,
        fingerprint: crossFp,
        isTestFile: isTest,
        scope: isTest ? 'TEST' : 'SOURCE',
        status: 'DETECTED',
        createdAt: new Date().toISOString()
      });
      continue;
    }

    // 5. Hardcoded Secret
    if (checkHardcodedSecret(code)) {
      const rule = DETERMINISTIC_RULES.find(r => r.category === 'HARDCODED_SECRET');
      const crossFp = generateCrossEngineFingerprint({
        category: 'HARDCODED_SECRET',
        filePath,
        startLine: lineNumber,
        evidence
      });

      findings.push({
        id: `find_${crypto.randomBytes(6).toString('hex')}`,
        scanId,
        scanner: 'pattern-sast',
        ruleId: rule.id,
        title: rule.title,
        category: rule.category,
        severity: isTest ? 'LOW' : rule.severity,
        confidence: isTest ? 'LOW' : rule.confidence,
        filePath: filePath.replace(/\\/g, '/'),
        startLine: lineNumber,
        endLine: lineNumber,
        message: rule.message,
        evidence,
        fingerprint: crossFp,
        isTestFile: isTest,
        scope: isTest ? 'TEST' : 'SOURCE',
        status: 'DETECTED',
        createdAt: new Date().toISOString()
      });
      continue;
    }

    // 6. Path Traversal
    if (checkPathTraversal(code)) {
      const rule = DETERMINISTIC_RULES.find(r => r.category === 'PATH_TRAVERSAL');
      const crossFp = generateCrossEngineFingerprint({
        category: 'PATH_TRAVERSAL',
        filePath,
        startLine: lineNumber,
        evidence
      });

      findings.push({
        id: `find_${crypto.randomBytes(6).toString('hex')}`,
        scanId,
        scanner: 'pattern-sast',
        ruleId: rule.id,
        title: rule.title,
        category: rule.category,
        severity: isTest ? 'LOW' : rule.severity,
        confidence: isTest ? 'LOW' : rule.confidence,
        filePath: filePath.replace(/\\/g, '/'),
        startLine: lineNumber,
        endLine: lineNumber,
        message: rule.message,
        evidence,
        fingerprint: crossFp,
        isTestFile: isTest,
        scope: isTest ? 'TEST' : 'SOURCE',
        status: 'DETECTED',
        createdAt: new Date().toISOString()
      });
      continue;
    }
  }

  return findings;
}

/**
 * Scan discovered source files across a workspace
 *
 * @param {string} workspacePath
 * @param {Array<Object>} sourceFiles
 * @param {string} scanId
 * @param {Object} [options={}]
 * @returns {Array<Object>}
 */
function scanWorkspace(workspacePath, sourceFiles, scanId, options = {}) {
  const allFindings = [];
  const nonCodeExts = new Set(['.md', '.txt', '.rst', '.markdown', '.map', '.json', '.yaml', '.yml']);

  for (const fileInfo of sourceFiles) {
    const ext = path.extname(fileInfo.path || '').toLowerCase();
    if (nonCodeExts.has(ext)) continue;

    const fullPath = path.join(workspacePath, fileInfo.path);
    let content;
    try {
      content = fs.readFileSync(fullPath, 'utf8');
    } catch {
      continue;
    }

    const fileFindings = scanFile(content, fileInfo.path, scanId, options);
    allFindings.push(...fileFindings);
  }

  return allFindings;
}

module.exports = {
  isTestFile,
  generateCrossEngineFingerprint,
  analyzeLines,
  checkSqlInjection,
  checkCommandInjection,
  checkCodeInjection,
  checkXss,
  checkHardcodedSecret,
  checkPathTraversal,
  scanFile,
  scanWorkspace,
  DETERMINISTIC_RULES
};
