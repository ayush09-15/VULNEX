const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { scanWithSemgrep, semgrepService } = require('./semgrep.service');

// Default security rules for lightweight fallback SAST pattern matching
const SECURITY_RULES = [
  {
    id: 'VULN-001',
    name: 'SQL Injection Vulnerability',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    severity: 'CRITICAL',
    pattern: /(?:query|execute|raw)\s*\(\s*[`'"].*?\$\{.*?\}|SELECT\s+.*?\s+FROM\s+.*?\s*\+\s*[\w\.]+/i,
    description: 'Direct concatenation or interpolation of untrusted input into SQL queries detected.',
    remediation: 'Use parameterized queries or prepared statements instead of string concatenation.'
  },
  {
    id: 'VULN-002',
    name: 'Command Injection / Unsafe Execution',
    category: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    severity: 'CRITICAL',
    pattern: /(?:child_process|cp)\.(?:exec|execSync)\s*\(\s*[`'"].*?\$\{.*?\}|eval\s*\(|new\s+Function\s*\(/,
    description: 'Unsafe execution of system commands or arbitrary code evaluation using dynamic input.',
    remediation: 'Use child_process.execFile with validated arguments, and avoid eval().'
  },
  {
    id: 'VULN-003',
    name: 'Hardcoded Secret / API Key',
    category: 'HARDCODED_SECRET',
    cwe: 'CWE-798',
    severity: 'HIGH',
    pattern: /(?:api_?key|secret|password|auth_?token|jwt_?secret)\s*[:=]\s*['"`][A-Za-z0-9_\-\.]{16,}['"`]/i,
    description: 'Sensitive credentials or API keys embedded directly into source code.',
    remediation: 'Move secrets into environment variables and reference them via process.env.'
  },
  {
    id: 'VULN-004',
    name: 'Path Traversal Vulnerability',
    category: 'PATH_TRAVERSAL',
    cwe: 'CWE-22',
    severity: 'HIGH',
    pattern: /fs\.(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:req\.(?:query|params|body)|path\.join\([^)]*req\.)/,
    description: 'File system access using unsanitized user path, enabling directory traversal.',
    remediation: 'Validate input against an allowlist and resolve paths safely with path.resolve() within allowed root.'
  },
  {
    id: 'VULN-005',
    name: 'Weak Cryptographic Hash (MD5 / SHA1)',
    category: 'INSECURE_CRYPTO',
    cwe: 'CWE-328',
    severity: 'MEDIUM',
    pattern: /crypto\.createHash\s*\(\s*['"`](?:md5|sha1)['"`]\s*\)/i,
    description: 'Usage of broken or cryptographically weak hashing algorithms.',
    remediation: 'Upgrade to collision-resistant hash algorithms such as SHA-256 or SHA-512.'
  },
  {
    id: 'VULN-006',
    name: 'Cross-Site Scripting (XSS) via Unescaped HTML',
    category: 'XSS',
    cwe: 'CWE-79',
    severity: 'HIGH',
    pattern: /dangerouslySetInnerHTML|innerHTML\s*=\s*(?:req\.|props\.|[^'"]*\+)/,
    description: 'Direct insertion of untrusted data into DOM without sanitization.',
    remediation: 'Sanitize HTML inputs using DOMPurify or use safe text node APIs.'
  },
  {
    id: 'VULN-007',
    name: 'Insecure CORS Wildcard with Credentials',
    category: 'SECURITY_MISCONFIG',
    cwe: 'CWE-942',
    severity: 'MEDIUM',
    pattern: /origin\s*:\s*['"`]\*['"`].*?credentials\s*:\s*true/s,
    description: 'Overly permissive CORS policy allowing wildcard origin with credential support.',
    remediation: 'Specify explicit allowed origins instead of wildcard when credentials are required.'
  }
];

// In-memory repositories, scans, and findings stores
const scansStore = new Map();
const findingsStore = new Map();

class ScannerService {
  constructor() {
    this.rules = SECURITY_RULES;
    this.semgrep = semgrepService;
  }

  /**
   * Scan raw code snippet or file content directly
   * @param {string} content Source code string
   * @param {string} filePath Optional file name/path
   * @returns {Array} List of detected vulnerabilities
   */
  scanContent(content, filePath = 'snippet.js') {
    const findings = [];
    const lines = content.split('\n');

    for (const rule of this.rules) {
      if (rule.pattern.test(content)) {
        lines.forEach((line, index) => {
          if (rule.pattern.test(line)) {
            const findingId = `find_${crypto.randomBytes(6).toString('hex')}`;
            findings.push({
              id: findingId,
              scanner: 'fallback-sast',
              ruleId: rule.id,
              title: rule.name,
              category: rule.category,
              cwe: rule.cwe,
              severity: rule.severity,
              confidence: 'MEDIUM',
              filePath,
              startLine: index + 1,
              endLine: index + 1,
              codeSnippet: line.trim(),
              evidence: line.trim(),
              message: rule.description,
              remediation: rule.remediation,
              fingerprint: crypto.createHash('sha256').update(`${rule.id}:${filePath}:${index + 1}`).digest('hex'),
              status: 'DETECTED',
              createdAt: new Date().toISOString()
            });
          }
        });
      }
    }

    return findings;
  }

  /**
   * Create and trigger a scan
   * @param {Object} scanData
   * @returns {Object} Created scan record
   */
  async createScan({ repositoryId, repositoryPath, name = 'Automated Scan' }) {
    const scanId = `scan_${crypto.randomBytes(6).toString('hex')}`;
    const scanRecord = {
      id: scanId,
      repositoryId: repositoryId || 'repo_default',
      name,
      repositoryPath: repositoryPath || './',
      status: 'SCANNING',
      stage: 'SCANNING',
      findingsCount: 0,
      severities: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      startedAt: new Date().toISOString(),
      completedAt: null,
      provenance: null,
      errors: []
    };

    scansStore.set(scanId, scanRecord);

    // Asynchronously perform scan using Semgrep if available, fallback to internal scanner
    setImmediate(async () => {
      try {
        let findings = [];
        let errors = [];

        if (repositoryPath && fs.existsSync(repositoryPath)) {
          const semgrepAvailable = await this.semgrep.isAvailable();
          if (semgrepAvailable) {
            const semgrepResult = await scanWithSemgrep(repositoryPath, { scanId });
            findings = semgrepResult.findings || [];
            errors = semgrepResult.errors || [];
            scanRecord.provenance = semgrepResult.provenance;
            scanRecord.status = semgrepResult.status;
          } else {
            // Local fallback rule scan if Semgrep is not installed
            findings = this.scanDirectory(repositoryPath);
            scanRecord.status = 'COMPLETED';
          }
        } else {
          // If no path specified or workspace missing, fail with WORKSPACE_NOT_FOUND error (never substitute mock findings)
          findings = [];
          errors = [`Workspace directory not found: ${repositoryPath || 'unspecified'}`];
          scanRecord.status = 'FAILED';
          scanRecord.stage = 'FAILED';
          scanRecord.errorCode = 'WORKSPACE_NOT_FOUND';
        }

        // Attach scanId and store findings
        findings.forEach(f => {
          f.scanId = scanId;
          findingsStore.set(f.id, f);
          if (scanRecord.severities[f.severity] !== undefined) {
            scanRecord.severities[f.severity]++;
          }
        });

        scanRecord.findingsCount = findings.length;
        scanRecord.errors = errors;
        scanRecord.completedAt = new Date().toISOString();
        scanRecord.stage = 'COMPLETED';
      } catch (err) {
        scanRecord.status = 'FAILED';
        scanRecord.stage = 'FAILED';
        scanRecord.errorCode = 'SCANNER_FAILURE';
        scanRecord.errors.push(err.message);
        scanRecord.completedAt = new Date().toISOString();
      }
    });

    return scanRecord;
  }

  /**
   * Scan directory recursively with built-in patterns
   */
  scanDirectory(dirPath, extensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.json']) {
    const findings = [];
    const walk = (currentPath) => {
      if (!fs.existsSync(currentPath)) return;
      const entries = fs.readdirSync(currentPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(currentPath, entry.name);
        if (entry.isDirectory()) {
          if (!['node_modules', '.git', 'dist', 'build', '.workspaces', 'coverage'].includes(entry.name)) {
            walk(fullPath);
          }
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (extensions.includes(ext)) {
            try {
              const content = fs.readFileSync(fullPath, 'utf8');
              const relPath = path.relative(dirPath, fullPath).replace(/\\/g, '/');
              const fileFindings = this.scanContent(content, relPath);
              findings.push(...fileFindings);
            } catch (_) {}
          }
        }
      }
    };

    walk(dirPath);
    return findings;
  }

  generateSampleFindings(scanId) {
    return [
      {
        id: `find_${crypto.randomBytes(6).toString('hex')}`,
        scanId,
        scanner: 'semgrep',
        ruleId: 'javascript.express.security.audit.sqli',
        title: 'SQL Injection in User Search',
        category: 'SQL_INJECTION',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        filePath: 'src/controllers/user.controller.js',
        startLine: 42,
        endLine: 42,
        message: 'Direct string interpolation in SQL query permits arbitrary SQL injection.',
        evidence: 'const query = `SELECT * FROM users WHERE username = \'${req.query.username}\'`;',
        fingerprint: crypto.createHash('sha256').update(`sqli:src/controllers/user.controller.js:42`).digest('hex'),
        status: 'DETECTED',
        createdAt: new Date().toISOString()
      }
    ];
  }

  getScan(scanId) {
    return scansStore.get(scanId) || null;
  }

  listScans() {
    return Array.from(scansStore.values());
  }

  getFindings(scanId) {
    const fromScanner = Array.from(findingsStore.values()).filter(f => f.scanId === scanId);
    const { scanOrchestrator } = require('../orchestrator/scanOrchestrator');
    const fromOrch = scanOrchestrator.getScanFindings(scanId);
    const map = new Map();
    for (const f of [...fromScanner, ...fromOrch]) {
      map.set(f.id, f);
    }
    return Array.from(map.values());
  }

  getAllFindings() {
    const fromScanner = Array.from(findingsStore.values());
    const { scanOrchestrator } = require('../orchestrator/scanOrchestrator');
    const fromOrch = scanOrchestrator.getAllFindings();
    const map = new Map();
    for (const f of [...fromScanner, ...fromOrch]) {
      map.set(f.id, f);
    }
    return Array.from(map.values());
  }

  getFindingById(id) {
    const fromScanner = findingsStore.get(id);
    if (fromScanner) return fromScanner;
    const { scanOrchestrator } = require('../orchestrator/scanOrchestrator');
    return scanOrchestrator.getFindingById(id);
  }

  updateFinding(id, updates) {
    const finding = findingsStore.get(id);
    if (!finding) return null;
    const updated = { ...finding, ...updates, updatedAt: new Date().toISOString() };
    findingsStore.set(id, updated);
    return updated;
  }

  addFinding(finding) {
    if (!finding || !finding.id) {
      throw new Error('Finding must have an id');
    }
    findingsStore.set(finding.id, finding);
    return finding;
  }

  deleteScan(scanId) {
    const exists = scansStore.has(scanId);
    if (exists) {
      scansStore.delete(scanId);
      for (const [fId, finding] of findingsStore.entries()) {
        if (finding.scanId === scanId) {
          findingsStore.delete(fId);
        }
      }
    }
    return exists;
  }
}

module.exports = new ScannerService();

