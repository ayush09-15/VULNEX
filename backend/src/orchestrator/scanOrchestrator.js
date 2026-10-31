const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { ScanStateMachine, SCAN_STATES, isTerminalState } = require('./scanStateMachine');
const inventoryService = require('../services/inventory.service');
const { semgrepService } = require('../services/semgrep.service');
const npmAuditService = require('../services/npmAudit.service');
const { validateFinding, validateScan } = require('../validators/canonical.schema');

/**
 * ============================================================================
 * VULNEX Core Scan Orchestrator
 * 
 * Responsibilities (Bible Part IV Section 4.2 & Part VIII Section 8.7):
 * 1. Single traceable scan ID generation and correlation.
 * 2. Stage-by-stage lifecycle state machine execution:
 *    QUEUED -> PREPARING -> SCANNING -> NORMALIZING -> COMPLETED / PARTIAL / FAILED
 * 3. Immutable timestamped stage event logging.
 * 4. Workspace inventory and manifest inspection during PREPARING.
 * 5. Multi-scanner dispatch (Semgrep CLI + deterministic pattern engine).
 * 6. Canonical finding normalization and fingerprint deduplication.
 * 7. Partial failure resilience (scanner failures yield PARTIAL status, never discarded data).
 * ============================================================================
 */

// Persistent in-memory scan records & findings stores (isolated behind orchestrator interface)
const scansStore = new Map();
const findingsStore = new Map();

// Built-in deterministic pattern rules for lightweight/fallback SAST scanning
const DETERMINISTIC_RULES = [
  {
    id: 'vulnex.javascript.sqli',
    title: 'SQL Injection via unsanitized query parameters',
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    pattern: /(?:query|execute|raw)\s*\(\s*[`'"].*?\$\{.*?\}|SELECT\s+.*?\s+FROM\s+.*?\s*\+\s*[\w\.]+/i,
    message: 'Direct concatenation or interpolation of untrusted input into SQL queries detected.'
  },
  {
    id: 'vulnex.javascript.cmd-injection',
    title: 'Command Injection via child_process execution',
    category: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    pattern: /(?:child_process|cp)\.(?:exec|execSync)\s*\(\s*[`'"].*?\$\{.*?\}|eval\s*\(|new\s+Function\s*\(/,
    message: 'Dynamic untrusted argument passed to system command or code evaluation.'
  },
  {
    id: 'vulnex.javascript.hardcoded-secret',
    title: 'Hard-coded Secret / API Token',
    category: 'HARDCODED_SECRET',
    severity: 'HIGH',
    confidence: 'HIGH',
    pattern: /(?:api_?key|secret|password|auth_?token|jwt_?secret)\s*[:=]\s*['"`][A-Za-z0-9_\-\.]{16,}['"`]/i,
    message: 'Sensitive credential or secret key embedded directly into source code.'
  },
  {
    id: 'vulnex.javascript.path-traversal',
    title: 'Path Traversal via unsanitized file system access',
    category: 'PATH_TRAVERSAL',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    pattern: /fs\.(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:req\.(?:query|params|body)|path\.join\([^)]*req\.)/,
    message: 'File read operation using unsanitized user path allows directory traversal.'
  },
  {
    id: 'vulnex.javascript.xss',
    title: 'Cross-Site Scripting (XSS) via unescaped HTML injection',
    category: 'XSS',
    severity: 'HIGH',
    confidence: 'HIGH',
    pattern: /dangerouslySetInnerHTML|innerHTML\s*=\s*(?:req\.|props\.|[^'"]*\+)/,
    message: 'Direct insertion of untrusted data into DOM without context-aware output encoding.'
  }
];

/**
 * Generate a deterministic fingerprint for a finding (SHA-256 of ruleId + filePath + snippet)
 * @param {Object} param
 * @param {string} param.ruleId
 * @param {string} param.filePath
 * @param {string} param.evidence
 * @returns {string} 64-char hex string
 */
function generateFingerprint({ ruleId, filePath, evidence }) {
  const normalizedPath = (filePath || '').replace(/\\/g, '/');
  const normalizedEvidence = (evidence || '').trim().replace(/\s+/g, ' ');
  return crypto.createHash('sha256')
    .update(`${ruleId}:${normalizedPath}:${normalizedEvidence}`)
    .digest('hex');
}

/**
 * Sanitize error messages to scrub stack traces, credentials, tokens, and private host paths.
 * @param {Error|string|any} err
 * @returns {string}
 */
function sanitizeErrorMessage(err) {
  if (!err) return 'Unknown scanner error';
  let raw = typeof err === 'string' ? err : (err.message || String(err));

  // Extract primary error line (strip stack frames)
  let line = raw.split(/\r?\n/)[0] || '';
  line = line.replace(/\s+at\s+[\w$.<>]+\s+\([^)]+:\d+:\d+\)$/, '').trim();

  // Strip file paths containing user home directories
  line = line.replace(/(?:\/Users\/|\/home\/|[A-Za-z]:[\\/]Users[\\/])[^/\\]+[/\\]?/g, '~/');

  // Redact AWS credentials
  line = line.replace(/\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g, '[REDACTED_AWS_KEY]');

  // Redact GitHub / generic tokens
  line = line.replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b/g, '[REDACTED_TOKEN]');

  // Redact JWT / Bearer tokens
  line = line.replace(/Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g, 'Bearer [REDACTED_JWT]');

  // Redact secret / password / token assignments
  line = line.replace(/(password|passwd|pwd|secret|api_key|apikey|auth_token)\s*([:=])\s*(['"`]?)(?!\[REDACTED_)([^'"`\s]{4,})\3/gi, '$1=$3[REDACTED_SECRET]$3');

  return line || 'Unknown scanner error';
}

/**
 * Append an immutable event to the scan record's timeline
 * @param {Object} scanRecord
 * @param {string} stage
 * @param {'IN_PROGRESS'|'SUCCESS'|'FAILED'|'SKIPPED'} status
 * @param {string} message
 * @param {Object} [details]
 * @returns {Object} Appended event
 */
function recordEvent(scanRecord, stage, status, message, details = {}) {
  const event = {
    stage,
    status,
    timestamp: new Date().toISOString(),
    message,
    ...(details && Object.keys(details).length > 0 ? { details } : {})
  };

  scanRecord.events.push(event);
  return event;
}

/**
 * Run deterministic pattern-based SAST scanning across discovered source files
 * @param {string} workspacePath
 * @param {Array<Object>} sourceFiles
 * @param {string} scanId
 * @returns {Array<Object>}
 */
function scanWithDeterministicPatterns(workspacePath, sourceFiles, scanId) {
  const findings = [];

  for (const fileInfo of sourceFiles) {
    const fullPath = path.join(workspacePath, fileInfo.path);
    let content;
    try {
      content = fs.readFileSync(fullPath, 'utf8');
    } catch {
      continue;
    }

    const lines = content.split('\n');

    for (const rule of DETERMINISTIC_RULES) {
      if (!rule.pattern.test(content)) continue;

      lines.forEach((lineText, idx) => {
        if (rule.pattern.test(lineText)) {
          const lineNumber = idx + 1;
          const trimmedLine = lineText.trim();
          const fingerprint = generateFingerprint({
            ruleId: rule.id,
            filePath: fileInfo.path,
            evidence: trimmedLine
          });

          findings.push({
            id: `find_${crypto.randomBytes(6).toString('hex')}`,
            scanId,
            scanner: 'pattern-sast',
            ruleId: rule.id,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            confidence: rule.confidence,
            filePath: fileInfo.path.replace(/\\/g, '/'),
            startLine: lineNumber,
            endLine: lineNumber,
            message: rule.message,
            evidence: trimmedLine,
            fingerprint,
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
 * Core Orchestrator Class
 */
class ScanOrchestrator {
  constructor() {
    this.semgrep = semgrepService;
    this.npmAudit = npmAuditService;
    this.inventory = inventoryService;
  }

  /**
   * Start a fully managed scan workflow:
   * QUEUED -> PREPARING -> SCANNING -> NORMALIZING -> COMPLETED/PARTIAL/FAILED
   * 
   * @param {Object} input
   * @param {string} input.repositoryId - Associated repository ID
   * @param {string} input.repositoryPath - Absolute or relative path to workspace
   * @param {string} [input.ref='main'] - Git branch/tag/ref
   * @param {Array<string>} [input.scanners=['semgrep', 'npm-audit', 'patterns']] - Target scanner engines
   * @param {Object} [options={}]
   * @param {string} [options.scanId] - Predefined scanId (optional)
   * @param {boolean} [options.async=false] - Whether to return immediately after QUEUED
   * @returns {Promise<Object>} The canonical Scan record
   */
  async startScan(input, options = {}) {
    const repositoryId = input.repositoryId || 'repo_default';
    const repositoryPath = input.repositoryPath || './';
    const ref = input.ref || 'main';
    const configuredScanners = Array.isArray(input.scanners) && input.scanners.length > 0
      ? input.scanners
      : ['semgrep', 'npm-audit', 'patterns'];

    // 1. Generate single traceable Scan ID
    const scanId = options.scanId || `scan_${crypto.randomBytes(6).toString('hex')}`;
    const stateMachine = new ScanStateMachine(SCAN_STATES.QUEUED, { scanId });

    // Initialize canonical scan record
    const scanRecord = {
      id: scanId,
      repositoryId,
      ref,
      status: SCAN_STATES.QUEUED,
      stage: SCAN_STATES.QUEUED,
      toolVersions: {},
      startedAt: null,
      completedAt: null,
      errorCode: null,
      workspaceId: options.workspaceId || path.basename(repositoryPath),
      createdAt: new Date().toISOString(),
      events: [],
      summary: {
        totalFindings: 0,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        scannersRun: [],
        scannersFailed: [],
        scannerOutcomes: {}
      }
    };

    // Record initial QUEUED event
    recordEvent(scanRecord, SCAN_STATES.QUEUED, 'SUCCESS', 'Scan queued in orchestrator');
    scansStore.set(scanId, scanRecord);

    // Execution pipeline runner
    const executePipeline = async () => {
      try {
        // --------------------------------------------------------------------
        // PHASE 1: PREPARING (Intake & Bounded Workspace Inventory)
        // --------------------------------------------------------------------
        stateMachine.transition(SCAN_STATES.PREPARING, { reason: 'Workspace preparation initiated' });
        scanRecord.status = SCAN_STATES.PREPARING;
        scanRecord.stage = SCAN_STATES.PREPARING;
        scanRecord.startedAt = new Date().toISOString();
        recordEvent(scanRecord, SCAN_STATES.PREPARING, 'IN_PROGRESS', 'Validating workspace and inspecting source tree');

        const resolvedWorkspace = path.resolve(repositoryPath);

        if (!fs.existsSync(resolvedWorkspace)) {
          const errorMsg = `Workspace path does not exist: ${resolvedWorkspace}`;
          recordEvent(scanRecord, SCAN_STATES.PREPARING, 'FAILED', errorMsg);
          stateMachine.fail('WORKSPACE_NOT_FOUND', errorMsg);
          scanRecord.status = SCAN_STATES.FAILED;
          scanRecord.stage = SCAN_STATES.FAILED;
          scanRecord.errorCode = 'WORKSPACE_ERROR';
          scanRecord.completedAt = new Date().toISOString();
          return scanRecord;
        }

        let inventory;
        try {
          inventory = this.inventory.scanWorkspace(resolvedWorkspace);
          recordEvent(scanRecord, SCAN_STATES.PREPARING, 'SUCCESS', 'Workspace inventory completed', {
            totalFiles: inventory.totalFiles,
            manifestCount: inventory.manifests.length,
            languages: inventory.summary.fileCountByLanguage
          });
        } catch (invErr) {
          const errorMsg = `Workspace inventory failed: ${invErr.message}`;
          recordEvent(scanRecord, SCAN_STATES.PREPARING, 'FAILED', errorMsg);
          stateMachine.fail('INVENTORY_ERROR', errorMsg);
          scanRecord.status = SCAN_STATES.FAILED;
          scanRecord.stage = SCAN_STATES.FAILED;
          scanRecord.errorCode = 'WORKSPACE_ERROR';
          scanRecord.completedAt = new Date().toISOString();
          return scanRecord;
        }

        // --------------------------------------------------------------------
        // PHASE 2: SCANNING (Multi-Scanner Execution with Partial Resilience)
        // --------------------------------------------------------------------
        stateMachine.transition(SCAN_STATES.SCANNING, { reason: 'Dispatching configured security scanners' });
        scanRecord.status = SCAN_STATES.SCANNING;
        scanRecord.stage = SCAN_STATES.SCANNING;
        recordEvent(scanRecord, SCAN_STATES.SCANNING, 'IN_PROGRESS', `Initiating detection engines: ${configuredScanners.join(', ')}`);

        const rawFindings = [];

        const normScanners = configuredScanners.map(s => String(s).toLowerCase().trim());
        const shouldRunSemgrep = normScanners.some(s => ['semgrep', 'semgrep-sast', 'sast'].includes(s));
        const shouldRunNpmAudit = normScanners.some(s => ['npm-audit', 'npm_audit', 'npm', 'dependency-audit', 'dependency_audit', 'audit'].includes(s));
        const shouldRunPatterns = normScanners.some(s => ['patterns', 'pattern-sast', 'pattern'].includes(s));

        // Scanner A Task: Semgrep CLI
        const runSemgrepTask = async () => {
          const start = Date.now();
          recordEvent(scanRecord, SCAN_STATES.SCANNING, 'IN_PROGRESS', 'Executing Semgrep static analysis engine');

          try {
            const semgrepAvailable = await this.semgrep.isAvailable();
            if (!semgrepAvailable) {
              const errMsg = 'Semgrep binary unavailable on host environment';
              return {
                scanner: 'semgrep',
                status: 'FAILED',
                findings: [],
                errors: [errMsg],
                durationMs: Date.now() - start,
                toolVersion: null,
                diagnostic: 'Semgrep binary not detected on PATH; skipped Semgrep pass'
              };
            }

            const semgrepResult = await this.semgrep.scanWithSemgrep(resolvedWorkspace, { scanId });
            const durationMs = semgrepResult.durationMs || (Date.now() - start);
            const toolVersion = semgrepResult.provenance?.version || null;

            if (semgrepResult.success || semgrepResult.status === 'COMPLETED') {
              return {
                scanner: 'semgrep',
                status: 'COMPLETED',
                findings: semgrepResult.findings || [],
                errors: [],
                durationMs,
                toolVersion,
                diagnostic: null
              };
            } else {
              const rawErr = semgrepResult.errors?.[0] || 'Semgrep scan completed with error status';
              const sanitizedErr = sanitizeErrorMessage(rawErr);
              return {
                scanner: 'semgrep',
                status: 'FAILED',
                findings: semgrepResult.findings || [],
                errors: [sanitizedErr],
                durationMs,
                toolVersion,
                diagnostic: sanitizedErr
              };
            }
          } catch (semgrepErr) {
            const sanitizedErr = sanitizeErrorMessage(semgrepErr);
            return {
              scanner: 'semgrep',
              status: 'FAILED',
              findings: [],
              errors: [sanitizedErr],
              durationMs: Date.now() - start,
              toolVersion: null,
              diagnostic: sanitizedErr
            };
          }
        };

        // Scanner B Task: npm Dependency Audit
        const runNpmAuditTask = async () => {
          const start = Date.now();
          recordEvent(scanRecord, SCAN_STATES.SCANNING, 'IN_PROGRESS', 'Executing npm dependency audit scanner');

          try {
            const auditResult = await this.npmAudit.scanWorkspace(resolvedWorkspace, { scanId });
            const durationMs = auditResult.durationMs || (Date.now() - start);
            let version = null;
            try {
              version = await this.npmAudit.getVersion();
            } catch (_) {}

            if (auditResult.success || auditResult.status === 'COMPLETED') {
              const findings = auditResult.findings || [];
              const skipped = auditResult.metadata?.skipped;
              const errors = (auditResult.errors || []).map(sanitizeErrorMessage);

              return {
                scanner: 'npm-audit',
                status: 'COMPLETED',
                findings,
                errors,
                durationMs,
                toolVersion: version,
                diagnostic: skipped ? (auditResult.metadata?.reason || 'Skipped: no package manifest') : null
              };
            } else {
              const rawErr = auditResult.errors?.[0] || 'npm audit execution failed';
              const sanitizedErr = sanitizeErrorMessage(rawErr);
              return {
                scanner: 'npm-audit',
                status: 'FAILED',
                findings: auditResult.findings || [],
                errors: [sanitizedErr],
                durationMs,
                toolVersion: version,
                diagnostic: sanitizedErr
              };
            }
          } catch (auditErr) {
            const sanitizedErr = sanitizeErrorMessage(auditErr);
            return {
              scanner: 'npm-audit',
              status: 'FAILED',
              findings: [],
              errors: [sanitizedErr],
              durationMs: Date.now() - start,
              toolVersion: null,
              diagnostic: sanitizedErr
            };
          }
        };

        // Scanner C Task: Deterministic Pattern SAST
        const runPatternsTask = async () => {
          const start = Date.now();
          recordEvent(scanRecord, SCAN_STATES.SCANNING, 'IN_PROGRESS', 'Executing deterministic pattern scanner');

          try {
            const patternFindings = scanWithDeterministicPatterns(resolvedWorkspace, inventory.sourceFiles, scanId);
            return {
              scanner: 'pattern-sast',
              status: 'COMPLETED',
              findings: patternFindings,
              errors: [],
              durationMs: Date.now() - start,
              toolVersion: '1.0.0',
              diagnostic: null
            };
          } catch (patternErr) {
            const sanitizedErr = sanitizeErrorMessage(patternErr);
            return {
              scanner: 'pattern-sast',
              status: 'FAILED',
              findings: [],
              errors: [sanitizedErr],
              durationMs: Date.now() - start,
              toolVersion: null,
              diagnostic: sanitizedErr
            };
          }
        };

        const scannerTasks = [];
        if (shouldRunSemgrep) scannerTasks.push(runSemgrepTask());
        if (shouldRunNpmAudit) scannerTasks.push(runNpmAuditTask());
        if (shouldRunPatterns) scannerTasks.push(runPatternsTask());

        // Handle explicitly requested unrecognized scanners
        for (const scannerName of configuredScanners) {
          const norm = scannerName.toLowerCase().trim();
          if (
            !['semgrep', 'semgrep-sast', 'sast'].includes(norm) &&
            !['npm-audit', 'npm_audit', 'npm', 'dependency-audit', 'dependency_audit', 'audit'].includes(norm) &&
            !['patterns', 'pattern-sast', 'pattern'].includes(norm)
          ) {
            scannerTasks.push(Promise.resolve({
              scanner: scannerName,
              status: 'FAILED',
              findings: [],
              errors: [`Unrecognized scanner engine: ${scannerName}`],
              durationMs: 0,
              toolVersion: null,
              diagnostic: `Scanner '${scannerName}' is not supported`
            }));
          }
        }

        const outcomes = await Promise.allSettled(scannerTasks);

        for (const res of outcomes) {
          const outcome = res.status === 'fulfilled'
            ? res.value
            : {
                scanner: 'unknown',
                status: 'FAILED',
                findings: [],
                errors: [sanitizeErrorMessage(res.reason)],
                durationMs: 0,
                toolVersion: null,
                diagnostic: sanitizeErrorMessage(res.reason)
              };

          const { scanner, status, findings, errors, durationMs, toolVersion, diagnostic } = outcome;

          if (toolVersion) {
            scanRecord.toolVersions[scanner] = toolVersion;
          }

          scanRecord.summary.scannerOutcomes[scanner] = {
            status,
            durationMs,
            findingsCount: findings ? findings.length : 0,
            errors,
            diagnostic: diagnostic || null
          };

          const scannerLabel = scanner === 'semgrep'
            ? 'Semgrep'
            : (scanner === 'npm-audit' ? 'npm-audit' : (scanner === 'pattern-sast' ? 'Pattern' : scanner));

          if (status === 'COMPLETED') {
            scanRecord.summary.scannersRun.push(scanner);
            if (findings && findings.length > 0) {
              rawFindings.push(...findings);
            }
            recordEvent(
              scanRecord,
              SCAN_STATES.SCANNING,
              'SUCCESS',
              `${scannerLabel} completed with ${findings ? findings.length : 0} finding(s)`,
              { durationMs, findingsCount: findings ? findings.length : 0 }
            );
          } else {
            const primaryErr = errors[0] || `${scanner} scan failed`;
            scanRecord.summary.scannersFailed.push({ scanner, error: primaryErr });

            // Preserve any partial findings salvaged despite non-zero exit:
            if (findings && findings.length > 0) {
              rawFindings.push(...findings);
            }

            if (diagnostic && diagnostic.includes('not detected on PATH')) {
              recordEvent(
                scanRecord,
                SCAN_STATES.SCANNING,
                'SKIPPED',
                'Semgrep binary not detected on PATH; skipped Semgrep pass',
                { durationMs, error: primaryErr }
              );
            } else {
              recordEvent(
                scanRecord,
                SCAN_STATES.SCANNING,
                'FAILED',
                `${scannerLabel} scanner reported error: ${primaryErr}`,
                { durationMs, error: primaryErr }
              );
            }
          }
        }

        // --------------------------------------------------------------------
        // PHASE 3: NORMALIZING (Deduplication, Stable Fingerprinting & Storage)
        // --------------------------------------------------------------------
        stateMachine.transition(SCAN_STATES.NORMALIZING, { reason: 'Aggregating and normalizing findings' });
        scanRecord.status = SCAN_STATES.NORMALIZING;
        scanRecord.stage = SCAN_STATES.NORMALIZING;
        recordEvent(scanRecord, SCAN_STATES.NORMALIZING, 'IN_PROGRESS', `Normalizing ${rawFindings.length} raw scanner findings`);

        const normalizedFindings = [];
        const seenFingerprints = new Set();

        for (const raw of rawFindings) {
          // Normalize coordinates and paths
          const rawPath = raw.filePath || raw.file || raw.path || 'unknown.js';
          const cleanPath = String(rawPath).replace(/\\/g, '/').replace(/^\/+/, '');
          const startLine = Math.max(1, parseInt(raw.startLine, 10) || 1);
          const endLine = Math.max(startLine, parseInt(raw.endLine, 10) || startLine);
          const evidence = typeof raw.evidence === 'string'
            ? raw.evidence
            : (raw.codeSnippet || (raw.evidence ? JSON.stringify(raw.evidence) : ''));

          const ruleId = raw.ruleId || raw.rule || raw.check_id || 'generic.security.rule';

          const fingerprint = raw.fingerprint || generateFingerprint({
            ruleId,
            filePath: cleanPath,
            evidence
          });

          // Deduplicate by stable fingerprint
          if (seenFingerprints.has(fingerprint)) {
            continue;
          }
          seenFingerprints.add(fingerprint);

          const findingId = raw.id && raw.id.startsWith('find_')
            ? raw.id
            : `find_${crypto.randomBytes(6).toString('hex')}`;

          const validCategories = [
            'SQL_INJECTION', 'XSS', 'HARDCODED_SECRET', 'VULNERABLE_DEPENDENCY',
            'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'INJECTION', 'BROKEN_AUTH',
            'SENSITIVE_DATA_EXPOSURE', 'SECURITY_MISCONFIG', 'OTHER'
          ];
          const rawCat = raw.category ? String(raw.category).toUpperCase() : 'OTHER';
          const category = validCategories.includes(rawCat) ? rawCat : 'OTHER';

          const canonicalFinding = {
            id: findingId,
            scanId,
            scanner: raw.scanner || 'semgrep',
            ruleId,
            title: raw.title || raw.name || 'Security Finding',
            category,
            severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(raw.severity)
              ? raw.severity
              : 'MEDIUM',
            confidence: ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].includes(raw.confidence)
              ? raw.confidence
              : 'MEDIUM',
            filePath: cleanPath,
            startLine,
            endLine,
            message: raw.message || raw.description || '',
            evidence,
            fingerprint,
            status: 'DETECTED',
            createdAt: raw.createdAt || new Date().toISOString()
          };

          // Validate against canonical FindingSchema
          const valResult = validateFinding(canonicalFinding);
          if (valResult.success) {
            normalizedFindings.push(canonicalFinding);
            findingsStore.set(canonicalFinding.id, canonicalFinding);

            // Update severity metrics
            if (scanRecord.summary.bySeverity[canonicalFinding.severity] !== undefined) {
              scanRecord.summary.bySeverity[canonicalFinding.severity]++;
            }
          }
        }

        scanRecord.summary.totalFindings = normalizedFindings.length;
        recordEvent(scanRecord, SCAN_STATES.NORMALIZING, 'SUCCESS', `Normalized and stored ${normalizedFindings.length} unique finding(s)`);

        // --------------------------------------------------------------------
        // PHASE 4: TERMINAL RESOLUTION (Partial Failure Resilience)
        // --------------------------------------------------------------------
        const totalScannersRun = scanRecord.summary.scannersRun.length;
        const totalScannersFailed = scanRecord.summary.scannersFailed.length;

        if (totalScannersRun === 0 && totalScannersFailed > 0) {
          // Catastrophic failure: All scanners failed
          stateMachine.fail('SCANNER_FAILURE', 'All configured scanners failed to execute');
          scanRecord.status = SCAN_STATES.FAILED;
          scanRecord.stage = SCAN_STATES.FAILED;
          scanRecord.errorCode = 'SCANNER_FAILURE';
          recordEvent(scanRecord, SCAN_STATES.FAILED, 'FAILED', 'Scan terminated: all scanners failed');
        } else if (totalScannersFailed > 0) {
          // Partial failure: At least one scanner succeeded, but one or more failed
          stateMachine.complete(true, `${totalScannersFailed} scanner(s) failed, but usable findings were preserved`);
          scanRecord.status = SCAN_STATES.PARTIAL;
          scanRecord.stage = SCAN_STATES.COMPLETED;
          recordEvent(scanRecord, SCAN_STATES.PARTIAL, 'SUCCESS', `Scan completed with PARTIAL results (${normalizedFindings.length} findings preserved)`);
        } else {
          // Full success: All scanners completed
          stateMachine.complete(false, 'All configured scanners completed successfully');
          scanRecord.status = SCAN_STATES.COMPLETED;
          scanRecord.stage = SCAN_STATES.COMPLETED;
          recordEvent(scanRecord, SCAN_STATES.COMPLETED, 'SUCCESS', `Scan completed successfully with ${normalizedFindings.length} findings`);
        }

        scanRecord.completedAt = new Date().toISOString();
        return scanRecord;
      } catch (pipelineErr) {
        // Unexpected unhandled pipeline crash
        if (!isTerminalState(scanRecord.status)) {
          try {
            stateMachine.fail('INTERNAL_ERROR', pipelineErr.message);
          } catch (_) {}
          scanRecord.status = SCAN_STATES.FAILED;
          scanRecord.stage = SCAN_STATES.FAILED;
          scanRecord.errorCode = 'INTERNAL_ERROR';
        }
        scanRecord.completedAt = new Date().toISOString();
        recordEvent(scanRecord, SCAN_STATES.FAILED, 'FAILED', `Fatal pipeline error: ${pipelineErr.message}`);
        return scanRecord;
      }
    };

    if (options.async) {
      // Background execution
      setImmediate(executePipeline);
      return scanRecord;
    }

    // Synchronous execution for immediate response / testing
    return await executePipeline();
  }

  /**
   * Retrieve a scan record by ID
   * @param {string} scanId
   * @returns {Object|null}
   */
  getScan(scanId) {
    return scansStore.get(scanId) || null;
  }

  /**
   * List all scan records
   * @returns {Array<Object>}
   */
  listScans() {
    return Array.from(scansStore.values());
  }

  /**
   * Retrieve timestamped event timeline for a scan
   * @param {string} scanId
   * @returns {Array<Object>|null}
   */
  getScanEvents(scanId) {
    const scan = this.getScan(scanId);
    return scan ? scan.events : null;
  }

  /**
   * Retrieve findings for a specific scan with optional filtering
   * @param {string} scanId
   * @param {Object} [filters={}]
   * @param {string} [filters.severity]
   * @param {string} [filters.category]
   * @param {string} [filters.scanner]
   * @param {string} [filters.status]
   * @returns {Array<Object>}
   */
  getScanFindings(scanId, filters = {}) {
    let findings = Array.from(findingsStore.values()).filter((f) => f.scanId === scanId);

    if (filters.severity) {
      findings = findings.filter((f) => f.severity.toUpperCase() === filters.severity.toUpperCase());
    }
    if (filters.category) {
      findings = findings.filter((f) => f.category.toUpperCase() === filters.category.toUpperCase());
    }
    if (filters.scanner) {
      findings = findings.filter((f) => f.scanner.toLowerCase() === filters.scanner.toLowerCase());
    }
    if (filters.status) {
      findings = findings.filter((f) => f.status.toUpperCase() === filters.status.toUpperCase());
    }

    return findings;
  }

  /**
   * Cancel an in-flight scan
   * @param {string} scanId
   * @param {string} [reason='Scan cancelled by user']
   * @returns {Object|null}
   */
  cancelScan(scanId, reason = 'Scan cancelled by user') {
    const scan = this.getScan(scanId);
    if (!scan) return null;

    if (isTerminalState(scan.status)) {
      const { InvalidStateTransitionError } = require('./scanStateMachine');
      throw new InvalidStateTransitionError(
        scan.status,
        SCAN_STATES.CANCELLED,
        `Cannot cancel scan in terminal state '${scan.status}'`
      );
    }

    scan.status = SCAN_STATES.CANCELLED;
    scan.stage = SCAN_STATES.CANCELLED;
    scan.completedAt = new Date().toISOString();

    recordEvent(scan, SCAN_STATES.CANCELLED, 'SUCCESS', reason);
    return scan;
  }

  /**
   * Delete a scan and its associated findings
   * @param {string} scanId
   * @returns {boolean}
   */
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

  /**
   * Get an individual finding by ID
   * @param {string} findingId
   * @returns {Object|null}
   */
  getFindingById(findingId) {
    return findingsStore.get(findingId) || null;
  }

  /**
   * List all findings with optional filtering
   * @param {Object} [filters={}]
   * @returns {Array<Object>}
   */
  getAllFindings(filters = {}) {
    let findings = Array.from(findingsStore.values());

    if (filters.scanId) {
      findings = findings.filter((f) => f.scanId === filters.scanId);
    }
    if (filters.severity) {
      findings = findings.filter((f) => f.severity.toUpperCase() === filters.severity.toUpperCase());
    }
    if (filters.category) {
      findings = findings.filter((f) => f.category.toUpperCase() === filters.category.toUpperCase());
    }
    if (filters.scanner) {
      findings = findings.filter((f) => f.scanner.toLowerCase() === filters.scanner.toLowerCase());
    }
    if (filters.status) {
      findings = findings.filter((f) => f.status.toUpperCase() === filters.status.toUpperCase());
    }

    return findings;
  }

  /**
   * Update an existing finding (e.g. status transition, AI analysis, patch link)
   * @param {string} findingId
   * @param {Object} updates
   * @returns {Object|null}
   */
  updateFinding(findingId, updates = {}) {
    const finding = findingsStore.get(findingId);
    if (!finding) return null;

    const updated = {
      ...finding,
      ...updates,
      updatedAt: new Date().toISOString()
    };

    findingsStore.set(findingId, updated);
    return updated;
  }

  /**
   * Clear stores (test helper)
   */
  clearStores() {
    scansStore.clear();
    findingsStore.clear();
  }
}

// Singleton orchestrator instance
const scanOrchestrator = new ScanOrchestrator();

module.exports = {
  ScanOrchestrator,
  scanOrchestrator,
  generateFingerprint,
  recordEvent,
  sanitizeErrorMessage
};
