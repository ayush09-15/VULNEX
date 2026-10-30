const { describe, it } = require('node:test');
const assert = require('node:assert');
const {
  validateScan,
  validateCreateScan,
  validateFinding,
  validateFindings,
  validatePatch,
  validateApplyPatch,
  validateVerification,
  validateInvestigation,
  validateAIInvestigationOutput,
  validateRepository,
  validateRegisterRepository,
  validateAuditEvent,
  ScanSchema,
  FindingSchema,
  PatchSchema,
  VerificationSchema,
  InvestigationSchema,
  AIInvestigationOutputSchema,
  ApplyPatchSchema,
  RegisterRepositorySchema,
  SafeRelativeFilePath,
  SafeHttpsRepoUrl
} = require('../src/validators/canonical.schema');

describe('Canonical Schemas & Contracts Validation (Task 04)', () => {
  // --------------------------------------------------------------------------
  // 1. Scan Entity & CreateScan Schemas
  // --------------------------------------------------------------------------
  describe('Scan Schemas', () => {
    it('should validate a valid Scan entity', () => {
      const validScan = {
        id: 'scan_01JAZZ80002',
        repositoryId: 'repo_01JAZZ80001',
        ref: 'main',
        status: 'SCANNING',
        stage: 'SCANNING',
        toolVersions: { semgrep: '1.70.0', 'npm-audit': '10.2.0' },
        startedAt: '2026-10-31T03:00:00.000Z',
        completedAt: null,
        errorCode: null,
        workspaceId: 'ws_01JAZZ80002',
        createdAt: '2026-10-31T03:00:00.000Z'
      };

      const result = validateScan(validScan);
      assert.strictEqual(result.success, true);
    });

    it('should reject a Scan with an invalid status', () => {
      const invalidScan = {
        id: 'scan_01JAZZ80002',
        repositoryId: 'repo_01JAZZ80001',
        status: 'UNKNOWN_STATUS',
        stage: 'UNKNOWN_STATUS',
        createdAt: '2026-10-31T03:00:00.000Z'
      };

      const result = validateScan(invalidScan);
      assert.strictEqual(result.success, false);
      assert.ok(result.error.issues.some((i) => i.path.includes('status')));
    });

    it('should validate a valid CreateScan request', () => {
      const validCreate = {
        repositoryId: 'repo_01JAZZ80001',
        ref: 'feature/auth',
        scanners: ['semgrep', 'npm-audit']
      };

      const result = validateCreateScan(validCreate);
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.data.ref, 'feature/auth');
    });

    it('should default ref to main if omitted in CreateScan', () => {
      const minimalCreate = { repositoryId: 'repo_01JAZZ80001' };
      const result = validateCreateScan(minimalCreate);
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.data.ref, 'main');
    });
  });

  // --------------------------------------------------------------------------
  // 2. Finding Schema & Path Traversal Guards
  // --------------------------------------------------------------------------
  describe('Finding Schema', () => {
    it('should validate a complete valid finding', () => {
      const validFinding = {
        id: 'find_01JAZZ80003',
        scanId: 'scan_01JAZZ80002',
        scanner: 'semgrep',
        ruleId: 'javascript.express.security.audit.sqli',
        title: 'Potential SQL Injection in User Lookup',
        category: 'SQL_INJECTION',
        severity: 'HIGH',
        confidence: 'MEDIUM',
        filePath: 'src/routes/user.js',
        startLine: 24,
        endLine: 26,
        message: 'Untrusted user query parameter concatenated into SQL string',
        evidence: 'db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)',
        fingerprint: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        status: 'DETECTED',
        createdAt: '2026-10-31T03:15:00.000Z'
      };

      const result = validateFinding(validFinding);
      assert.strictEqual(result.success, true);
    });

    it('should reject a finding where endLine is less than startLine', () => {
      const invertedLines = {
        id: 'find_01JAZZ80003',
        scanId: 'scan_01JAZZ80002',
        scanner: 'semgrep',
        ruleId: 'rule.test',
        title: 'Invalid line order',
        category: 'OTHER',
        severity: 'LOW',
        confidence: 'LOW',
        filePath: 'src/test.js',
        startLine: 50,
        endLine: 40,
        message: 'invalid lines',
        fingerprint: 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234',
        createdAt: '2026-10-31T03:15:00.000Z'
      };

      const result = validateFinding(invertedLines);
      assert.strictEqual(result.success, false);
      assert.ok(result.error.issues.some((i) => i.message.includes('endLine must be greater than or equal to startLine')));
    });

    it('should reject absolute paths in filePath', () => {
      const absolutePathResult = SafeRelativeFilePath.safeParse('/etc/passwd');
      assert.strictEqual(absolutePathResult.success, false);

      const winAbsolutePath = SafeRelativeFilePath.safeParse('C:\\Windows\\System32\\drivers');
      assert.strictEqual(winAbsolutePath.success, false);
    });

    it('should reject path traversal in filePath', () => {
      const traversalResult = SafeRelativeFilePath.safeParse('../../config/database.js');
      assert.strictEqual(traversalResult.success, false);
      assert.ok(traversalResult.error.issues.some((i) => i.message.includes('path traversal sequences')));
    });
  });

  // --------------------------------------------------------------------------
  // 3. Patch Schema & Human Approval Gate
  // --------------------------------------------------------------------------
  describe('Patch Schema & Human Approval Gate', () => {
    it('should validate a valid Patch entity', () => {
      const validPatch = {
        id: 'patch_01JAZZ80005',
        findingId: 'find_01JAZZ80003',
        diff: '--- a/src/routes/user.js\n+++ b/src/routes/user.js\n@@ -24,1 +24,1 @@\n-db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)\n+db.query("SELECT * FROM users WHERE id = $1", [req.query.id])\n',
        rationale: 'Replace raw string interpolation with parameterized queries to prevent SQL injection.',
        status: 'GENERATED',
        changedFiles: ['src/routes/user.js'],
        appliedWorkspaceId: null,
        createdAt: '2026-10-31T03:30:00.000Z'
      };

      const result = validatePatch(validPatch);
      assert.strictEqual(result.success, true);
    });

    it('should reject patch with empty changedFiles array', () => {
      const noFilesPatch = {
        id: 'patch_01JAZZ80005',
        findingId: 'find_01JAZZ80003',
        diff: 'diff content',
        rationale: 'some rationale',
        changedFiles: [],
        createdAt: '2026-10-31T03:30:00.000Z'
      };

      const result = validatePatch(noFilesPatch);
      assert.strictEqual(result.success, false);
    });

    it('should enforce explicit human approval (approved: true) on ApplyPatchSchema', () => {
      const approvedResult = validateApplyPatch({ approved: true, approverComments: 'Reviewed and safe to apply' });
      assert.strictEqual(approvedResult.success, true);

      const falseApproved = validateApplyPatch({ approved: false });
      assert.strictEqual(falseApproved.success, false);

      const missingApproved = validateApplyPatch({});
      assert.strictEqual(missingApproved.success, false);
    });
  });

  // --------------------------------------------------------------------------
  // 4. Verification Schema
  // --------------------------------------------------------------------------
  describe('Verification Schema', () => {
    it('should validate a complete Verification record', () => {
      const validVerification = {
        id: 'ver_01JAZZ80006',
        patchId: 'patch_01JAZZ80005',
        testResults: {
          syntaxValid: true,
          testsExecuted: 8,
          passed: 8,
          failed: 0,
          durationMs: 342,
          exitCode: 0,
          output: '8 tests passed'
        },
        scannerResults: {
          originalFindingResolved: true,
          ruleId: 'javascript.express.security.audit.sqli',
          newFindingsCount: 0,
          newFindings: [],
          exitCode: 0
        },
        beforeAfterComparison: {
          astDifferenceVerified: true,
          regressionDetected: false,
          comparisonOutcome: 'RESOLVED'
        },
        status: 'PASSED',
        logsReference: 'logs/ver_01JAZZ80006.log',
        createdAt: '2026-10-31T03:45:00.000Z'
      };

      const result = validateVerification(validVerification);
      assert.strictEqual(result.success, true);
    });

    it('should reject verification with negative test counts', () => {
      const invalidVerification = {
        id: 'ver_01JAZZ80006',
        patchId: 'patch_01JAZZ80005',
        testResults: {
          syntaxValid: true,
          testsExecuted: -1,
          passed: 0,
          failed: 0
        },
        scannerResults: {
          originalFindingResolved: false,
          ruleId: 'test.rule'
        },
        beforeAfterComparison: {
          comparisonOutcome: 'STILL_DETECTED'
        },
        status: 'FAILED',
        createdAt: '2026-10-31T03:45:00.000Z'
      };

      const result = validateVerification(invalidVerification);
      assert.strictEqual(result.success, false);
    });
  });

  // --------------------------------------------------------------------------
  // 5. AI Investigation & Output Schemas
  // --------------------------------------------------------------------------
  describe('AI Investigation Schemas', () => {
    it('should validate structured AI output per Bible Section 8.4', () => {
      const validAIOutput = {
        assessment: 'LIKELY_TRUE',
        severity: 'HIGH',
        summary: 'Direct user input is interpolated into database query without parameterization.',
        evidence: [
          'req.query.id directly passed to template literal',
          'No sanitization or parameter binding detected'
        ],
        preconditions: [
          'Endpoint is accessible to unauthenticated callers',
          'Database driver supports parameterized queries'
        ],
        potentialImpact: 'Arbitrary database read/write access via boolean or time-based injection.',
        recommendedFix: 'Convert the query to use parameterized positional variables ($1).',
        confidence: 'HIGH',
        limitations: [
          'Static analysis only; database dialect was inferred from npm dependencies.'
        ]
      };

      const result = validateAIInvestigationOutput(validAIOutput);
      assert.strictEqual(result.success, true);
    });

    it('should reject AI output with missing mandatory reasoning fields', () => {
      const incompleteAIOutput = {
        assessment: 'LIKELY_TRUE',
        severity: 'HIGH',
        summary: 'Incomplete output missing fix and impact'
      };

      const result = validateAIInvestigationOutput(incompleteAIOutput);
      assert.strictEqual(result.success, false);
    });

    it('should validate an Investigation database entity', () => {
      const validInvEntity = {
        id: 'inv_01JAZZ80004',
        findingId: 'find_01JAZZ80003',
        model: 'gemini-1.5-pro',
        promptVersion: 'v1.0.0',
        assessment: 'LIKELY_TRUE',
        explanation: 'Detailed root-cause analysis text...',
        impact: 'High security risk',
        recommendation: 'Use parameterized queries',
        confidence: 0.95,
        limitations: ['Static heuristic only'],
        createdAt: '2026-10-31T03:25:00.000Z'
      };

      const result = validateInvestigation(validInvEntity);
      assert.strictEqual(result.success, true);
    });
  });

  // --------------------------------------------------------------------------
  // 6. Repository Schema & SSRF Protection
  // --------------------------------------------------------------------------
  describe('Repository Schema & SSRF Protection', () => {
    it('should accept valid public HTTPS GitHub repository URLs', () => {
      const validReg = {
        sourceType: 'GITHUB',
        displayName: 'express-sample',
        sourceUrl: 'https://github.com/org/repo',
        defaultRef: 'main'
      };

      const result = validateRegisterRepository(validReg);
      assert.strictEqual(result.success, true);
    });

    it('should reject local or private IP addresses (SSRF mitigation)', () => {
      const privateUrls = [
        'https://localhost/repo.git',
        'https://127.0.0.1/repo.git',
        'https://10.0.0.1/internal.git',
        'https://192.168.1.1/secret.git',
        'https://169.254.169.254/latest/meta-data'
      ];

      for (const url of privateUrls) {
        const result = SafeHttpsRepoUrl.safeParse(url);
        assert.strictEqual(result.success, false, `Expected ${url} to be rejected by SSRF guard`);
      }
    });

    it('should require sourceUrl when sourceType is GITHUB', () => {
      const missingUrl = {
        sourceType: 'GITHUB',
        displayName: 'missing-url-repo'
      };

      const result = validateRegisterRepository(missingUrl);
      assert.strictEqual(result.success, false);
      assert.ok(result.error.issues.some((i) => i.path.includes('sourceUrl')));
    });

    it('should allow omitting sourceUrl when sourceType is ZIP_UPLOAD', () => {
      const zipReg = {
        sourceType: 'ZIP_UPLOAD',
        displayName: 'uploaded-source'
      };

      const result = validateRegisterRepository(zipReg);
      assert.strictEqual(result.success, true);
    });
  });

  // --------------------------------------------------------------------------
  // 7. Audit Event Schema
  // --------------------------------------------------------------------------
  describe('AuditEvent Schema', () => {
    it('should validate an immutable AuditEvent record', () => {
      const validEvent = {
        id: 'aud_01JAZZ80007',
        actor: 'user_ayush',
        action: 'PATCH_APPLY_APPROVED',
        entityId: 'patch_01JAZZ80005',
        timestamp: '2026-10-31T03:35:00.000Z',
        outcome: 'SUCCESS',
        requestId: 'req_01HZX87K79W9E2V6G9C5Q3A1B2'
      };

      const result = validateAuditEvent(validEvent);
      assert.strictEqual(result.success, true);
    });
  });
});
