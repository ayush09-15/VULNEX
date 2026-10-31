const { z } = require('zod');
const { isPrivateOrBlockedHost } = require('../utils/ssrfGuard');

/**
 * ============================================================================
 * VULNEX Canonical Data Contracts & Schemas
 * Source of truth: VULNEX Master Antigravity Execution Bible & docs/DATA_MODELS.md
 * ============================================================================
 */

// ----------------------------------------------------------------------------
// 1. Core Enumerations & Safe Types
// ----------------------------------------------------------------------------

const SeverityEnum = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

const ConfidenceEnum = z.enum(['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);

const AIConfidenceEnum = z.enum(['HIGH', 'MEDIUM', 'LOW']);

const AIAssessmentEnum = z.enum(['LIKELY_TRUE', 'UNCERTAIN', 'LIKELY_FALSE']);

const ScanStatusEnum = z.enum([
  'QUEUED',
  'PREPARING',
  'SCANNING',
  'NORMALIZING',
  'INVESTIGATING',
  'COMPLETED',
  'PARTIAL',
  'FAILED',
  'CANCELLED'
]);

const ScanStageEnum = ScanStatusEnum;

const FindingStatusEnum = z.enum([
  'DETECTED',
  'TRIAGED',
  'PATCH_PROPOSED',
  'PATCH_APPLIED',
  'VERIFIED',
  'REJECTED',
  'FAILED',
  'INCONCLUSIVE'
]);

const PatchStatusEnum = z.enum([
  'GENERATED',
  'VALIDATED',
  'APPLIED_TO_TEMP',
  'TESTING',
  'VERIFIED',
  'FAILED',
  'REJECTED',
  'INCONCLUSIVE'
]);

const VerificationStatusEnum = z.enum([
  'PASSED',
  'FAILED',
  'INCONCLUSIVE',
  'NOT_RUN',
  'PARTIAL'
]);

const SourceTypeEnum = z.enum(['GITHUB', 'ZIP_UPLOAD']);

const VulnerabilityCategoryEnum = z.enum([
  'SQL_INJECTION',
  'XSS',
  'HARDCODED_SECRET',
  'VULNERABLE_DEPENDENCY',
  'COMMAND_INJECTION',
  'PATH_TRAVERSAL',
  'INJECTION',
  'BROKEN_AUTH',
  'SENSITIVE_DATA_EXPOSURE',
  'SECURITY_MISCONFIG',
  'OTHER'
]);

// Path traversal guard: no absolute paths, no drive letters, no '..' segments, no null bytes, no encoded escapes
const SafeRelativeFilePath = z.string()
  .min(1, 'File path cannot be empty')
  .refine((p) => !p.includes('\0'), { message: 'File path cannot contain null bytes' })
  .refine(
    (p) => !p.startsWith('/') && !p.startsWith('\\') && !/^[A-Za-z]:[\\/]/.test(p),
    { message: 'File path must be relative to the scan workspace, not an absolute host path' }
  )
  .refine(
    (p) => {
      let decoded = p;
      try {
        while (decoded.includes('%')) {
          const next = decodeURIComponent(decoded);
          if (next === decoded) break;
          decoded = next;
        }
      } catch {
        return false;
      }
      if (decoded.includes('\0')) return false;
      if (decoded.startsWith('/') || decoded.startsWith('\\') || /^[A-Za-z]:[\\/]/.test(decoded)) {
        return false;
      }
      const parts = decoded.split(/[/\\]/);
      return !parts.includes('..') && !parts.some((s) => s === '..' || /^\.\.[/\\]/.test(s));
    },
    { message: 'File path cannot contain path traversal sequences ("..") or encoded escapes' }
  )
  .refine(
    (p) => !p.split(/[/\\]/).includes('..'),
    { message: 'File path cannot contain path traversal sequences ("..")' }
  );

// Safe HTTPS repository URL validator (SSRF protection against private IPs)
const SafeHttpsRepoUrl = z.string()
  .url('Must be a valid URL')
  .refine((u) => u.startsWith('https://'), { message: 'Only secure HTTPS repository URLs are allowed' })
  .refine(
    (u) => {
      try {
        const parsed = new URL(u);
        if (parsed.username || parsed.password) return false;
        const host = parsed.hostname.toLowerCase();
        if (isPrivateOrBlockedHost(host)) return false;
        return true;
      } catch {
        return false;
      }
    },
    { message: 'Target URL resolves to a prohibited local or private address space (SSRF protection)' }
  );

// ----------------------------------------------------------------------------
// 2. Repository Schemas
// ----------------------------------------------------------------------------

const RepositorySchema = z.object({
  id: z.string().min(1, 'Repository ID is required'),
  sourceType: SourceTypeEnum,
  displayName: z.string().min(1).max(100),
  sanitizedSourceUrl: z.string().url().nullable().optional(),
  defaultRef: z.string().min(1).default('main'),
  createdAt: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' }),
  ownerId: z.string().nullable().optional()
});

const RegisterRepositorySchema = z.object({
  sourceType: SourceTypeEnum,
  displayName: z.string().min(1, 'Display name is required').max(100),
  sourceUrl: SafeHttpsRepoUrl.optional().nullable(),
  defaultRef: z.string().optional().default('main')
}).refine(
  (data) => {
    if (data.sourceType === 'GITHUB') {
      return Boolean(data.sourceUrl);
    }
    return true;
  },
  {
    message: 'sourceUrl is required when sourceType is GITHUB',
    path: ['sourceUrl']
  }
);

// ----------------------------------------------------------------------------
// 3. Scan Schemas
// ----------------------------------------------------------------------------

const CreateScanSchema = z.object({
  repositoryId: z.string().min(1, 'repositoryId is required'),
  ref: z.string().optional().default('main'),
  scanners: z.array(z.string()).optional()
});

const ScanEventSchema = z.object({
  stage: ScanStageEnum,
  status: z.enum(['IN_PROGRESS', 'SUCCESS', 'FAILED', 'SKIPPED']),
  timestamp: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' }),
  message: z.string().min(1),
  details: z.record(z.any()).optional()
});

const ScanSchema = z.object({
  id: z.string().min(1, 'Scan ID is required'),
  repositoryId: z.string().min(1, 'repositoryId is required'),
  ref: z.string().min(1).default('main'),
  status: ScanStatusEnum,
  stage: ScanStageEnum,
  toolVersions: z.record(z.string()).default({}),
  startedAt: z.string().datetime().nullable().optional(),
  completedAt: z.string().datetime().nullable().optional(),
  errorCode: z.string().nullable().optional(),
  workspaceId: z.string().nullable().optional(),
  createdAt: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' })
});

// ----------------------------------------------------------------------------
// 4. Finding Schemas
// ----------------------------------------------------------------------------

const FindingSchema = z.object({
  id: z.string().min(1, 'Finding unique ID required'),
  scanId: z.string().min(1, 'scanId required'),
  scanner: z.string().min(1, 'Scanner name required'),
  ruleId: z.string().min(1, 'Rule identifier required'),
  title: z.string().min(1, 'Title required'),
  category: z.string().min(1, 'Category required'),
  severity: SeverityEnum,
  confidence: ConfidenceEnum,
  filePath: SafeRelativeFilePath,
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
  message: z.string().default(''),
  evidence: z.union([z.string(), z.record(z.any())]).default(''),
  fingerprint: z.string().min(1, 'Stable fingerprint required'),
  status: FindingStatusEnum.default('DETECTED'),
  createdAt: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' })
}).refine(
  (data) => data.endLine >= data.startLine,
  { message: 'endLine must be greater than or equal to startLine', path: ['endLine'] }
);

// ----------------------------------------------------------------------------
// 5. Investigation Schemas
// ----------------------------------------------------------------------------

// Structured LLM model output schema (Bible Section 8.4)
const AIInvestigationOutputSchema = z.object({
  assessment: AIAssessmentEnum,
  severity: SeverityEnum,
  summary: z.string().min(1, 'Summary is required'),
  evidence: z.array(z.string()).default([]),
  preconditions: z.array(z.string()).default([]),
  potentialImpact: z.string().min(1, 'Potential impact is required'),
  recommendedFix: z.string().min(1, 'Recommended fix is required'),
  confidence: AIConfidenceEnum,
  limitations: z.array(z.string()).default([])
});

// Stored Investigation entity schema (Bible Section 4.9 & DATA_MODELS.md 2.4)
const InvestigationSchema = z.object({
  id: z.string().min(1, 'Investigation ID is required'),
  findingId: z.string().min(1, 'findingId is required'),
  model: z.string().min(1, 'Model identifier is required'),
  promptVersion: z.string().min(1, 'promptVersion is required'),
  assessment: z.string().min(1, 'assessment is required'),
  explanation: z.string().min(1, 'explanation is required'),
  impact: z.string().min(1, 'impact is required'),
  recommendation: z.string().min(1, 'recommendation is required'),
  confidence: z.union([
    z.number().min(0.0).max(1.0),
    AIConfidenceEnum
  ]),
  limitations: z.array(z.string()).default([]),
  createdAt: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' })
});

// ----------------------------------------------------------------------------
// 6. Patch Schemas
// ----------------------------------------------------------------------------

const CreatePatchProposalSchema = z.object({
  findingId: z.string().min(1, 'findingId is required'),
  diff: z.string().min(1, 'diff content is required'),
  rationale: z.string().min(1, 'rationale is required'),
  changedFiles: z.array(SafeRelativeFilePath).min(1, 'At least one changed file is required')
});

const PatchSchema = z.object({
  id: z.string().min(1, 'Patch ID is required'),
  findingId: z.string().min(1, 'findingId is required'),
  diff: z.string().min(1, 'diff is required'),
  rationale: z.string().min(1, 'rationale is required'),
  status: PatchStatusEnum.default('GENERATED'),
  changedFiles: z.array(SafeRelativeFilePath).min(1, 'At least one changed file is required'),
  appliedWorkspaceId: z.string().nullable().optional(),
  createdAt: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' })
});

const ApplyPatchSchema = z.object({
  approved: z.literal(true, {
    errorMap: () => ({ message: 'Explicit human approval (approved: true) is required to apply patches.' })
  }),
  approverComments: z.string().optional()
});

// ----------------------------------------------------------------------------
// 7. Verification Schemas
// ----------------------------------------------------------------------------

const VerificationTestResultsSchema = z.object({
  syntaxValid: z.boolean(),
  testsExecuted: z.number().int().nonnegative(),
  passed: z.number().int().nonnegative(),
  failed: z.number().int().nonnegative(),
  durationMs: z.number().nonnegative().optional(),
  exitCode: z.number().int().nullable().optional(),
  output: z.string().optional()
});

const VerificationScannerResultsSchema = z.object({
  originalFindingResolved: z.boolean(),
  ruleId: z.string().min(1),
  newFindingsCount: z.number().int().nonnegative().default(0),
  newFindings: z.array(z.any()).default([]),
  exitCode: z.number().int().nullable().optional(),
  rawOutput: z.string().optional()
});

const VerificationComparisonSchema = z.object({
  astDifferenceVerified: z.boolean().default(false),
  regressionDetected: z.boolean().default(false),
  matchedFingerprint: z.string().optional(),
  comparisonOutcome: z.enum(['RESOLVED', 'STILL_DETECTED', 'AMBIGUOUS', 'INTRODUCED_NEW_DEFECT', 'REGRESSION_DETECTED']).default('RESOLVED')
});

const VerificationSchema = z.object({
  id: z.string().min(1, 'Verification ID is required'),
  patchId: z.string().min(1, 'patchId is required'),
  testResults: VerificationTestResultsSchema,
  scannerResults: VerificationScannerResultsSchema,
  beforeAfterComparison: VerificationComparisonSchema,
  status: VerificationStatusEnum,
  logsReference: z.string().nullable().optional(),
  createdAt: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' })
});

// ----------------------------------------------------------------------------
// 8. Audit Event & API Envelope Schemas
// ----------------------------------------------------------------------------

const AuditEventSchema = z.object({
  id: z.string().min(1, 'Audit ID is required'),
  actor: z.string().min(1, 'Actor is required'),
  action: z.string().min(1, 'Action is required'),
  entityId: z.string().min(1, 'entityId is required'),
  timestamp: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' }),
  outcome: z.enum(['SUCCESS', 'FAILURE', 'DENIED']),
  requestId: z.string().min(1, 'requestId is required')
});

const ApiSuccessEnvelopeSchema = z.object({
  success: z.literal(true),
  data: z.any(),
  requestId: z.string().min(1)
});

const ApiErrorEnvelopeSchema = z.object({
  success: z.literal(false),
  error: z.object({
    code: z.string().min(1),
    message: z.string().min(1),
    details: z.any().optional()
  }),
  requestId: z.string().min(1)
});

// ----------------------------------------------------------------------------
// 9. Validation Safe Parse Helpers
// ----------------------------------------------------------------------------

function validateScan(data) {
  return ScanSchema.safeParse(data);
}

function validateCreateScan(data) {
  return CreateScanSchema.safeParse(data);
}

function validateFinding(data) {
  return FindingSchema.safeParse(data);
}

function validateFindings(data) {
  return z.array(FindingSchema).safeParse(data);
}

function validateInvestigation(data) {
  return InvestigationSchema.safeParse(data);
}

function validateAIInvestigationOutput(data) {
  return AIInvestigationOutputSchema.safeParse(data);
}

function validatePatch(data) {
  return PatchSchema.safeParse(data);
}

function validateApplyPatch(data) {
  return ApplyPatchSchema.safeParse(data);
}

function validateVerification(data) {
  return VerificationSchema.safeParse(data);
}

function validateRepository(data) {
  return RepositorySchema.safeParse(data);
}

function validateRegisterRepository(data) {
  return RegisterRepositorySchema.safeParse(data);
}

function validateAuditEvent(data) {
  return AuditEventSchema.safeParse(data);
}

module.exports = {
  // Enums
  SeverityEnum,
  ConfidenceEnum,
  AIConfidenceEnum,
  AIAssessmentEnum,
  ScanStatusEnum,
  ScanStageEnum,
  FindingStatusEnum,
  PatchStatusEnum,
  VerificationStatusEnum,
  SourceTypeEnum,
  VulnerabilityCategoryEnum,

  // Path & URL types
  SafeRelativeFilePath,
  SafeHttpsRepoUrl,

  // Entity Schemas
  RepositorySchema,
  RegisterRepositorySchema,
  ScanSchema,
  CreateScanSchema,
  ScanEventSchema,
  FindingSchema,
  InvestigationSchema,
  AIInvestigationOutputSchema,
  CreatePatchProposalSchema,
  PatchSchema,
  ApplyPatchSchema,
  VerificationTestResultsSchema,
  VerificationScannerResultsSchema,
  VerificationComparisonSchema,
  VerificationSchema,
  AuditEventSchema,
  ApiSuccessEnvelopeSchema,
  ApiErrorEnvelopeSchema,

  // Validation Helpers
  validateScan,
  validateCreateScan,
  validateFinding,
  validateFindings,
  validateInvestigation,
  validateAIInvestigationOutput,
  validatePatch,
  validateApplyPatch,
  validateVerification,
  validateRepository,
  validateRegisterRepository,
  validateAuditEvent
};
