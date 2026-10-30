const { z } = require('zod');

// Valid Severity Values per VULNEX Canonical Data Model
const SeverityEnum = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

// Valid Confidence Values
const ConfidenceEnum = z.enum(['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);

// Valid Finding Remediate Statuses
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

// Valid Scanner Execution Statuses
const ScanStatusEnum = z.enum(['COMPLETED', 'PARTIAL', 'FAILED']);

// Safe relative file path: no leading slashes, no '..' traversal segments
const SafeRelativeFilePath = z.string()
  .min(1, 'File path cannot be empty')
  .refine(
    (p) => !p.startsWith('/') && !p.startsWith('\\') && !/^[A-Za-z]:[\\/]/.test(p),
    { message: 'File path must be relative to the scan workspace, not an absolute host path' }
  )
  .refine(
    (p) => !p.split(/[/\\]/).includes('..'),
    { message: 'File path cannot contain path traversal sequences ("..")' }
  );

// Raw Semgrep CLI Output Schemas
const SemgrepPositionSchema = z.object({
  line: z.number().int().min(1),
  col: z.number().int().min(1),
  offset: z.number().optional()
});

const SemgrepExtraSchema = z.object({
  message: z.string().default(''),
  metadata: z.record(z.any()).optional().default({}),
  severity: z.string().optional().default('INFO'),
  lines: z.string().optional().default(''),
  fingerprint: z.string().optional()
}).passthrough();

const SemgrepResultItemSchema = z.object({
  check_id: z.string().min(1, 'check_id is required'),
  path: z.string().min(1, 'path is required'),
  start: SemgrepPositionSchema,
  end: SemgrepPositionSchema,
  extra: SemgrepExtraSchema
}).passthrough();

const SemgrepRawOutputSchema = z.object({
  version: z.string().nullable().optional(),
  results: z.array(SemgrepResultItemSchema).default([]),
  errors: z.array(z.any()).optional().default([]),
  paths: z.object({
    scanned: z.array(z.string()).optional(),
    skipped: z.array(z.any()).optional()
  }).optional(),
  time: z.record(z.any()).optional(),
  skipped_rules: z.array(z.any()).optional()
}).passthrough();

// Normalized VULNEX Finding Schema
const NormalizedFindingSchema = z.object({
  id: z.string().min(1, 'Finding unique ID required'),
  scanner: z.literal('semgrep'),
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

// Provenance Entry for an Individual Finding
const RuleFindingProvenanceSchema = z.object({
  findingId: z.string(),
  ruleId: z.string(),
  filePath: SafeRelativeFilePath,
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1)
});

// Semgrep Scanner Execution Provenance Schema
const SemgrepProvenanceSchema = z.object({
  scanner: z.literal('semgrep'),
  version: z.string().nullable(),
  config: z.string().min(1),
  scanId: z.string().min(1),
  timestamp: z.string().datetime(),
  durationMs: z.number().nonnegative(),
  exitCode: z.number().nullable(),
  status: ScanStatusEnum,
  findingsCount: z.number().int().nonnegative(),
  errors: z.array(z.union([z.string(), z.record(z.any())])).default([]),
  ruleFindings: z.array(RuleFindingProvenanceSchema).default([])
});

/**
 * Validation helpers with safe error handling
 */
function validateRawSemgrepOutput(data) {
  return SemgrepRawOutputSchema.safeParse(data);
}

function validateNormalizedFinding(data) {
  return NormalizedFindingSchema.safeParse(data);
}

function validateNormalizedFindings(data) {
  return z.array(NormalizedFindingSchema).safeParse(data);
}

function validateProvenance(data) {
  return SemgrepProvenanceSchema.safeParse(data);
}

module.exports = {
  SeverityEnum,
  ConfidenceEnum,
  FindingStatusEnum,
  ScanStatusEnum,
  SafeRelativeFilePath,
  SemgrepRawOutputSchema,
  NormalizedFindingSchema,
  SemgrepProvenanceSchema,
  RuleFindingProvenanceSchema,
  validateRawSemgrepOutput,
  validateNormalizedFinding,
  validateNormalizedFindings,
  validateProvenance
};
