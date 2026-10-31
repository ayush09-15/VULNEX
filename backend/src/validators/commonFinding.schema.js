const { z } = require('zod');

/**
 * ============================================================================
 * VULNEX Common Finding Schema
 *
 * Defines the standard normalized contract for security findings across
 * all scanner engines (Semgrep, custom SAST patterns, linters, etc.).
 *
 * Required Normalized Fields:
 * - rule: Scanner rule identifier
 * - path: Normalized relative file path within workspace
 * - startLine: 1-indexed start line number (integer >= 1)
 * - endLine: 1-indexed end line number (integer >= startLine)
 * - message: Descriptive explanation of finding from scanner
 * - evidence: Code snippet or structured match context
 * - severity: VULNEX severity enum (CRITICAL, HIGH, MEDIUM, LOW, INFO)
 * - confidence: VULNEX confidence enum (HIGH, MEDIUM, LOW, UNKNOWN)
 * ============================================================================
 */

// Core Severities per VULNEX Convention
const SeverityEnum = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

// Core Confidence per VULNEX Convention
const ConfidenceEnum = z.enum(['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);

// Safe relative file path: no leading slashes, no drive letters, no '..' traversal
const SafeRelativePath = z.string()
  .min(1, 'File path cannot be empty')
  .refine(
    (p) => !p.startsWith('/') && !p.startsWith('\\') && !/^[A-Za-z]:[\\/]/.test(p),
    { message: 'File path must be relative to the scan workspace, not an absolute host path' }
  )
  .refine(
    (p) => !p.split(/[/\\]/).includes('..'),
    { message: 'File path cannot contain path traversal sequences ("..")' }
  );

// Common VULNEX Finding Schema
const CommonFindingSchema = z.object({
  // Required Normalized Fields
  rule: z.string().min(1, 'Rule ID is required'),
  path: SafeRelativePath,
  startLine: z.number().int().min(1, 'startLine must be an integer >= 1'),
  endLine: z.number().int().min(1, 'endLine must be an integer >= 1'),
  message: z.string().default(''),
  evidence: z.union([z.string(), z.record(z.any())]).default(''),
  severity: SeverityEnum,
  confidence: ConfidenceEnum,

  // Optional Scanner Metadata & Context
  metadata: z.record(z.any()).nullable().optional().default(null),
  scanner: z.string().optional(),
  title: z.string().optional(),
  category: z.string().optional(),
  startCol: z.number().int().nullable().optional(),
  endCol: z.number().int().nullable().optional(),
  codeSnippet: z.string().nullable().optional(),
  references: z.array(z.string()).optional().default([])
}).passthrough().refine(
  (data) => data.endLine >= data.startLine,
  { message: 'endLine must be greater than or equal to startLine', path: ['endLine'] }
);

/**
 * Validate a single finding against the Common Finding Schema
 * @param {Object} data Finding record
 * @returns {{ success: boolean, data?: Object, error?: z.ZodError }}
 */
function validateCommonFinding(data) {
  const result = CommonFindingSchema.safeParse(data);
  if (!result.success) {
    return { success: false, error: result.error, data: null };
  }
  return { success: true, data: result.data, error: null };
}

/**
 * Validate an array of findings against the Common Finding Schema
 * @param {Array<Object>} dataArray Array of finding records
 * @returns {{ success: boolean, data?: Array<Object>, error?: z.ZodError }}
 */
function validateCommonFindings(dataArray) {
  const ArraySchema = z.array(CommonFindingSchema);
  const result = ArraySchema.safeParse(dataArray);
  if (!result.success) {
    return { success: false, error: result.error, data: null };
  }
  return { success: true, data: result.data, error: null };
}

module.exports = {
  SeverityEnum,
  ConfidenceEnum,
  SafeRelativePath,
  CommonFindingSchema,
  validateCommonFinding,
  validateCommonFindings
};
