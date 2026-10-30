/**
 * VULNEX Evidence-Bounded AI Investigation Schema & Output Validator
 *
 * Implements:
 * - Master Antigravity Execution Bible Section 8.4 (Structured Investigation Output)
 * - Section 8.5 (Context Engineering & Bounds)
 * - Section 4.9 (Investigation Entity)
 * - Section 9.3 (Severity, Confidence, and Assessment Enums)
 * - Section 8.9 (Malformed AI JSON and Failure Handling)
 */

const { z } = require('zod');

// ----------------------------------------------------------------------------
// Canonical Enums & Constants
// ----------------------------------------------------------------------------

const AI_ASSESSMENTS = Object.freeze({
  LIKELY_TRUE: 'LIKELY_TRUE',
  UNCERTAIN: 'UNCERTAIN',
  LIKELY_FALSE: 'LIKELY_FALSE'
});

const AI_CONFIDENCES = Object.freeze({
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH'
});

const SEVERITIES = Object.freeze({
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO'
});

// Zod Enums
const AIAssessmentEnum = z.enum([
  AI_ASSESSMENTS.LIKELY_TRUE,
  AI_ASSESSMENTS.UNCERTAIN,
  AI_ASSESSMENTS.LIKELY_FALSE
], {
  errorMap: () => ({
    message: "Assessment must be one of 'LIKELY_TRUE', 'UNCERTAIN', or 'LIKELY_FALSE'"
  })
});

const AIConfidenceEnum = z.enum([
  AI_CONFIDENCES.LOW,
  AI_CONFIDENCES.MEDIUM,
  AI_CONFIDENCES.HIGH
], {
  errorMap: () => ({
    message: "Confidence must be one of 'LOW', 'MEDIUM', or 'HIGH'"
  })
});

const SeverityEnum = z.enum([
  SEVERITIES.CRITICAL,
  SEVERITIES.HIGH,
  SEVERITIES.MEDIUM,
  SEVERITIES.LOW,
  SEVERITIES.INFO
], {
  errorMap: () => ({
    message: "Severity must be one of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'INFO'"
  })
});

// ----------------------------------------------------------------------------
// Bounds & Constraints (Protection against DoS / Token runaway)
// ----------------------------------------------------------------------------

const BOUNDS = Object.freeze({
  MAX_SUMMARY_LENGTH: 5000,
  MAX_IMPACT_LENGTH: 5000,
  MAX_RECOMMENDATION_LENGTH: 5000,
  MAX_EVIDENCE_ITEMS: 50,
  MAX_EVIDENCE_ITEM_LENGTH: 4000,
  MAX_LIMITATIONS_ITEMS: 50,
  MAX_LIMITATION_ITEM_LENGTH: 2000,
  MAX_PRECONDITIONS_ITEMS: 50,
  MAX_PRECONDITION_ITEM_LENGTH: 2000
});

// ----------------------------------------------------------------------------
// 1. Structured LLM Model Output Schema (Bible Section 8.4)
// ----------------------------------------------------------------------------

const AIInvestigationOutputSchema = z.object({
  assessment: AIAssessmentEnum,
  severity: SeverityEnum,
  summary: z
    .string({ required_error: 'Summary is required' })
    .trim()
    .min(1, 'Summary cannot be empty')
    .max(BOUNDS.MAX_SUMMARY_LENGTH, `Summary exceeds maximum length of ${BOUNDS.MAX_SUMMARY_LENGTH} characters`),
  evidence: z
    .array(
      z.string({ invalid_type_error: 'Evidence items must be strings' })
        .trim()
        .min(1, 'Evidence item cannot be empty')
        .max(BOUNDS.MAX_EVIDENCE_ITEM_LENGTH, 'Evidence item exceeds max length')
    )
    .max(BOUNDS.MAX_EVIDENCE_ITEMS, `Evidence cannot exceed ${BOUNDS.MAX_EVIDENCE_ITEMS} items`)
    .default([]),
  preconditions: z
    .array(
      z.string({ invalid_type_error: 'Precondition items must be strings' })
        .trim()
        .min(1, 'Precondition item cannot be empty')
        .max(BOUNDS.MAX_PRECONDITION_ITEM_LENGTH, 'Precondition item exceeds max length')
    )
    .max(BOUNDS.MAX_PRECONDITIONS_ITEMS, `Preconditions cannot exceed ${BOUNDS.MAX_PRECONDITIONS_ITEMS} items`)
    .default([]),
  potentialImpact: z
    .string({ required_error: 'Potential impact is required' })
    .trim()
    .min(1, 'Potential impact cannot be empty')
    .max(BOUNDS.MAX_IMPACT_LENGTH, `Potential impact exceeds maximum length of ${BOUNDS.MAX_IMPACT_LENGTH} characters`),
  recommendedFix: z
    .string({ required_error: 'Recommended fix is required' })
    .trim()
    .min(1, 'Recommended fix cannot be empty')
    .max(BOUNDS.MAX_RECOMMENDATION_LENGTH, `Recommended fix exceeds maximum length of ${BOUNDS.MAX_RECOMMENDATION_LENGTH} characters`),
  confidence: AIConfidenceEnum,
  limitations: z
    .array(
      z.string({ invalid_type_error: 'Limitation items must be strings' })
        .trim()
        .min(1, 'Limitation item cannot be empty')
        .max(BOUNDS.MAX_LIMITATION_ITEM_LENGTH, 'Limitation item exceeds max length')
    )
    .max(BOUNDS.MAX_LIMITATIONS_ITEMS, `Limitations cannot exceed ${BOUNDS.MAX_LIMITATIONS_ITEMS} items`)
    .default([])
}).strict();

// ----------------------------------------------------------------------------
// 2. Stored Investigation Entity Schema (Bible Section 4.9 & DATA_MODELS.md 2.4)
// ----------------------------------------------------------------------------

const InvestigationEntitySchema = z.object({
  id: z.string().min(1, 'Investigation ID is required'),
  findingId: z.string().min(1, 'findingId is required'),
  model: z.string().min(1, 'Model identifier is required'),
  promptVersion: z.string().min(1, 'promptVersion is required'),
  assessment: AIAssessmentEnum,
  explanation: z.string().min(1, 'Explanation is required'),
  impact: z.string().min(1, 'Impact is required'),
  recommendation: z.string().min(1, 'Recommendation is required'),
  confidence: z.union([
    z.number().min(0.0).max(1.0),
    AIConfidenceEnum
  ]),
  evidence: z.array(z.string()).default([]),
  preconditions: z.array(z.string()).default([]),
  limitations: z.array(z.string()).default([]),
  createdAt: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' })
});

// Alias for backward compatibility
const InvestigationSchema = InvestigationEntitySchema;

// ----------------------------------------------------------------------------
// Helper: Safe JSON Extractor (strips markdown code blocks and wrappers)
// ----------------------------------------------------------------------------

/**
 * Extracts and cleans JSON string from raw LLM output.
 * Handles:
 * - ```json ... ```
 * - ``` ... ```
 * - Surrounding conversational preamble / epilogue
 * - Direct JSON string or object
 *
 * @param {string|object} raw
 * @returns {string} Cleaned JSON string
 */
function extractJsonString(raw) {
  if (raw === null || raw === undefined) {
    return '';
  }
  if (typeof raw === 'object') {
    return JSON.stringify(raw);
  }
  if (typeof raw !== 'string') {
    return '';
  }

  const trimmed = raw.trim();
  if (!trimmed) {
    return '';
  }

  // Look for markdown fenced code blocks: ```json ... ``` or ``` ... ```
  const codeBlockRegex = /```(?:json)?\s*([\s\S]*?)\s*```/i;
  const match = codeBlockRegex.exec(trimmed);
  if (match && match[1]) {
    return match[1].trim();
  }

  // Find outermost JSON object braces { ... } if preamble/epilogue exists
  const firstBrace = trimmed.indexOf('{');
  const lastBrace = trimmed.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
    return trimmed.slice(firstBrace, lastBrace + 1).trim();
  }

  return trimmed;
}

// ----------------------------------------------------------------------------
// Helper: Parser & Validator
// ----------------------------------------------------------------------------

/**
 * Safely parses and validates AI model output against the evidence-bounded schema.
 * Never throws uncaught exceptions.
 *
 * @param {string|object} rawInput - Raw LLM string or parsed object
 * @returns {{ success: boolean, data?: object, error?: { code: string, message: string, details: any[] } }}
 */
function parseAndValidateAIInvestigation(rawInput) {
  if (rawInput === null || rawInput === undefined || rawInput === '') {
    return {
      success: false,
      error: {
        code: 'EMPTY_AI_OUTPUT',
        message: 'AI output is empty or undefined',
        details: []
      }
    };
  }

  let parsed;
  if (typeof rawInput === 'object') {
    parsed = rawInput;
  } else {
    const jsonStr = extractJsonString(rawInput);
    if (!jsonStr) {
      return {
        success: false,
        error: {
          code: 'MALFORMED_AI_OUTPUT',
          message: 'Could not extract JSON content from AI output',
          details: []
        }
      };
    }
    try {
      parsed = JSON.parse(jsonStr);
    } catch (parseErr) {
      return {
        success: false,
        error: {
          code: 'MALFORMED_AI_JSON',
          message: `Failed to parse AI output as JSON: ${parseErr.message}`,
          details: [{ error: parseErr.message }]
        }
      };
    }
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return {
      success: false,
      error: {
        code: 'INVALID_AI_STRUCTURE',
        message: 'AI output must be a JSON object',
        details: []
      }
    };
  }

  const result = AIInvestigationOutputSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues || [];
    return {
      success: false,
      error: {
        code: 'INVALID_INVESTIGATION_SCHEMA',
        message: 'AI output failed evidence-bounded schema validation',
        details: issues.map(err => ({
          path: Array.isArray(err.path) ? err.path.join('.') : String(err.path),
          message: err.message,
          code: err.code
        }))
      }
    };
  }

  return {
    success: true,
    data: result.data
  };
}

// ----------------------------------------------------------------------------
// Helper: Structured Fallback Constructor
// ----------------------------------------------------------------------------

/**
 * Creates an honest, schema-compliant fallback investigation when the model
 * is unavailable, times out, or fails validation.
 * Per Bible Section 8.5 & 8.9 (UNCERTAIN status with limitations).
 *
 * @param {object} params
 * @param {string} params.findingId
 * @param {string} [params.reason]
 * @param {string} [params.model]
 * @param {string} [params.promptVersion]
 * @param {object} [params.finding]
 * @returns {object} Canonical Investigation entity
 */
function createFallbackInvestigation({
  findingId,
  reason = 'AI investigation was unavailable or inconclusive.',
  model = 'vulnex-investigation-fallback-v1',
  promptVersion = '1.0.0',
  finding = null
}) {
  const limitationMsg = reason;
  return {
    id: `inv_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    findingId: findingId || (finding && finding.id) || 'finding_unknown',
    model,
    promptVersion,
    assessment: AI_ASSESSMENTS.UNCERTAIN,
    explanation: `Automated AI investigation could not conclusively verify this finding. ${reason}`,
    impact: (finding && finding.title) ? `Potential impact related to ${finding.title}` : 'Uncertain security impact; manual review recommended.',
    recommendation: 'Perform manual verification of the code context and apply relevant remediation.',
    confidence: AI_CONFIDENCES.LOW,
    evidence: (finding && finding.evidence) ? [finding.evidence] : [],
    preconditions: ['Requires manual verification by security engineer'],
    limitations: [limitationMsg],
    createdAt: new Date().toISOString()
  };
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

function validateAIInvestigationOutput(data) {
  return AIInvestigationOutputSchema.safeParse(data);
}

function validateInvestigation(data) {
  return InvestigationEntitySchema.safeParse(data);
}

module.exports = {
  // Constants & Enums
  AI_ASSESSMENTS,
  AI_CONFIDENCES,
  SEVERITIES,
  BOUNDS,

  // Zod Schemas
  AIAssessmentEnum,
  AIConfidenceEnum,
  SeverityEnum,
  AIInvestigationOutputSchema,
  InvestigationEntitySchema,
  InvestigationSchema,

  // Functions
  extractJsonString,
  parseAndValidateAIInvestigation,
  createFallbackInvestigation,
  validateAIInvestigationOutput,
  validateInvestigation
};
