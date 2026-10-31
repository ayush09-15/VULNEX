/**
 * VULNEX Canonical Patch Proposal Contract & Schema
 *
 * Implements:
 * - Master Antigravity Execution Bible Section 8.7 & DATA_MODELS.md Section 2.5
 * - Canonical Unified Diff Proposal Schema
 * - Explicit Review States: PENDING_REVIEW, APPROVED, REJECTED
 * - Deterministic Diff Validation & Scope Bounding
 * - Path Traversal Prevention
 * - Strict Separation of Proposal from Patch Application & Verification
 */

const { z } = require('zod');
const { SafeRelativeFilePath } = require('./canonical.schema');
const { extractJsonString } = require('./investigation.schema');

// ----------------------------------------------------------------------------
// 1. Constants & Enums
// ----------------------------------------------------------------------------

const PATCH_REVIEW_STATES = Object.freeze({
  PENDING_REVIEW: 'PENDING_REVIEW',
  APPROVED: 'APPROVED',
  REJECTED: 'REJECTED'
});

const PatchReviewStateEnum = z.enum([
  PATCH_REVIEW_STATES.PENDING_REVIEW,
  PATCH_REVIEW_STATES.APPROVED,
  PATCH_REVIEW_STATES.REJECTED
], {
  errorMap: () => ({
    message: "reviewState must be one of 'PENDING_REVIEW', 'APPROVED', or 'REJECTED'"
  })
});

const ALLOWED_REVIEW_STATE_TRANSITIONS = Object.freeze({
  [PATCH_REVIEW_STATES.PENDING_REVIEW]: Object.freeze([
    PATCH_REVIEW_STATES.APPROVED,
    PATCH_REVIEW_STATES.REJECTED
  ]),
  [PATCH_REVIEW_STATES.APPROVED]: Object.freeze([
    PATCH_REVIEW_STATES.REJECTED
  ]),
  [PATCH_REVIEW_STATES.REJECTED]: Object.freeze([
    PATCH_REVIEW_STATES.PENDING_REVIEW
  ])
});

// ----------------------------------------------------------------------------
// 2. Custom Errors
// ----------------------------------------------------------------------------

class InvalidReviewStateTransitionError extends Error {
  constructor(fromState, toState, message) {
    super(message || `Invalid patch review state transition from '${fromState}' to '${toState}'`);
    this.name = 'InvalidReviewStateTransitionError';
    this.fromState = fromState;
    this.toState = toState;
  }
}

class OutOfScopeProposalError extends Error {
  constructor(message, details = {}) {
    super(message || 'Patch proposal modifies files outside finding scope');
    this.name = 'OutOfScopeProposalError';
    this.details = details;
  }
}

class MissingEvidenceLinkError extends Error {
  constructor(message, details = {}) {
    super(message || 'Patch proposal cannot be linked to the original finding evidence');
    this.name = 'MissingEvidenceLinkError';
    this.details = details;
  }
}

// ----------------------------------------------------------------------------
// 3. Unified Diff Parser & Validator
// ----------------------------------------------------------------------------

/**
 * Parse and validate unified diff format.
 * Checks for standard unified diff headers (--- / +++), hunk markers (@@),
 * hunk line prefixes (+, -, space, \), and safe relative file paths.
 *
 * @param {string} diffString
 * @returns {{ valid: boolean, oldFile?: string, newFile?: string, files: string[], hunks: object[], error?: string }}
 */
function parseUnifiedDiff(diffString) {
  if (typeof diffString !== 'string') {
    return { valid: false, files: [], hunks: [], error: 'Diff content must be a string' };
  }

  const trimmed = diffString.trim();
  if (!trimmed) {
    return { valid: false, files: [], hunks: [], error: 'Diff content cannot be empty' };
  }

  const lines = trimmed.split(/\r?\n/);
  let oldFile = null;
  let newFile = null;
  const hunks = [];
  let currentHunk = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith('--- ')) {
      const match = line.match(/^---\s+(?:[ab]\/)?(.+?)(?:\t.*)?$/);
      if (match) {
        oldFile = match[1].trim();
      }
      continue;
    }

    if (line.startsWith('+++ ')) {
      const match = line.match(/^\+\+\+\s+(?:[ab]\/)?(.+?)(?:\t.*)?$/);
      if (match) {
        newFile = match[1].trim();
      }
      continue;
    }

    if (line.startsWith('@@')) {
      const hunkMatch = line.match(/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/);
      if (!hunkMatch) {
        return {
          valid: false,
          files: [],
          hunks: [],
          error: `Malformed hunk header at line ${i + 1}: "${line}"`
        };
      }
      currentHunk = {
        header: line,
        oldStart: parseInt(hunkMatch[1], 10),
        oldCount: hunkMatch[2] !== undefined ? parseInt(hunkMatch[2], 10) : 1,
        newStart: parseInt(hunkMatch[3], 10),
        newCount: hunkMatch[4] !== undefined ? parseInt(hunkMatch[4], 10) : 1,
        lines: []
      };
      hunks.push(currentHunk);
      continue;
    }

    if (currentHunk) {
      if ([' ', '+', '-', '\\'].includes(line[0])) {
        currentHunk.lines.push(line);
      } else if (line.trim() === '') {
        currentHunk.lines.push(' ');
      } else {
        return {
          valid: false,
          files: [],
          hunks: [],
          error: `Invalid diff hunk line prefix at line ${i + 1}: "${line[0]}". Must be '+', '-', ' ', or '\\'`
        };
      }
    }
  }

  if (!oldFile && !newFile) {
    return { valid: false, files: [], hunks: [], error: 'Missing unified diff file headers (--- and +++)' };
  }

  if (hunks.length === 0) {
    return { valid: false, files: [], hunks: [], error: 'Unified diff must contain at least one hunk header (@@ ... @@)' };
  }

  const hasModifications = hunks.some(h =>
    h.lines.some(l => l.startsWith('+') || l.startsWith('-'))
  );
  if (!hasModifications) {
    return { valid: false, files: [], hunks: [], error: 'Unified diff does not contain any added (+) or deleted (-) lines' };
  }

  // Validate raw paths from diff headers for absolute paths and path traversal
  for (const raw of [oldFile, newFile]) {
    if (!raw || raw === '/dev/null') continue;
    if (raw.startsWith('/') || raw.startsWith('\\') || /^[A-Za-z]:[\\/]/.test(raw)) {
      return { valid: false, files: [], hunks: [], error: `Diff contains absolute file path: "${raw}"` };
    }
    if (raw.split(/[/\\]/).includes('..')) {
      return { valid: false, files: [], hunks: [], error: `Diff contains unsafe path traversal sequence: "${raw}"` };
    }
  }

  const normalizeDiffPath = (p) => {
    if (!p || p === '/dev/null') return null;
    return p.replace(/^[ab]\//, '').replace(/\\/g, '/');
  };

  const normOld = normalizeDiffPath(oldFile);
  const normNew = normalizeDiffPath(newFile);

  const files = Array.from(new Set([normOld, normNew].filter(Boolean)));

  // Validate normalized paths
  for (const f of files) {
    if (f.split(/[/\\]/).includes('..')) {
      return { valid: false, files: [], hunks: [], error: `Diff contains unsafe path traversal sequence: "${f}"` };
    }
    if (f.startsWith('/') || f.startsWith('\\') || /^[A-Za-z]:[\\/]/.test(f)) {
      return { valid: false, files: [], hunks: [], error: `Diff contains absolute file path: "${f}"` };
    }
  }

  return {
    valid: true,
    oldFile: normOld,
    newFile: normNew,
    files,
    hunks
  };
}

/**
 * Validate unified diff string
 * @param {string} diffString
 * @returns {{ valid: boolean, error?: string, files: string[] }}
 */
function validateUnifiedDiff(diffString) {
  return parseUnifiedDiff(diffString);
}

// ----------------------------------------------------------------------------
// 4. Zod Schemas
// ----------------------------------------------------------------------------

const UnifiedDiffSchema = z.string()
  .min(1, 'diff content is required')
  .superRefine((diff, ctx) => {
    const parsed = parseUnifiedDiff(diff);
    if (!parsed.valid) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: parsed.error || 'Invalid unified diff format'
      });
    }
  });

const EvidenceReferenceSchema = z.union([
  z.string().trim().min(1, 'Evidence reference string cannot be empty'),
  z.object({
    type: z.enum(['FINGERPRINT', 'LINE_RANGE', 'SNIPPET', 'RULE_ID', 'URL', 'OTHER']).default('SNIPPET'),
    reference: z.string().trim().min(1, 'Evidence reference value is required'),
    description: z.string().optional()
  })
]);

const CreatePatchProposalSchema = z.object({
  findingId: z.string().min(1, 'findingId is required'),
  diff: UnifiedDiffSchema,
  rationale: z.string().trim().min(5, 'Rationale must be at least 5 characters explaining the fix'),
  changedFiles: z.array(SafeRelativeFilePath).min(1, 'At least one changed file is required'),
  evidenceReferences: z.array(EvidenceReferenceSchema).min(1, 'At least one evidence reference linking proposal to finding is required'),
  reviewState: PatchReviewStateEnum.default(PATCH_REVIEW_STATES.PENDING_REVIEW),
  metadata: z.record(z.any()).optional()
}).refine((data) => {
  const parsed = parseUnifiedDiff(data.diff);
  if (!parsed.valid) return false;
  const normalizedChanged = data.changedFiles.map(f => f.replace(/\\/g, '/').replace(/^\/+/, ''));
  return parsed.files.every(f => normalizedChanged.includes(f));
}, {
  message: 'Files in unified diff header must match changedFiles list',
  path: ['changedFiles']
});

const PatchProposalSchema = z.object({
  id: z.string().min(1, 'Unique proposal ID is required'),
  findingId: z.string().min(1, 'findingId is required'),
  diff: UnifiedDiffSchema,
  rationale: z.string().trim().min(5, 'Rationale must be at least 5 characters explaining the fix'),
  changedFiles: z.array(SafeRelativeFilePath).min(1, 'At least one changed file is required'),
  evidenceReferences: z.array(EvidenceReferenceSchema).min(1, 'At least one evidence reference linking proposal to finding is required'),
  reviewState: PatchReviewStateEnum.default(PATCH_REVIEW_STATES.PENDING_REVIEW),
  reviewedBy: z.string().nullable().optional().default(null),
  reviewedAt: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' }).nullable().optional().default(null),
  reviewComments: z.string().nullable().optional().default(null),
  createdAt: z.string().datetime({ message: 'Must be ISO-8601 UTC timestamp' }),
  metadata: z.record(z.any()).optional()
}).refine((data) => {
  const parsed = parseUnifiedDiff(data.diff);
  if (!parsed.valid) return false;
  const normalizedChanged = data.changedFiles.map(f => f.replace(/\\/g, '/').replace(/^\/+/, ''));
  return parsed.files.every(f => normalizedChanged.includes(f));
}, {
  message: 'Files in unified diff header must match changedFiles list',
  path: ['changedFiles']
});

const AIPatchRationaleSchema = z.union([
  z.string().trim().min(5, 'Rationale must be at least 5 characters explaining the fix'),
  z.object({
    rootCause: z.string().trim().min(1, 'rootCause is required'),
    proposedCorrection: z.string().trim().min(1, 'proposedCorrection is required'),
    explanation: z.string().trim().min(1, 'explanation is required')
  })
]);

const AIPatchProposalOutputSchema = z.object({
  diff: UnifiedDiffSchema,
  rationale: AIPatchRationaleSchema,
  changedFiles: z.array(SafeRelativeFilePath).min(1).optional(),
  evidenceReferences: z.array(EvidenceReferenceSchema).min(1).optional()
}).strict();

// ----------------------------------------------------------------------------
// 5. Scope Validation Helper
// ----------------------------------------------------------------------------

/**
 * Ensure proposals cannot silently modify files outside the associated finding's intended scope.
 *
 * @param {Object} proposal - Patch proposal object
 * @param {Object} finding - Associated finding object
 * @returns {{ valid: boolean, error?: string }}
 */
function validateProposalScope(proposal, finding) {
  if (!proposal || typeof proposal !== 'object') {
    return { valid: false, error: 'Proposal must be a non-null object' };
  }
  if (!finding || typeof finding !== 'object') {
    return { valid: false, error: 'Finding must be a non-null object' };
  }

  if (proposal.findingId !== finding.id) {
    return {
      valid: false,
      error: `Proposal findingId "${proposal.findingId}" does not match target finding id "${finding.id}"`
    };
  }

  const rawFindingPath = finding.filePath || finding.path;
  if (!rawFindingPath || typeof rawFindingPath !== 'string') {
    return { valid: false, error: 'Finding does not have a valid file path' };
  }

  const normalizedFindingPath = rawFindingPath.replace(/\\/g, '/').replace(/^\/+/, '');

  if (!Array.isArray(proposal.changedFiles) || proposal.changedFiles.length === 0) {
    return { valid: false, error: 'Proposal changedFiles must be a non-empty array' };
  }

  const normalizedChangedFiles = proposal.changedFiles.map(f =>
    String(f).replace(/\\/g, '/').replace(/^\/+/, '')
  );

  // Must include the finding's target file
  if (!normalizedChangedFiles.includes(normalizedFindingPath)) {
    return {
      valid: false,
      error: `Proposal changedFiles must include finding target file: "${normalizedFindingPath}"`
    };
  }

  // Must NOT include unauthorized out-of-scope files
  const outOfScope = normalizedChangedFiles.filter(f => f !== normalizedFindingPath);
  if (outOfScope.length > 0) {
    return {
      valid: false,
      error: `Proposal silently modifies files outside finding scope: ${outOfScope.map(f => `"${f}"`).join(', ')}`
    };
  }

  // Verify diff content does not target out-of-scope files
  if (proposal.diff) {
    const parsedDiff = parseUnifiedDiff(proposal.diff);
    if (!parsedDiff.valid) {
      return { valid: false, error: `Diff validation failed: ${parsedDiff.error}` };
    }

    for (const diffFile of parsedDiff.files) {
      if (diffFile !== normalizedFindingPath) {
        return {
          valid: false,
          error: `Diff header targets file outside finding scope: "${diffFile}" (expected "${normalizedFindingPath}")`
        };
      }
    }
  }

  return { valid: true };
}

/**
 * Asserts proposal scope, throwing an OutOfScopeProposalError if scope violation is detected.
 * @param {Object} proposal
 * @param {Object} finding
 */
function assertProposalScope(proposal, finding) {
  const result = validateProposalScope(proposal, finding);
  if (!result.valid) {
    throw new OutOfScopeProposalError(result.error, { proposal, finding });
  }
}

// ----------------------------------------------------------------------------
// 6. Review State Machine Helpers
// ----------------------------------------------------------------------------

function isValidReviewStateTransition(fromState, toState) {
  if (fromState === toState) return true;
  const allowed = ALLOWED_REVIEW_STATE_TRANSITIONS[fromState];
  return Boolean(allowed && allowed.includes(toState));
}

function transitionReviewState(proposal, nextState, options = {}) {
  const currentState = proposal.reviewState;
  if (!isValidReviewStateTransition(currentState, nextState)) {
    throw new InvalidReviewStateTransitionError(currentState, nextState);
  }

  const { reviewer = null, comments = null } = options;

  return {
    ...proposal,
    reviewState: nextState,
    reviewedBy: reviewer || proposal.reviewedBy || null,
    reviewedAt: new Date().toISOString(),
    reviewComments: comments !== undefined ? comments : proposal.reviewComments
  };
}

// ----------------------------------------------------------------------------
// 7. Validation SafeParse Helpers
// ----------------------------------------------------------------------------

function validatePatchProposal(data) {
  return PatchProposalSchema.safeParse(data);
}

function validateCreatePatchProposal(data) {
  return CreatePatchProposalSchema.safeParse(data);
}

// ----------------------------------------------------------------------------
// 8. AI Patch Output Parser & Validator
// ----------------------------------------------------------------------------

/**
 * Safely parses and validates AI model patch output against the unified proposal contract.
 * Enforces:
 * - JSON extraction and syntax parsing with secret scrubbing
 * - Strict schema validation rejecting unauthorized command/policy override fields
 * - Scope bounding ensuring diff targets only the finding's file
 * - Evidence linking ensuring proposal references original finding evidence
 * - Strict PENDING_REVIEW initial state (never self-authorized)
 *
 * @param {string|object} rawInput - Raw AI output string or parsed JSON object
 * @param {object} finding - Associated security finding
 * @param {object} [options={}] - Optional configuration
 * @returns {{ success: boolean, data?: object, error?: { code: string, message: string, details: any[] } }}
 */
function parseAndValidateAIPatchProposal(rawInput, finding, options = {}) {
  if (rawInput === null || rawInput === undefined || (typeof rawInput === 'string' && rawInput.trim() === '')) {
    return {
      success: false,
      error: {
        code: 'EMPTY_AI_OUTPUT',
        message: 'AI patch proposal output is empty or undefined',
        details: []
      }
    };
  }

  // 1. Finding validation
  if (!finding || typeof finding !== 'object') {
    return {
      success: false,
      error: {
        code: 'INVALID_FINDING',
        message: 'A valid target finding object is required to bind the patch proposal',
        details: []
      }
    };
  }

  const rawFindingPath = finding.filePath || finding.path;
  if (!rawFindingPath || typeof rawFindingPath !== 'string') {
    return {
      success: false,
      error: {
        code: 'INVALID_FINDING',
        message: 'Target finding is missing a valid filePath',
        details: []
      }
    };
  }
  const normalizedFindingPath = rawFindingPath.replace(/\\/g, '/').replace(/^\/+/, '');

  // 2. Finding evidence check
  const rawFindingEvidence = finding.evidence || finding.codeSnippet || options.sourceContext || '';
  const evidenceText = typeof rawFindingEvidence === 'object' ? JSON.stringify(rawFindingEvidence) : String(rawFindingEvidence).trim();
  if (!evidenceText) {
    return {
      success: false,
      error: {
        code: 'MISSING_EVIDENCE',
        message: 'Finding contains no evidence or code snippet to link proposal against',
        details: []
      }
    };
  }

  // 3. Extract and parse JSON
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
      let cleanMsg = String(parseErr.message || 'JSON parse error');
      cleanMsg = cleanMsg
        .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b/g, '[REDACTED_TOKEN]')
        .replace(/\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g, '[REDACTED_AWS_KEY]')
        .replace(/(password|secret|api_key|token)\s*[:=]\s*['"]?[^\s'"]+['"]?/gi, '$1=[REDACTED_SECRET]');

      return {
        success: false,
        error: {
          code: 'MALFORMED_AI_JSON',
          message: `Failed to parse AI output as JSON: ${cleanMsg}`,
          details: [{ error: cleanMsg }]
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

  // 4. Validate schema with strict key enforcement
  const schemaResult = AIPatchProposalOutputSchema.safeParse(parsed);
  if (!schemaResult.success) {
    const issues = schemaResult.error.issues || [];
    const isUnrecognizedKey = issues.some(i => i.code === 'unrecognized_keys');
    const isPathError = issues.some(i =>
      i.path.includes('changedFiles') ||
      String(i.message).toLowerCase().includes('path') ||
      String(i.message).toLowerCase().includes('traversal')
    );
    const isDiffError = issues.some(i => i.path.includes('diff'));

    let code = 'INVALID_PATCH_PROPOSAL_SCHEMA';
    if (isUnrecognizedKey) code = 'UNAUTHORIZED_POLICY_OVERRIDE';
    else if (isPathError) code = 'INVALID_PATH';
    else if (isDiffError) code = 'MALFORMED_DIFF';

    return {
      success: false,
      error: {
        code,
        message: issues[0]?.message || 'AI output failed patch proposal schema validation',
        details: issues.map(err => ({
          path: Array.isArray(err.path) ? err.path.join('.') : String(err.path),
          message: err.message,
          code: err.code
        }))
      }
    };
  }

  // 5. Diff structure and path safety
  const parsedDiff = parseUnifiedDiff(parsed.diff);
  if (!parsedDiff.valid) {
    return {
      success: false,
      error: {
        code: 'MALFORMED_DIFF',
        message: parsedDiff.error || 'Invalid unified diff syntax',
        details: []
      }
    };
  }

  // 6. Scope check on diff headers
  for (const diffFile of parsedDiff.files) {
    if (diffFile !== normalizedFindingPath) {
      return {
        success: false,
        error: {
          code: 'UNSUPPORTED_FILE_CHANGES',
          message: `Diff modifies file outside finding scope: "${diffFile}" (expected "${normalizedFindingPath}")`,
          details: [{ file: diffFile, expected: normalizedFindingPath }]
        }
      };
    }
  }

  // 7. Scope check on changedFiles (if supplied in output)
  if (parsed.changedFiles && Array.isArray(parsed.changedFiles)) {
    for (const f of parsed.changedFiles) {
      const norm = String(f).replace(/\\/g, '/').replace(/^\/+/, '');
      if (norm !== normalizedFindingPath) {
        return {
          success: false,
          error: {
            code: 'UNSUPPORTED_FILE_CHANGES',
            message: `changedFiles includes file outside finding scope: "${norm}" (expected "${normalizedFindingPath}")`,
            details: [{ file: norm, expected: normalizedFindingPath }]
          }
        };
      }
    }
  }

  // 8. Evidence reference linking
  let evidenceRefs = [];
  if (parsed.evidenceReferences && Array.isArray(parsed.evidenceReferences) && parsed.evidenceReferences.length > 0) {
    const hasEvidenceLink = parsed.evidenceReferences.some(ref => {
      const refVal = typeof ref === 'object' ? (ref.reference || '') : String(ref);
      if (!refVal) return false;
      return (
        (evidenceText && (evidenceText.includes(refVal) || refVal.includes(evidenceText))) ||
        (finding.fingerprint && refVal === finding.fingerprint) ||
        (finding.ruleId && refVal === finding.ruleId) ||
        (finding.rule && refVal === finding.rule) ||
        (finding.startLine && refVal.includes(String(finding.startLine)))
      );
    });

    if (!hasEvidenceLink) {
      return {
        success: false,
        error: {
          code: 'MISSING_EVIDENCE_LINK',
          message: 'Proposal evidenceReferences cannot be linked to the original finding evidence',
          details: [{ provided: parsed.evidenceReferences, findingEvidence: evidenceText }]
        }
      };
    }
    evidenceRefs = parsed.evidenceReferences;
  } else {
    evidenceRefs = [
      {
        type: 'SNIPPET',
        reference: evidenceText,
        description: `Linked to finding ${finding.id || ''} evidence`
      }
    ];
  }

  // 9. Format rationale string and keep structured rationale details
  let rationaleString = '';
  let rationaleDetails = {};
  if (typeof parsed.rationale === 'object') {
    const r = parsed.rationale;
    rationaleString = `Root cause: ${r.rootCause}\nProposed correction: ${r.proposedCorrection}\nWhy this addresses the finding: ${r.explanation}`;
    rationaleDetails = r;
  } else {
    rationaleString = String(parsed.rationale).trim();
    rationaleDetails = { explanation: rationaleString };
  }

  // 10. Assemble canonical PatchProposal
  const proposal = {
    id: `prop_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    findingId: finding.id || 'finding_unknown',
    diff: parsed.diff.trim(),
    rationale: rationaleString,
    changedFiles: [normalizedFindingPath],
    evidenceReferences: evidenceRefs,
    reviewState: PATCH_REVIEW_STATES.PENDING_REVIEW,
    reviewedBy: null,
    reviewedAt: null,
    reviewComments: null,
    createdAt: new Date().toISOString(),
    metadata: {
      model: options.model || 'gemma-2-9b-it',
      promptVersion: options.promptVersion || '1.0.0',
      applied: false,
      requiresHumanReview: true,
      verified: false,
      rationaleDetails,
      ...(parsed.metadata || {})
    }
  };

  // 11. Final canonical schema & scope validation
  const validation = validatePatchProposal(proposal);
  if (!validation.success) {
    return {
      success: false,
      error: {
        code: 'INVALID_PATCH_PROPOSAL_SCHEMA',
        message: 'Assembled proposal failed canonical validation',
        details: validation.error.issues
      }
    };
  }

  const scopeValidation = validateProposalScope(proposal, finding);
  if (!scopeValidation.valid) {
    return {
      success: false,
      error: {
        code: 'OUT_OF_SCOPE_MODIFICATION',
        message: scopeValidation.error,
        details: []
      }
    };
  }

  return {
    success: true,
    data: proposal
  };
}

module.exports = {
  PATCH_REVIEW_STATES,
  PatchReviewStateEnum,
  ALLOWED_REVIEW_STATE_TRANSITIONS,
  InvalidReviewStateTransitionError,
  OutOfScopeProposalError,
  MissingEvidenceLinkError,

  parseUnifiedDiff,
  validateUnifiedDiff,

  UnifiedDiffSchema,
  EvidenceReferenceSchema,
  CreatePatchProposalSchema,
  PatchProposalSchema,
  AIPatchRationaleSchema,
  AIPatchProposalOutputSchema,

  validateProposalScope,
  assertProposalScope,
  isValidReviewStateTransition,
  transitionReviewState,

  validatePatchProposal,
  validateCreatePatchProposal,
  parseAndValidateAIPatchProposal
};
