/**
 * Normalization and formatting utilities for AI Investigation results.
 * Supports InvestigationResultPanel and FindingDetailDrawer.
 * Adheres strictly to Master Antigravity Execution Bible Section 8.4 and Commit 27 gates.
 */

export const ASSESSMENT_CONFIG = {
  LIKELY_TRUE: {
    label: 'Likely True Positive',
    color: 'red',
    tagBg: 'bg-red-950/50',
    tagBorder: 'border-red-800/50',
    tagText: 'text-red-400',
    cardBorder: 'border-red-900/30',
    description: 'Model identified active vulnerable data flow without mitigating sanitization.',
  },
  UNCERTAIN: {
    label: 'Uncertain / Context Incomplete',
    color: 'amber',
    tagBg: 'bg-amber-950/50',
    tagBorder: 'border-amber-800/50',
    tagText: 'text-amber-400',
    cardBorder: 'border-amber-900/30',
    description: 'Insufficient context or ambiguous control flow requires manual human review.',
  },
  LIKELY_FALSE: {
    label: 'Likely False Positive',
    color: 'emerald',
    tagBg: 'bg-emerald-950/50',
    tagBorder: 'border-emerald-800/50',
    tagText: 'text-emerald-400',
    cardBorder: 'border-emerald-900/30',
    description: 'Sanitization, parameterization, or dead code prevents vulnerability execution.',
  },
};

/**
 * Normalizes an investigation payload for predictable rendering in the UI.
 * Ensures evidence, preconditions, and limitations are safe iterable arrays.
 * 
 * @param {Object} raw
 * @returns {Object|null}
 */
export function formatInvestigationData(raw) {
  if (!raw || typeof raw !== 'object') return null;

  const assessment = (raw.assessment || 'UNCERTAIN').toUpperCase();
  const meta = ASSESSMENT_CONFIG[assessment] || ASSESSMENT_CONFIG.UNCERTAIN;

  const toArray = (val) => {
    if (Array.isArray(val)) return val.filter(Boolean).map(String);
    if (val && typeof val === 'string') return [val.trim()];
    return [];
  };

  return {
    id: raw.id || null,
    findingId: raw.findingId || null,
    assessment,
    assessmentMeta: meta,
    confidence: (raw.confidence || 'MEDIUM').toUpperCase(),
    summary: raw.summary || raw.explanation || 'Diagnosis completed.',
    evidence: toArray(raw.evidence),
    preconditions: toArray(raw.preconditions),
    potentialImpact: raw.potentialImpact || raw.impact || 'No specific impact noted.',
    recommendedFix: raw.recommendedFix || raw.recommendation || null,
    limitations: toArray(raw.limitations),
    model: raw.model || raw.modelUsed || 'gemma-2-9b-it',
    promptVersion: raw.promptVersion || 'vulnex-investigation-v1',
    createdAt: raw.createdAt || null,
  };
}
