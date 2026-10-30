/**
 * VULNEX Core Domain Constants & Types
 * Derived from Master Antigravity Execution Bible and docs/DATA_MODELS.md
 */

export const SCAN_STAGES = {
  QUEUED: 'QUEUED',
  PREPARING: 'PREPARING',
  SCANNING: 'SCANNING',
  NORMALIZING: 'NORMALIZING',
  INVESTIGATING: 'INVESTIGATING',
  COMPLETED: 'COMPLETED',
  PARTIAL: 'PARTIAL',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED',
};

export const FINDING_STATUSES = {
  DETECTED: 'DETECTED',
  TRIAGED: 'TRIAGED',
  PATCH_PROPOSED: 'PATCH_PROPOSED',
  PATCH_APPLIED: 'PATCH_APPLIED',
  VERIFIED: 'VERIFIED',
  REJECTED: 'REJECTED',
  FAILED: 'FAILED',
  INCONCLUSIVE: 'INCONCLUSIVE',
};

export const PATCH_STATUSES = {
  GENERATED: 'GENERATED',
  VALIDATED: 'VALIDATED',
  APPLIED_TO_TEMP: 'APPLIED_TO_TEMP',
  TESTING: 'TESTING',
  VERIFIED: 'VERIFIED',
  FAILED: 'FAILED',
  REJECTED: 'REJECTED',
  INCONCLUSIVE: 'INCONCLUSIVE',
};

export const VERIFICATION_STATUSES = {
  PASSED: 'PASSED',
  FAILED: 'FAILED',
  INCONCLUSIVE: 'INCONCLUSIVE',
  NOT_RUN: 'NOT_RUN',
  PARTIAL: 'PARTIAL',
};

export const AI_ASSESSMENTS = {
  LIKELY_TRUE: 'LIKELY_TRUE',
  UNCERTAIN: 'UNCERTAIN',
  LIKELY_FALSE: 'LIKELY_FALSE',
};

export const AI_CONFIDENCE = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
};


export const SOURCE_TYPES = {
  GITHUB: 'GITHUB',
  ZIP_UPLOAD: 'ZIP_UPLOAD',
};

export const SEVERITY_LEVELS = {
  CRITICAL: {
    label: 'Critical',
    bg: 'bg-red-500/15',
    text: 'text-red-400',
    border: 'border-red-500/30',
    dot: 'bg-red-500',
  },
  HIGH: {
    label: 'High',
    bg: 'bg-orange-500/15',
    text: 'text-orange-400',
    border: 'border-orange-500/30',
    dot: 'bg-orange-500',
  },
  MEDIUM: {
    label: 'Medium',
    bg: 'bg-amber-500/15',
    text: 'text-amber-400',
    border: 'border-amber-500/30',
    dot: 'bg-amber-500',
  },
  LOW: {
    label: 'Low',
    bg: 'bg-blue-500/15',
    text: 'text-blue-400',
    border: 'border-blue-500/30',
    dot: 'bg-blue-500',
  },
  INFO: {
    label: 'Info',
    bg: 'bg-slate-500/15',
    text: 'text-slate-400',
    border: 'border-slate-500/30',
    dot: 'bg-slate-400',
  },
};

export const VULNERABILITY_CATEGORIES = {
  SQL_INJECTION: 'SQL Injection',
  XSS: 'Cross-Site Scripting (XSS)',
  SECRETS: 'Hard-coded Secret',
  HARDCODED_SECRET: 'Hard-coded Secret',
  VULNERABLE_DEPENDENCY: 'Vulnerable Dependency',
  COMMAND_INJECTION: 'Command Injection',
  PATH_TRAVERSAL: 'Path Traversal',
  OTHER: 'Other Security Flaw',
};
