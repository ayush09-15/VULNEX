/**
 * Normalization and formatting utilities for Verification results.
 * Supports VerificationChecklist component and Reports page.
 *
 * Implements:
 * - Master Antigravity Execution Bible Section 3.3, 3.4 & Section 9.3
 * - Commit 40 Acceptance Gate: PASSED/FAILED/NOT RUN/INCONCLUSIVE per check.
 */

export const VERIFICATION_STATUS_CONFIG = {
  PASSED: {
    label: 'PASSED',
    color: 'emerald',
    badgeClass: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60',
    description: 'Check executed and satisfied all criteria cleanly.',
  },
  FAILED: {
    label: 'FAILED',
    color: 'rose',
    badgeClass: 'bg-rose-950/80 text-rose-300 border-rose-700/60',
    description: 'Check failed: tests did not pass, flaw persisted, or regression was introduced.',
  },
  INCONCLUSIVE: {
    label: 'INCONCLUSIVE',
    color: 'amber',
    badgeClass: 'bg-amber-950/80 text-amber-300 border-amber-700/60',
    description: 'Check was inconclusive due to ambiguous fingerprint matching or scanner uncertainty.',
  },
  NOT_RUN: {
    label: 'NOT RUN',
    color: 'slate',
    badgeClass: 'bg-slate-900 text-slate-400 border-slate-700/60',
    description: 'Check has not been executed yet.',
  },
};

/**
 * Normalizes a status string to canonical PASSED | FAILED | INCONCLUSIVE | NOT_RUN
 * @param {string} raw
 * @returns {'PASSED' | 'FAILED' | 'INCONCLUSIVE' | 'NOT_RUN'}
 */
export function normalizeCheckStatus(raw) {
  if (!raw) return 'NOT_RUN';
  const upper = String(raw).toUpperCase().trim();
  if (['PASSED', 'VERIFIED', 'RESOLVED', 'SUCCESS'].includes(upper)) return 'PASSED';
  if (['FAILED', 'FAILURE', 'ERROR', 'STILL_DETECTED'].includes(upper)) return 'FAILED';
  if (['INCONCLUSIVE', 'AMBIGUOUS', 'UNCERTAIN'].includes(upper)) return 'INCONCLUSIVE';
  return 'NOT_RUN';
}

/**
 * Builds the canonical 5-point verification checklist
 * Acceptance Gate: PASSED/FAILED/NOT RUN/INCONCLUSIVE per check.
 *
 * @param {Object} verification
 * @param {Object} patch
 * @returns {Array<Object>}
 */
export function buildVerificationChecklist(verification = null, patch = null) {
  const patchAppliedStatus = normalizeCheckStatus(
    patch?.status === 'APPLIED_TO_TEMP' || patch?.status === 'VERIFIED'
      ? 'PASSED'
      : patch?.status === 'FAILED'
      ? 'FAILED'
      : 'NOT_RUN'
  );

  const testStatus = normalizeCheckStatus(
    verification?.testResults
      ? verification.testResults.testsPassed
        ? 'PASSED'
        : 'FAILED'
      : 'NOT_RUN'
  );

  const syntaxStatus = normalizeCheckStatus(
    verification?.testResults?.syntaxValid !== undefined
      ? verification.testResults.syntaxValid
        ? 'PASSED'
        : 'FAILED'
      : 'NOT_RUN'
  );

  const comparison = verification?.beforeAfterComparison;
  const isAmbiguous = Boolean(comparison?.ambiguousMatch || comparison?.comparisonOutcome === 'AMBIGUOUS');

  const rescanStatus = normalizeCheckStatus(
    verification?.scannerResults
      ? isAmbiguous
        ? 'INCONCLUSIVE'
        : verification.scannerResults.originalFindingResolved
        ? 'PASSED'
        : 'FAILED'
      : 'NOT_RUN'
  );

  const regressionStatus = normalizeCheckStatus(
    verification?.scannerResults
      ? isAmbiguous
        ? 'INCONCLUSIVE'
        : (comparison?.regressionDetected || verification.scannerResults.newFindingsCount > 0)
        ? 'FAILED'
        : 'PASSED'
      : 'NOT_RUN'
  );

  return [
    {
      id: 'patch_apply',
      title: 'Disposable Workspace Patch Application',
      description: 'Diff validated against traversal guards and applied exclusively to temporary workspace.',
      status: patchAppliedStatus,
    },
    {
      id: 'syntax_validation',
      title: 'Syntax & Parse Tree Integrity Check',
      description: 'Abstract Syntax Tree (AST) validation verifying patched file parses without syntax errors.',
      status: syntaxStatus,
    },
    {
      id: 'targeted_tests',
      title: 'Targeted Subprocess Regression Tests',
      description: 'Restricted targeted test runner executed inside disposable sandbox with bounded timeouts.',
      status: testStatus,
    },
    {
      id: 'post_patch_scan',
      title: 'Post-Patch Scanner Fingerprint Matching',
      description: 'Re-scan with Semgrep engine comparing before/after finding fingerprints.',
      status: rescanStatus,
    },
    {
      id: 'defect_regression',
      title: 'Zero Defect Regression Boundary',
      description: 'Inspection of modified file scope to verify no new security vulnerabilities were introduced.',
      status: regressionStatus,
    },
  ];
}

/**
 * Returns truthful scoped wording for verification status banner (Bible Section 9.3)
 * @param {string} status
 * @returns {string}
 */
export function getScopedStatusWording(status) {
  const norm = normalizeCheckStatus(status);
  switch (norm) {
    case 'PASSED':
      return 'Targeted finding is no longer detected by scanner in this run. Verification is scoped to the executed test commands and disposable workspace.';
    case 'INCONCLUSIVE':
      return 'Verification outcome is inconclusive due to ambiguous fingerprint matching or scanner uncertainty. Manual human review is required.';
    case 'FAILED':
      return 'Verification checks detected flaws: tests failed, the vulnerability persists, or a regression was introduced.';
    case 'NOT_RUN':
    default:
      return 'Verification has not yet been executed for this proposal.';
  }
}
