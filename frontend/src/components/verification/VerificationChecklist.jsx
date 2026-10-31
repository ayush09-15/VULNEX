import { useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  HelpCircle,
  MinusCircle,
  Terminal,
  ShieldCheck,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  Cpu,
  Fingerprint,
  Info,
} from 'lucide-react';

/**
 * Status Badge Component with consistent color mapping
 * Values: PASSED | FAILED | NOT_RUN | INCONCLUSIVE
 */
export function StatusBadge({ status }) {
  const norm = String(status || 'NOT_RUN').toUpperCase();

  switch (norm) {
    case 'PASSED':
    case 'VERIFIED':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold uppercase bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 shadow-sm">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          PASSED
        </span>
      );
    case 'FAILED':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold uppercase bg-rose-950/80 text-rose-300 border border-rose-700/60 shadow-sm">
          <XCircle className="w-3.5 h-3.5 text-rose-400" />
          FAILED
        </span>
      );
    case 'INCONCLUSIVE':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold uppercase bg-amber-950/80 text-amber-300 border border-amber-700/60 shadow-sm">
          <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
          INCONCLUSIVE
        </span>
      );
    case 'PARTIAL':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold uppercase bg-amber-950/80 text-amber-300 border border-amber-700/60 shadow-sm">
          <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
          PARTIAL
        </span>
      );
    case 'NOT_RUN':
    default:
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium uppercase bg-slate-900 text-slate-400 border border-slate-700/60">
          <MinusCircle className="w-3.5 h-3.5 text-slate-500" />
          NOT RUN
        </span>
      );
  }
}

/**
 * VerificationChecklist Component (Commit 40)
 *
 * Implements:
 * - Master Antigravity Execution Bible Section 3.3, 3.4 & Section 9.3
 * - Acceptance Gate: PASSED/FAILED/NOT RUN/INCONCLUSIVE per check.
 * - Scoped status wording (no whole-app 'secure' badge).
 * - Separate rows for patch-applied, targeted-test, syntax, re-scan, and regressions.
 */
export default function VerificationChecklist({
  verification = null,
  patch = null,
  onRunVerification = null,
  isVerifying = false,
}) {
  const [expandedRow, setExpandedRow] = useState(null);

  const toggleRow = (rowId) => {
    setExpandedRow((prev) => (prev === rowId ? null : rowId));
  };

  // Derive individual check statuses
  const patchAppliedStatus = patch?.status === 'APPLIED_TO_TEMP' || patch?.status === 'VERIFIED'
    ? 'PASSED'
    : patch?.status === 'FAILED'
    ? 'FAILED'
    : 'NOT_RUN';

  const testStatus = verification?.testResults
    ? verification.testResults.testsPassed
      ? 'PASSED'
      : 'FAILED'
    : 'NOT_RUN';

  const syntaxStatus = verification?.testResults?.syntaxValid !== undefined
    ? verification.testResults.syntaxValid
      ? 'PASSED'
      : 'FAILED'
    : 'NOT_RUN';

  const comparison = verification?.beforeAfterComparison;
  const isAmbiguous = Boolean(comparison?.ambiguousMatch || comparison?.comparisonOutcome === 'AMBIGUOUS');

  const rescanStatus = verification?.scannerResults
    ? isAmbiguous
      ? 'INCONCLUSIVE'
      : verification.scannerResults.originalFindingResolved
      ? 'PASSED'
      : 'FAILED'
    : 'NOT_RUN';

  const regressionStatus = verification?.scannerResults
    ? isAmbiguous
      ? 'INCONCLUSIVE'
      : (comparison?.regressionDetected || verification.scannerResults.newFindingsCount > 0)
      ? 'FAILED'
      : 'PASSED'
    : 'NOT_RUN';

  const overallStatus = verification?.status || 'NOT_RUN';

  const checks = [
    {
      id: 'patch_apply',
      title: 'Disposable Workspace Patch Application',
      description: 'Diff validated against traversal guards and applied exclusively to temporary workspace.',
      status: patchAppliedStatus,
      details: {
        workspace: patch?.appliedWorkspaceId || 'ws_disposable_pending',
        scope: 'Original source files and git remote remain 100% untouched.',
        changedFiles: patch?.changedFiles || [],
      },
    },
    {
      id: 'syntax_validation',
      title: 'Syntax & Parse Tree Integrity Check',
      description: 'Abstract Syntax Tree (AST) validation verifying patched file parses without syntax errors.',
      status: syntaxStatus,
      details: {
        syntaxValid: verification?.testResults?.syntaxValid ?? 'Not evaluated',
        ruleRemediated: verification?.scannerResults?.ruleId || 'N/A',
      },
    },
    {
      id: 'targeted_tests',
      title: 'Targeted Subprocess Regression Tests',
      description: 'Restricted targeted test runner executed inside disposable sandbox with bounded timeouts.',
      status: testStatus,
      details: {
        command: verification?.testResults?.command?.join(' ') || 'node --test',
        exitCode: verification?.testResults?.exitCode ?? 'N/A',
        duration: verification?.testResults?.durationMs ? `${verification.testResults.durationMs}ms` : 'N/A',
        stdout: verification?.testResults?.stdout || 'No stdout recorded',
        stderr: verification?.testResults?.stderr || 'No errors reported',
      },
    },
    {
      id: 'post_patch_scan',
      title: 'Post-Patch Scanner Fingerprint Matching',
      description: 'Re-scan with Semgrep engine comparing before/after finding fingerprints.',
      status: rescanStatus,
      details: {
        tool: `${verification?.scannerResults?.tool || 'semgrep'} ${verification?.scannerResults?.toolVersion ? `v${verification.scannerResults.toolVersion}` : ''}`,
        command: verification?.scannerResults?.command?.join(' ') || 'semgrep scan --json',
        exitCode: verification?.scannerResults?.exitCode ?? 'N/A',
        targetResolved: verification?.scannerResults?.originalFindingResolved ? 'Yes (Flaw eliminated)' : 'No (Flaw persists)',
        comparisonOutcome: comparison?.comparisonOutcome || (rescanStatus === 'PASSED' ? 'RESOLVED' : 'STILL_DETECTED'),
        targetFingerprint: comparison?.targetFingerprint || 'sha256_canonical',
        matchedFingerprint: comparison?.matchedFingerprint || 'None (Resolved)',
      },
    },
    {
      id: 'defect_regression',
      title: 'Zero Defect Regression Boundary',
      description: 'Inspection of modified file scope to verify no new security vulnerabilities were introduced.',
      status: regressionStatus,
      details: {
        newDefectsCount: verification?.scannerResults?.newFindingsCount ?? 0,
        regressionDetected: comparison?.regressionDetected ? 'YES (Defect introduced)' : 'NO (Clean patch)',
        newFindings: verification?.scannerResults?.newFindings || [],
      },
    },
  ];

  return (
    <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-5 animate-fadeIn">
      {/* Header & Overall Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100 font-mono">
              Remediation Verification Checklist
            </h2>
          </div>
          <p className="text-xs text-slate-400">
            Independent multi-stage verification executed strictly within the disposable sandbox
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">Overall Verification:</span>
            <StatusBadge status={overallStatus} />
          </div>

          {onRunVerification && patch?.status === 'APPLIED_TO_TEMP' && (
            <button
              type="button"
              onClick={onRunVerification}
              disabled={isVerifying}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold shadow-md transition-all flex items-center gap-2 ${
                isVerifying
                  ? 'bg-cyan-800 text-cyan-300 cursor-not-allowed'
                  : 'bg-cyan-600 hover:bg-cyan-500 text-white'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>{isVerifying ? 'Verifying...' : 'Re-run Verification'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Scoped Status Disclosure Banner (Bible Section 9.3) */}
      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-cyan-900/40 text-xs flex items-start gap-2.5">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1 text-slate-300">
          <p className="leading-relaxed">
            <strong className="text-cyan-300">Scoped Verification Guarantee:</strong>{' '}
            {overallStatus === 'PASSED'
              ? 'Targeted finding is no longer detected by scanner in this run. Verification is scoped to the executed test commands and disposable workspace.'
              : overallStatus === 'INCONCLUSIVE'
              ? 'Verification outcome is inconclusive due to ambiguous fingerprint matching or scanner uncertainty. Manual human review is required.'
              : overallStatus === 'FAILED'
              ? 'Verification checks detected flaws: tests failed, the vulnerability persists, or a regression was introduced.'
              : 'Verification has not yet been executed for this proposal.'}
          </p>
          <p className="text-[11px] text-slate-500 font-mono">
            Safety Invariant: Verification does not claim whole-application security. Production branches remain untouched.
          </p>
        </div>
      </div>

      {/* Checklist Rows */}
      <div className="space-y-2.5">
        {checks.map((check) => {
          const isExpanded = expandedRow === check.id;

          return (
            <div
              key={check.id}
              className="rounded-xl border border-slate-800/80 bg-slate-950/60 overflow-hidden transition-colors hover:border-slate-700/80"
            >
              <div
                onClick={() => toggleRow(check.id)}
                className="p-3.5 flex items-center justify-between gap-4 cursor-pointer select-none"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-xs font-semibold text-slate-200">
                      {check.title}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    {check.description}
                  </p>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <StatusBadge status={check.status} />
                  <button
                    type="button"
                    className="text-slate-500 hover:text-slate-300 p-1"
                    aria-label="Toggle details"
                  >
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4" />
                    ) : (
                      <ChevronDown className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>

              {/* Collapsible Details Drawer */}
              {isExpanded && (
                <div className="px-4 pb-4 pt-1 border-t border-slate-800/60 text-xs font-mono space-y-2 bg-slate-950/90 text-slate-400">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2">
                    {Object.entries(check.details).map(([k, v]) => {
                      if (k === 'stdout' || k === 'stderr') return null;
                      return (
                        <div key={k} className="p-2 rounded bg-slate-900/60 border border-slate-800">
                          <span className="text-slate-500 text-[10px] uppercase block mb-0.5 font-bold">
                            {k}
                          </span>
                          <span className="text-slate-200 text-xs break-all">
                            {Array.isArray(v) ? (v.length > 0 ? v.join(', ') : 'None') : String(v)}
                          </span>
                        </div>
                      );
                    })}
                  </div>

                  {check.details.stdout && check.details.stdout !== 'No stdout recorded' && (
                    <div className="mt-2">
                      <span className="text-slate-500 text-[10px] uppercase block mb-1 font-bold">
                        Process Stdout
                      </span>
                      <pre className="p-2 rounded bg-black/60 border border-slate-800 text-[11px] text-slate-300 overflow-x-auto">
                        {check.details.stdout}
                      </pre>
                    </div>
                  )}

                  {check.details.stderr && check.details.stderr !== 'No errors reported' && (
                    <div className="mt-2">
                      <span className="text-rose-400 text-[10px] uppercase block mb-1 font-bold">
                        Process Stderr
                      </span>
                      <pre className="p-2 rounded bg-rose-950/20 border border-rose-900/40 text-[11px] text-rose-300 overflow-x-auto">
                        {check.details.stderr}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Residual Risks & Unexecuted Checks Note */}
      <div className="p-3 rounded-xl bg-slate-950/40 border border-slate-800/60 text-[11px] font-mono text-slate-500 flex items-center justify-between">
        <span>Unexecuted Checks: Live network penetration, end-user authentication flows</span>
        <span className="text-cyan-400/80">Audit-Ready Evidence</span>
      </div>
    </div>
  );
}
