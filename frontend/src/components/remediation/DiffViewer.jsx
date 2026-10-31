import { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  FileCode,
  Layers,
  ArrowRight,
  AlertTriangle,
  FileCheck2,
  Lock,
  Sparkles
} from 'lucide-react';
import { parseUnifiedDiff } from '../../utils/diffParser';

export default function DiffViewer({
  patch,
  targetFindingId,
  onApprove,
  onReject,
  onApply,
  isLoading = false,
  readOnly = false,
}) {
  const [approverComments, setApproverComments] = useState('');
  const [rejectReason, setRejectReason] = useState('');
  const [showRejectModal, setShowRejectModal] = useState(false);

  const diffText = patch?.diff || '';
  const parsed = useMemo(() => parseUnifiedDiff(diffText), [diffText]);

  const hasFindingMismatch = Boolean(
    targetFindingId && patch?.findingId && targetFindingId !== patch.findingId
  );

  const reviewState = patch?.reviewState || 'PENDING_REVIEW';
  const isApproved = reviewState === 'APPROVED';
  const isRejected = reviewState === 'REJECTED';
  const isPending = reviewState === 'PENDING_REVIEW';

  const stats = parsed.stats;
  const changedFiles = patch?.changedFiles || parsed.files.map((f) => f.newFile);

  const rationale =
    typeof patch?.rationale === 'object'
      ? patch.rationale.explanation || patch.rationale.proposedCorrection || JSON.stringify(patch.rationale)
      : patch?.rationale || 'Automated defensive remediation generated from vulnerability evidence.';

  const handleApprove = () => {
    if (onApprove) {
      onApprove(patch?.id, approverComments);
    }
  };

  const handleReject = () => {
    if (onReject) {
      onReject(patch?.id, rejectReason || 'Rejected during code review');
      setShowRejectModal(false);
    }
  };

  const handleApply = () => {
    if (!isApproved) return;
    if (onApply) {
      onApply(patch?.id);
    }
  };

  return (
    <div className="space-y-4 rounded-2xl bg-slate-900/80 border border-slate-800 p-5 font-sans">
      {/* 1. Header & Review State Badge */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <FileCode className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-100 font-mono tracking-tight">
                {patch?.id || 'patch_proposal'}
              </h3>
              {patch?.findingId && (
                <span className="text-[11px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800/60 border border-slate-700/60">
                  Finding: {patch.findingId}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Unified diff proposed for isolated temporary workspace remediation
            </p>
          </div>
        </div>

        {/* Status & Validation Badges */}
        <div className="flex items-center gap-2">
          {/* Validation badge */}
          {parsed.valid ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-emerald-950/40 text-emerald-400 border border-emerald-800/50">
              <FileCheck2 className="w-3.5 h-3.5" />
              DIFF_VALIDATED
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-red-950/40 text-red-400 border border-red-800/50">
              <AlertTriangle className="w-3.5 h-3.5" />
              MALFORMED_DIFF
            </span>
          )}

          {/* Review State Badge */}
          {isApproved && (
            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              <CheckCircle2 className="w-3.5 h-3.5" />
              APPROVED
            </span>
          )}
          {isRejected && (
            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-rose-500/15 text-rose-300 border border-rose-500/30">
              <XCircle className="w-3.5 h-3.5" />
              REJECTED
            </span>
          )}
          {isPending && (
            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
              <ShieldAlert className="w-3.5 h-3.5" />
              PENDING_REVIEW
            </span>
          )}
        </div>
      </div>

      {/* Invariant Check: Finding Association */}
      {hasFindingMismatch && (
        <div className="p-3.5 rounded-xl bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
          <span>
            <strong>Invariant Mismatch:</strong> Active target finding is <code className="bg-red-900/60 px-1 py-0.5 rounded text-white font-mono">{targetFindingId}</code>, but this patch was generated for finding <code className="bg-red-900/60 px-1 py-0.5 rounded text-white font-mono">{patch?.findingId}</code>. Patch approval and application are disabled.
          </span>
        </div>
      )}

      {/* 2. Gate Metrics & Affected Files */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Additions / Deletions Stats */}
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/70">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1 flex items-center justify-between">
            <span>Diff Statistics</span>
            <Layers className="w-3.5 h-3.5 text-slate-500" />
          </div>
          <div className="flex items-center gap-3 mt-1.5">
            <span className="inline-flex items-center gap-1 text-sm font-mono font-bold text-emerald-400">
              +{stats.additions} <span className="text-xs font-normal text-slate-500">additions</span>
            </span>
            <span className="inline-flex items-center gap-1 text-sm font-mono font-bold text-rose-400">
              -{stats.deletions} <span className="text-xs font-normal text-slate-500">deletions</span>
            </span>
          </div>
        </div>

        {/* Affected Files */}
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/70 md:col-span-2">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1 flex items-center justify-between">
            <span>Affected Files ({changedFiles.length})</span>
            <span className="text-[10px] text-emerald-400 font-mono">SCOPE_BOUNDED</span>
          </div>
          <div className="flex flex-wrap gap-1.5 mt-1">
            {changedFiles.map((file, idx) => (
              <span
                key={idx}
                className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700/80 truncate max-w-full"
              >
                {file}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* 3. Remediation Rationale Card */}
      <div className="p-4 rounded-xl bg-cyan-950/15 border border-cyan-800/30">
        <div className="flex items-center gap-2 mb-2">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-300 font-mono">
            Security Rationale & Behavior Assessment
          </h4>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed font-sans whitespace-pre-line">
          {rationale}
        </p>

        {patch?.evidenceReferences && patch.evidenceReferences.length > 0 && (
          <div className="mt-3 pt-3 border-t border-cyan-800/20">
            <span className="text-[11px] font-mono text-slate-400 block mb-1">
              Grounding Evidence References:
            </span>
            <div className="flex flex-wrap gap-2">
              {patch.evidenceReferences.map((ref, idx) => (
                <span
                  key={idx}
                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800"
                >
                  {typeof ref === 'object' ? ref.reference || ref.description || JSON.stringify(ref) : ref}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* 4. Syntax-Aware Diff Box */}
      <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden font-mono text-xs shadow-inner">
        {/* Diff Top Bar */}
        <div className="bg-slate-900/90 px-4 py-2 border-b border-slate-800 text-slate-400 flex items-center justify-between text-[11px]">
          <div className="flex items-center gap-2">
            <span className="text-rose-400 font-mono">--- a/{parsed.files[0]?.oldFile || 'original'}</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className="text-emerald-400 font-mono">+++ b/{parsed.files[0]?.newFile || 'patched'}</span>
          </div>
          <span className="text-slate-500">{parsed.hunks.length} hunk(s)</span>
        </div>

        {/* Diff Content Lines */}
        <div className="p-3 overflow-x-auto space-y-0.5 divide-y divide-transparent">
          {parsed.hunks.length === 0 ? (
            <div className="p-4 text-center text-slate-500 italic">No diff hunks to display.</div>
          ) : (
            parsed.hunks.map((hunk, hIdx) => (
              <div key={hIdx} className="mb-3 last:mb-0">
                {/* Hunk Header */}
                <div className="py-1 px-2.5 rounded bg-slate-900 text-cyan-400 text-[11px] font-mono border-l-2 border-cyan-500 mb-1 select-none">
                  {hunk.raw}
                </div>

                {/* Hunk Lines */}
                <div className="space-y-0.5 font-mono">
                  {hunk.lines.map((line, lIdx) => {
                    const isAdd = line.type === 'add';
                    const isDel = line.type === 'delete';
                                        const isMeta = line.type === 'meta';

                    let rowBg = 'hover:bg-slate-900/40 text-slate-300';
                    let textClass = 'text-slate-300';
                    let prefixColor = 'text-slate-600';

                    if (isAdd) {
                      rowBg = 'bg-emerald-950/40 hover:bg-emerald-950/60 text-emerald-200';
                      textClass = 'text-emerald-300';
                      prefixColor = 'text-emerald-400 font-bold';
                    } else if (isDel) {
                      rowBg = 'bg-rose-950/40 hover:bg-rose-950/60 text-rose-200';
                      textClass = 'text-rose-300';
                      prefixColor = 'text-rose-400 font-bold';
                    } else if (isMeta) {
                      rowBg = 'bg-slate-900/60 text-slate-500 italic';
                    }

                    return (
                      <div
                        key={lIdx}
                        className={`flex items-start px-2 py-0.5 rounded transition-colors ${rowBg}`}
                      >
                        {/* Old Line Number */}
                        <span className="w-9 text-right pr-2 text-[10px] text-slate-600 select-none">
                          {line.oldLineNumber || ''}
                        </span>
                        {/* New Line Number */}
                        <span className="w-9 text-right pr-3 text-[10px] text-slate-600 select-none border-r border-slate-800">
                          {line.newLineNumber || ''}
                        </span>
                        {/* Prefix */}
                        <span className={`w-5 text-center select-none ${prefixColor}`}>
                          {line.prefix || ' '}
                        </span>
                        {/* Code Content */}
                        <span className={`flex-1 whitespace-pre-wrap break-all ${textClass}`}>
                          {line.content || ' '}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* 5. Human Approval Gate & Action Controls */}
      {!readOnly && (
        <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/90 mt-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                  Human Approval Gate
                </h4>
              </div>
              <p className="text-[11px] text-slate-400 max-w-lg">
                Strict Security Invariant: No automated patch application without explicit human review
                and sign-off. Patches apply strictly to disposable temporary workspaces.
              </p>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center gap-2.5 w-full sm:w-auto">
              {isPending && (
                <>
                  <button
                    type="button"
                    onClick={handleApprove}
                    disabled={isLoading || !parsed.valid || stats.totalChanges === 0 || hasFindingMismatch}
                    className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold shadow-md transition-all cursor-pointer"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    Approve Patch
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowRejectModal(true)}
                    disabled={isLoading}
                    className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-800 hover:bg-rose-950/60 hover:text-rose-300 text-slate-300 text-xs font-semibold border border-slate-700/60 transition-all cursor-pointer"
                  >
                    <XCircle className="w-4 h-4" />
                    Reject
                  </button>
                </>
              )}

              {isApproved && (
                <button
                  type="button"
                  onClick={handleApply}
                  disabled={isLoading || hasFindingMismatch}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-bold shadow-lg shadow-cyan-950 transition-all cursor-pointer"
                >
                  <ShieldCheck className="w-4 h-4" />
                  Apply to Disposable Workspace
                </button>
              )}

              {isRejected && (
                <button
                  type="button"
                  onClick={handleApprove}
                  disabled={isLoading}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 cursor-pointer"
                >
                  Re-evaluate & Approve
                </button>
              )}
            </div>
          </div>

          {/* Optional Approver Comment Input */}
          {isPending && (
            <div className="mt-3 pt-3 border-t border-slate-800/80">
              <input
                type="text"
                value={approverComments}
                onChange={(e) => setApproverComments(e.target.value)}
                placeholder="Optional review comment or audit rationale..."
                className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
          )}
        </div>
      )}

      {/* Reject Modal */}
      {showRejectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4">
          <div className="w-full max-w-md rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <XCircle className="w-5 h-5 text-rose-400" />
              Reject Patch Proposal
            </h3>
            <p className="text-xs text-slate-400">
              Provide an optional reason for discarding this patch proposal. The finding will remain in its
              current state for alternate remediation.
            </p>
            <textarea
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              placeholder="e.g. Needs parameterized query instead of regex escaping..."
              rows={3}
              className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-rose-500"
            />
            <div className="flex items-center justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setShowRejectModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleReject}
                className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold"
              >
                Confirm Rejection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

