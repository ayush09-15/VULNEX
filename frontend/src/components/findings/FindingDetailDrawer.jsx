import { useState, useEffect } from 'react';
import {
  X,
  Sparkles,
  Terminal,
  FileCode,
  Wrench,
  CheckCircle2,
  Copy,
  Loader2,
  AlertTriangle
} from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';
import InvestigationResultPanel from './InvestigationResultPanel';
import vulnexApi from '../../services/api';

export default function FindingDetailDrawer({
  finding,
  onClose,
  onUpdateFinding,
  onNavigateToPatch
}) {
  const [investigating, setInvestigating] = useState(false);
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  // Fetch enriched details (sourceContext lines and persisted investigation) on mount / change
  useEffect(() => {
    let isMounted = true;
    if (finding?.id && !finding.sourceContext) {
      vulnexApi.findings.get(finding.id)
        .then((fullFinding) => {
          const item = fullFinding?.data || fullFinding;
          if (isMounted && item && (item.sourceContext || item.investigation)) {
            onUpdateFinding?.(finding.id, {
              ...(item.sourceContext ? { sourceContext: item.sourceContext } : {}),
              ...(item.investigation ? { investigation: item.investigation, aiInvestigation: item.investigation } : {})
            });
          }
        })
        .catch(() => {});
    }
    return () => { isMounted = false; };
  }, [finding?.id]);

  if (!finding) return null;

  const handleCopyFingerprint = () => {
    if (finding.fingerprint) {
      navigator.clipboard.writeText(finding.fingerprint);
      setCopiedFingerprint(true);
      setTimeout(() => setCopiedFingerprint(false), 2000);
    }
  };

  const handleRunInvestigation = async () => {
    setInvestigating(true);
    setErrorMsg(null);
    try {
      const res = await vulnexApi.findings.investigate(finding.id);
      const invData = res?.data || res;
      if (invData && (invData.id || invData.assessment)) {
        onUpdateFinding?.(finding.id, {
          investigation: invData,
          aiInvestigation: invData,
          status: 'TRIAGED'
        });
      } else {
        setErrorMsg('Investigation returned empty or unrecognized payload.');
      }
    } catch (err) {
      setErrorMsg(err.message || 'AI investigation failed.');
    } finally {
      setInvestigating(false);
    }
  };

  // Support both canonical 'investigation' and legacy 'aiInvestigation' property names
  const ai = finding.investigation || finding.aiInvestigation;

  const rawEvidence = typeof finding.evidence === 'string'
    ? finding.evidence
    : (finding.codeSnippet || (finding.evidence ? JSON.stringify(finding.evidence) : ''));

  return (
    <div
      className="fixed inset-y-0 right-0 z-40 w-full max-w-2xl bg-slate-950/95 backdrop-blur-xl border-l border-slate-800 shadow-2xl flex flex-col font-sans transition-all duration-300 animate-slideInRight"
      role="dialog"
      aria-label="Finding Details Drawer"
    >
      {/* Drawer Header */}
      <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-900/40">
        <div className="space-y-2 pr-6 flex-1">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={finding.severity} size="md" />
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              {finding.status}
            </span>
            <span className="text-xs font-mono text-slate-500 truncate">
              {finding.id}
            </span>
          </div>

          <h2 className="text-base font-bold text-slate-100 leading-snug">
            {finding.title}
          </h2>

          <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
            <span className="text-cyan-400">{finding.filePath}:{finding.startLine}</span>
            <span>•</span>
            <span className="uppercase text-slate-400">{finding.scanner}</span>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
          title="Close Drawer"
          aria-label="Close Drawer"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Drawer Content */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
        {/* Error Alert if any */}
        {errorMsg && (
          <div className="p-3.5 rounded-xl bg-red-950/50 border border-red-800/60 text-red-300 font-mono flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* =================================================================== */}
        {/* SECTION 1: DETERMINISTIC SCANNER FACTS (IMMUTABLE GROUND TRUTH) */}
        {/* =================================================================== */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono font-bold text-slate-300 uppercase tracking-wider text-[11px]">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>1. Scanner Evidence & Coordinate Facts</span>
            </div>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
              Deterministic Output
            </span>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="grid grid-cols-2 gap-3 font-mono text-[11px]">
              <div>
                <span className="text-slate-500 block">Scanner Tool:</span>
                <span className="text-slate-200 uppercase font-semibold">{finding.scanner}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Rule Identifier:</span>
                <span className="text-cyan-400 truncate block" title={finding.ruleId}>
                  {finding.ruleId || 'N/A'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Target Coordinate:</span>
                <span className="text-slate-200">
                  {finding.filePath} (Line {finding.startLine}{finding.endLine && finding.endLine !== finding.startLine ? `-${finding.endLine}` : ''})
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Scanner Confidence:</span>
                <span className="text-amber-400 font-semibold">{finding.confidence || 'MEDIUM'}</span>
              </div>
            </div>

            {/* Stable Normalized Fingerprint */}
            {finding.fingerprint && (
              <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-500">Fingerprint:</span>
                <div className="flex items-center gap-2">
                  <code className="text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800 truncate max-w-[240px]">
                    {finding.fingerprint}
                  </code>
                  <button
                    onClick={handleCopyFingerprint}
                    className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                    title="Copy Fingerprint"
                  >
                    {copiedFingerprint ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            )}

            {/* Raw Message */}
            <div className="pt-2 border-t border-slate-800 font-mono">
              <span className="text-slate-500 block mb-1">Scanner Message:</span>
              <p className="text-slate-300 bg-slate-950 p-2.5 rounded-lg border border-slate-800/80 leading-relaxed">
                {finding.message || 'Rule pattern matched AST syntax in source.'}
              </p>
            </div>
          </div>
        </div>

        {/* Source Code Evidence Panel: Real code lines from workspace or evidence */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 font-mono font-bold text-slate-300 uppercase tracking-wider text-[11px]">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <span>Source Code Context</span>
          </div>

          <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden font-mono text-[11px]">
            <div className="bg-slate-900/80 px-4 py-1.5 border-b border-slate-800 text-slate-400 flex items-center justify-between">
              <span>{finding.filePath}</span>
              <span className="text-cyan-400 font-bold">Line {finding.startLine}</span>
            </div>
            <div className="p-3 text-slate-300 space-y-1 overflow-x-auto">
              {finding.sourceContext?.lines && finding.sourceContext.lines.length > 0 ? (
                finding.sourceContext.lines.map((l) => (
                  <div
                    key={l.line}
                    className={
                      l.isTarget
                        ? "bg-red-950/40 text-red-300 px-2 py-1 rounded -mx-1 border-l-2 border-red-500 flex items-center justify-between font-mono"
                        : "text-slate-500 font-mono"
                    }
                  >
                    <span>{l.line} |   {l.content}</span>
                    {l.isTarget && (
                      <span className="text-[10px] text-red-400 font-bold uppercase ml-2 flex-shrink-0">Vulnerable Sink</span>
                    )}
                  </div>
                ))
              ) : rawEvidence ? (
                <div className="bg-red-950/40 text-red-300 px-2 py-1 rounded -mx-1 border-l-2 border-red-500 flex items-center justify-between font-mono">
                  <span>{finding.startLine} |   {rawEvidence}</span>
                  <span className="text-[10px] text-red-400 font-bold uppercase ml-2 flex-shrink-0">Vulnerable Sink</span>
                </div>
              ) : (
                <div className="text-slate-500 italic p-1">
                  No source excerpt captured for this finding.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* =================================================================== */}
        {/* SECTION 2: CONTEXTUAL AI INVESTIGATION (EXPLICITLY SEPARATED) */}
        {/* =================================================================== */}
        <div className="space-y-3 pt-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono font-bold text-cyan-400 uppercase tracking-wider text-[11px]">
              <Sparkles className="w-4 h-4" />
              <span>2. AI Investigation & Reasoning</span>
            </div>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950/40 text-cyan-400 border border-cyan-800/40">
              Probabilistic Assessment
            </span>
          </div>

          {ai ? (
            <InvestigationResultPanel
              investigation={ai}
              onReinvestigate={handleRunInvestigation}
              loading={investigating}
            />
          ) : (
            <div className="p-6 text-center rounded-2xl bg-slate-900/40 border border-slate-800 space-y-3">
              <p className="text-slate-400 text-xs">
                No AI investigation record exists for this finding yet. Run contextual analysis to evaluate exploitability, preconditions, and impact.
              </p>
              <button
                type="button"
                onClick={handleRunInvestigation}
                disabled={investigating}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-white font-semibold text-xs transition-colors shadow-md shadow-cyan-950/40"
              >
                {investigating ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Analyzing Bounded Context...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Investigate with AI</span>
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Drawer Footer Actions */}
      <div className="p-4 border-t border-slate-800 bg-slate-900/40 flex items-center justify-between">
        <button
          type="button"
          onClick={() => {
            onUpdateFinding?.(finding.id, { status: 'TRIAGED' });
          }}
          className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold font-mono transition-colors"
        >
          Mark Reviewed
        </button>

        <button
          type="button"
          onClick={() => {
            onNavigateToPatch?.(finding);
          }}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-950/40 transition-all"
        >
          <Wrench className="w-3.5 h-3.5" />
          <span>Generate Patch</span>
        </button>
      </div>
    </div>
  );
}
