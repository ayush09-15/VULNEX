import {
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  CheckCircle2,
  ListChecks,
  Lock,
  Layers,
  Info,
  Clock,
  RotateCcw
} from 'lucide-react';
import { formatInvestigationData } from '../../utils/investigationFormatter';

const ICON_MAP = {
  LIKELY_TRUE: ShieldAlert,
  UNCERTAIN: HelpCircle,
  LIKELY_FALSE: ShieldCheck,
};

export default function InvestigationResultPanel({
  investigation,
  onReinvestigate = null,
  loading = false,
}) {
  const data = formatInvestigationData(investigation);
  if (!data) return null;

  const AssessmentIcon = ICON_MAP[data.assessment] || HelpCircle;
  const meta = data.assessmentMeta;

  return (
    <div
      className={`rounded-2xl bg-slate-900/70 border ${meta.cardBorder} p-5 space-y-5 font-sans shadow-lg shadow-black/40`}
      aria-label="AI Investigation Results Panel"
    >
      {/* 1. Assessment Header & Confidence */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <div className={`p-2 rounded-xl ${meta.tagBg} ${meta.tagBorder} border`}>
            <AssessmentIcon className={`w-4 h-4 ${meta.tagText}`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span
                className={`font-mono font-bold text-xs px-2.5 py-0.5 rounded-full border ${meta.tagBg} ${meta.tagBorder} ${meta.tagText}`}
              >
                {data.assessment}
              </span>
              <span className="text-[11px] text-slate-400 font-medium hidden sm:inline">
                {meta.label}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-0.5">{meta.description}</p>
          </div>
        </div>

        {/* Confidence & Re-investigate trigger */}
        <div className="flex items-center gap-3 self-end sm:self-auto font-mono text-xs">
          <div className="text-right">
            <span className="text-[10px] uppercase text-slate-500 block">AI Confidence</span>
            <span
              className={`font-bold ${
                data.confidence === 'HIGH'
                  ? 'text-emerald-400'
                  : data.confidence === 'LOW'
                  ? 'text-amber-400'
                  : 'text-cyan-400'
              }`}
            >
              {data.confidence}
            </span>
          </div>

          {onReinvestigate && (
            <button
              onClick={onReinvestigate}
              disabled={loading}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-50 transition-colors"
              title="Re-run AI Analysis"
              aria-label="Re-run AI Analysis"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* 2. Root Cause Analysis / Summary */}
      <div className="space-y-1.5">
        <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-slate-300">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span>Root Cause Diagnosis</span>
        </div>
        <p className="text-xs text-slate-200 leading-relaxed bg-slate-950/60 p-3 rounded-xl border border-slate-800/60">
          {data.summary}
        </p>
      </div>

      {/* 3. Evidence Points (Facts Extracted from Context) */}
      {data.evidence.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-slate-300">
            <ListChecks className="w-3.5 h-3.5 text-cyan-400" />
            <span>Extracted Code Evidence</span>
          </div>
          <div className="bg-slate-950/60 rounded-xl border border-slate-800/60 p-3 space-y-1.5">
            {data.evidence.map((item, idx) => (
              <div key={idx} className="flex items-start gap-2 text-xs text-slate-300 font-mono">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-500 mt-0.5 flex-shrink-0" />
                <span className="leading-snug">
                  {typeof item === 'object' && item !== null
                    ? (item.reference || item.evidence || item.text || JSON.stringify(item))
                    : String(item)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. Exploit Preconditions & Potential Impact Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* Preconditions */}
        <div className="space-y-1.5">
          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-slate-300">
            <Lock className="w-3.5 h-3.5 text-amber-400" />
            <span>Exploit Preconditions</span>
          </div>
          <div className="bg-slate-950/60 rounded-xl border border-slate-800/60 p-3 text-xs text-slate-300 space-y-1 min-h-[72px]">
            {data.preconditions.length > 0 ? (
              data.preconditions.map((item, idx) => (
                <div key={idx} className="flex items-start gap-1.5">
                  <span className="text-amber-500 font-bold">•</span>
                  <span>
                    {typeof item === 'object' && item !== null
                      ? (item.reference || item.evidence || item.text || JSON.stringify(item))
                      : String(item)}
                  </span>
                </div>
              ))
            ) : (
              <span className="text-slate-500 italic">No specific external preconditions noted.</span>
            )}
          </div>
        </div>

        {/* Potential Impact */}
        <div className="space-y-1.5">
          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-slate-300">
            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
            <span>Potential Impact</span>
          </div>
          <div className="bg-slate-950/60 rounded-xl border border-slate-800/60 p-3 text-xs text-slate-300 min-h-[72px]">
            <p className="leading-relaxed">{data.potentialImpact}</p>
          </div>
        </div>
      </div>

      {/* 5. Recommended Remediation Guidance */}
      {data.recommendedFix && (
        <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-800/40 space-y-1">
          <span className="text-[11px] font-mono font-bold uppercase text-cyan-400 tracking-wider block">
            Recommended Remediation
          </span>
          <p className="text-xs text-slate-200 leading-relaxed font-sans">
            {data.recommendedFix}
          </p>
        </div>
      )}

      {/* 6. Stated Limitations Disclosure */}
      {data.limitations.length > 0 && (
        <div className="p-3 rounded-xl bg-slate-950/40 border border-slate-800/60 space-y-1 text-[11px] font-mono text-slate-500">
          <div className="flex items-center gap-1.5 text-slate-400 font-semibold uppercase text-[10px] tracking-wider">
            <Info className="w-3 h-3 text-slate-400" />
            <span>Analysis Boundaries & Limitations</span>
          </div>
          <ul className="list-disc list-inside space-y-0.5 pt-0.5">
            {data.limitations.map((lim, idx) => (
              <li key={idx}>{lim}</li>
            ))}
          </ul>
        </div>
      )}

      {/* 7. Provenance & Metadata Footer */}
      <div className="pt-2 border-t border-slate-800/60 flex flex-wrap items-center justify-between gap-2 text-[10px] font-mono text-slate-500">
        <div className="flex items-center gap-2">
          <Layers className="w-3 h-3 text-cyan-500" />
          <span>Model: <strong className="text-slate-400">{data.model}</strong></span>
          <span>•</span>
          <span>Prompt: <strong className="text-slate-400">{data.promptVersion}</strong></span>
        </div>
        {data.createdAt && (
          <div className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            <span>{new Date(data.createdAt).toLocaleTimeString()}</span>
          </div>
        )}
      </div>
    </div>
  );
}
