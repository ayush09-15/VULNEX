import { ArrowRight, AlertCircle } from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';

export default function FindingsTable({ findings = [], onSelectFinding, selectedFindingId = null }) {
  if (findings.length === 0) {
    return (
      <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800/80">
        <div className="w-12 h-12 rounded-2xl bg-slate-950 border border-slate-800 flex items-center justify-center mx-auto mb-3 text-slate-500">
          <AlertCircle className="w-6 h-6" />
        </div>
        <h3 className="text-sm font-bold text-slate-200 mb-1">No Matching Vulnerabilities</h3>
        <p className="text-xs text-slate-400 max-w-sm mx-auto">
          No findings match the current filter criteria or search query. Adjust the filters above to inspect other records.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl bg-slate-900/60 border border-slate-800 overflow-hidden shadow-xl">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/40 text-slate-400 uppercase font-mono tracking-wider">
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Vulnerability / Rule</th>
              <th className="py-3 px-4">Location</th>
              <th className="py-3 px-4">Scanner</th>
              <th className="py-3 px-4">Confidence</th>
              <th className="py-3 px-4">Remediation Status</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {findings.map((finding) => {
              const isSelected = selectedFindingId === finding.id;

              return (
                <tr
                  key={finding.id}
                  onClick={() => onSelectFinding?.(finding)}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-cyan-950/20 border-l-2 border-l-cyan-400'
                      : 'hover:bg-slate-800/40'
                  }`}
                >
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <SeverityBadge severity={finding.severity} />
                  </td>

                  <td className="py-3.5 px-4 font-sans font-medium text-slate-200">
                    <div className="max-w-md truncate" title={finding.title}>
                      {finding.title}
                    </div>
                    {finding.ruleId && (
                      <div className="text-[11px] text-cyan-400/90 font-mono mt-0.5 truncate">
                        {finding.ruleId}
                      </div>
                    )}
                  </td>

                  <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                    <code className="text-cyan-400/90 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                      {finding.filePath}:{finding.startLine || 1}
                    </code>
                  </td>

                  <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                    <span className="uppercase text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold border border-slate-700">
                      {finding.scanner}
                    </span>
                  </td>

                  <td className="py-3.5 px-4 text-slate-300 whitespace-nowrap">
                    <span
                      className={`text-[11px] font-semibold ${
                        finding.confidence === 'HIGH'
                          ? 'text-emerald-400'
                          : finding.confidence === 'MEDIUM'
                          ? 'text-amber-400'
                          : 'text-slate-400'
                      }`}
                    >
                      {finding.confidence || 'MEDIUM'}
                    </span>
                  </td>

                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-mono font-medium border ${
                        finding.status === 'VERIFIED'
                          ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40'
                          : finding.status === 'PATCH_PROPOSED'
                          ? 'bg-cyan-950/40 text-cyan-400 border-cyan-800/40'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {finding.status}
                    </span>
                  </td>

                  <td className="py-3.5 px-4 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectFinding?.(finding);
                      }}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-cyan-600 hover:text-white text-slate-300 transition-colors font-sans text-xs font-medium"
                    >
                      <span>Inspect</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
