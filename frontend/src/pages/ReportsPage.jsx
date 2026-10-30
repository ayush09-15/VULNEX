import { FileText, Download } from 'lucide-react';

export default function ReportsPage() {
  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-100">Audit & Scan Reports</h1>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic security audit records, tool versions, and remediation verification receipts
          </p>
        </div>
        <button className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-all">
          <Download className="w-4 h-4" />
          <span>Export Verification Report (JSON)</span>
        </button>
      </div>

      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2 font-mono text-xs text-slate-300">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span>Audit Report: rep_scan_01JAZZ80</span>
          </div>
          <span className="text-xs font-mono text-slate-500">2026-10-31T03:15:00.000Z</span>
        </div>

        <div className="space-y-4 text-xs font-mono">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80">
            <div className="text-slate-400 mb-2 font-bold uppercase tracking-wider text-[11px]">
              Engine Provenance & Tool Versions
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-slate-300">
              <div>Semgrep CLI: 1.60.0</div>
              <div>npm audit: Node 20 / npm 10</div>
              <div>Gemini Model: gemini-2.5-pro</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
