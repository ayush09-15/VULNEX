import { Server, Lock } from 'lucide-react';

export default function SettingsPage() {
  return (
    <div className="space-y-6 animate-fadeIn">
      <div>
        <h1 className="text-2xl font-extrabold text-slate-100">Console Settings</h1>
        <p className="text-xs text-slate-400 mt-1">
          Inspection parameters, retention limits, and API boundary configurations
        </p>
      </div>

      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 max-w-2xl space-y-6">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            Backend & Security Environment
          </h2>
          <div className="space-y-3 text-xs font-mono">
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-400">API Endpoint Base</span>
              <span className="text-slate-200">http://localhost:5001/api</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-400">Disposable Workspace Root</span>
              <span className="text-slate-200">./.workspaces/</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-400">Max Upload Size</span>
              <span className="text-slate-200">25 MB (MAX_UPLOAD_MB)</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-400">Scan Timeout</span>
              <span className="text-slate-200">120 Seconds</span>
            </div>
          </div>
        </div>

        <div className="pt-4 border-t border-slate-800 flex items-center gap-2 text-xs text-slate-500 font-mono">
          <Lock className="w-3.5 h-3.5 text-emerald-400" />
          <span>Server-side secrets remain strictly protected and never exposed to the client browser.</span>
        </div>
      </div>
    </div>
  );
}
