import { useState } from 'react';
import { Play } from 'lucide-react';

export default function ScanPage() {
  const [targetType, setTargetType] = useState('GITHUB');
  const [gitUrl, setGitUrl] = useState('');
  const [refName, setRefName] = useState('main');

  return (
    <div className="space-y-6 animate-fadeIn">
      <div>
        <h1 className="text-2xl font-extrabold text-slate-100">Scan Engine</h1>
        <p className="text-xs text-slate-400 mt-1">
          Launch deterministic SAST and dependency audits with strict SSRF & traversal guards
        </p>
      </div>

      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 max-w-2xl">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-4">
          Initiate Repository Scan
        </h2>
        
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5 font-mono">
              Source Intake Mode
            </label>
            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => setTargetType('GITHUB')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                  targetType === 'GITHUB'
                    ? 'bg-cyan-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                GitHub HTTPS URL
              </button>
              <button
                type="button"
                onClick={() => setTargetType('ZIP')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                  targetType === 'ZIP'
                    ? 'bg-cyan-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                ZIP Archive Upload
              </button>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5 font-mono">
              Repository URL
            </label>
            <input
              type="text"
              value={gitUrl}
              onChange={(e) => setGitUrl(e.target.value)}
              placeholder="https://github.com/org/repo"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5 font-mono">
              Git Reference (Branch or Tag)
            </label>
            <input
              type="text"
              value={refName}
              onChange={(e) => setRefName(e.target.value)}
              placeholder="main"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="pt-2">
            <button
              type="button"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-all"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>Start Deterministic Scan</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
