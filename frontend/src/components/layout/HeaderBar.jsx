import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderGit2,
  GitBranch,
  Plus,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import vulnexApi from '../../services/api';

export default function HeaderBar({ collapsed, activeRepo }) {
  const navigate = useNavigate();
  const [backendStatus, setBackendStatus] = useState('checking'); // 'connected', 'offline', 'checking'
  const [lastPing, setLastPing] = useState(null);

  useEffect(() => {
    let isMounted = true;
    const checkHealth = async () => {
      try {
        await vulnexApi.health.check();
        if (isMounted) {
          setBackendStatus('connected');
          setLastPing(new Date().toLocaleTimeString());
        }
      } catch {
        if (isMounted) {
          setBackendStatus('offline');
        }
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 20000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <header
      className={`fixed top-0 right-0 z-20 h-16 bg-slate-950/80 backdrop-blur-md border-b border-slate-800/80 transition-all duration-300 flex items-center justify-between px-6 ${
        collapsed ? 'left-20' : 'left-64'
      }`}
    >
      {/* Left: Active Repository & Ref Context */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
          <FolderGit2 className="w-3.5 h-3.5 text-cyan-400" />
          <span className="font-semibold text-slate-200">
            {activeRepo?.displayName || 'No Repository Selected'}
          </span>
          <span className="text-slate-600">/</span>
          <span className="flex items-center gap-1 text-slate-400">
            <GitBranch className="w-3 h-3 text-slate-500" />
            {activeRepo?.defaultRef || 'main'}
          </span>
        </div>

        <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900/60 border border-slate-800/60 text-[11px] text-slate-400">
          <span className="text-slate-500">Target:</span>
          <span className="text-slate-300 font-mono">Node.js / Express</span>
        </div>
      </div>

      {/* Right: Backend API Status & Actions */}
      <div className="flex items-center gap-4">
        {/* API Status Pill */}
        <div
          className={`flex items-center gap-2 px-3 py-1 rounded-full border text-xs font-mono transition-colors ${
            backendStatus === 'connected'
              ? 'bg-emerald-950/40 border-emerald-800/50 text-emerald-400'
              : backendStatus === 'offline'
              ? 'bg-red-950/40 border-red-800/50 text-red-400'
              : 'bg-slate-900 border-slate-800 text-slate-400'
          }`}
          title={lastPing ? `Last ping: ${lastPing}` : 'Probing backend'}
        >
          {backendStatus === 'connected' ? (
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          ) : (
            <AlertCircle className="w-3.5 h-3.5" />
          )}
          <span className="capitalize">{backendStatus}</span>
        </div>

        {/* Start New Scan CTA */}
        <button
          onClick={() => navigate('/scan')}
          className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-950/40 focus:outline-none focus:ring-2 focus:ring-cyan-400 transition-all active:scale-95"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Scan</span>
        </button>
      </div>
    </header>
  );
}
