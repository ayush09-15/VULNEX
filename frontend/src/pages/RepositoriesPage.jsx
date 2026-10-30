import { useState } from 'react';
import { FolderGit2, Plus, ShieldCheck } from 'lucide-react';

export default function RepositoriesPage() {
  const [repos] = useState([
    {
      id: 'repo_fixture_01',
      displayName: 'intentionally-vulnerable-node-app',
      sourceType: 'LOCAL_FIXTURE',
      sanitizedSourceUrl: 'fixtures/intentionally-vulnerable-node-app',
      defaultRef: 'main',
      latestScanStatus: 'COMPLETED',
      findingsCount: 4,
    },
    {
      id: 'repo_01JAZZ80001',
      displayName: 'juice-shop-sample',
      sourceType: 'GITHUB',
      sanitizedSourceUrl: 'https://github.com/juice-shop/juice-shop',
      defaultRef: 'main',
      latestScanStatus: 'COMPLETED',
      findingsCount: 12,
    },
  ]);

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-100">Repositories</h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage target repositories, branches, and bounded scan workspaces
          </p>
        </div>
        <button className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-all">
          <Plus className="w-4 h-4" />
          <span>Register Repository</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {repos.map((repo) => (
          <div
            key={repo.id}
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2 font-mono text-xs text-cyan-400">
                  <FolderGit2 className="w-4 h-4" />
                  <span className="font-semibold text-slate-200">{repo.displayName}</span>
                </div>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {repo.sourceType}
                </span>
              </div>
              <div className="text-xs font-mono text-slate-400 truncate mb-4">
                {repo.sanitizedSourceUrl}
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">
                Findings: <strong className="text-red-400">{repo.findingsCount}</strong>
              </span>
              <span className="text-emerald-400 flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5" />
                {repo.latestScanStatus}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
