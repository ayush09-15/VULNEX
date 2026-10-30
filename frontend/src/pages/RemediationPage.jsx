import { CheckCircle2 } from 'lucide-react';

export default function RemediationPage() {
  return (
    <div className="space-y-6 animate-fadeIn">
      <div>
        <h1 className="text-2xl font-extrabold text-slate-100">Remediation & Patch Studio</h1>
        <p className="text-xs text-slate-400 mt-1">
          Review generated unified diffs, validate path boundaries, and apply to disposable test workspaces
        </p>
      </div>

      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 font-mono">
              Patch Proposal: patch_sql_fix_01
            </h2>
          </div>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800/40">
            VALIDATED_DIFF
          </span>
        </div>

        {/* Diff preview box */}
        <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden font-mono text-xs mb-6">
          <div className="bg-slate-900 px-4 py-2 border-b border-slate-800 text-slate-400 flex items-center justify-between">
            <span>--- a/src/routes/user.js</span>
            <span>+++ b/src/routes/user.js</span>
          </div>
          <div className="p-4 space-y-1 text-slate-300 overflow-x-auto">
            <div className="text-slate-500">@@ -22,5 +22,5 @@ router.get('/profile', async (req, res) =&gt; &#123;</div>
            <div className="text-slate-400">{"   const { id } = req.query;"}</div>
            <div className="bg-red-950/40 text-red-300 px-2 py-0.5 rounded -mx-2">
              {"-  const query = `SELECT * FROM users WHERE id = '${id}'`;"}
            </div>
            <div className="bg-emerald-950/40 text-emerald-300 px-2 py-0.5 rounded -mx-2">
              {"+  const query = 'SELECT * FROM users WHERE id = $1';"}
            </div>
            <div className="text-slate-400">{"   const user = await db.query(query, [id]);"}</div>
          </div>
        </div>

        {/* Verification Status */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 mb-6">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 font-mono">
            Verification Evidence (Targeted Regression Test + Re-Scan)
          </h3>
          <div className="space-y-2 text-xs font-mono">
            <div className="flex items-center gap-2 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
              <span>Targeted test suite passed: node --test test/routes/user.test.js (Exit code 0)</span>
            </div>
            <div className="flex items-center gap-2 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
              <span>Post-patch Semgrep re-scan: Target rule "sql-injection" no longer detected.</span>
            </div>
            <div className="flex items-center gap-2 text-slate-400">
              <span className="w-1.5 h-1.5 rounded-full bg-slate-500 ml-1.5 mr-0.5" />
              <span>Original repository workspace untouched (disposable copy verified).</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-all">
            Apply Patch to Workspace
          </button>
          <button className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-all">
            Discard Patch
          </button>
        </div>
      </div>
    </div>
  );
}
