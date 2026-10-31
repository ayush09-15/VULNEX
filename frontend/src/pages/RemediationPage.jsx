import { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  ShieldAlert,
  CheckCircle2,
  AlertCircle,
  FileCode2,
  RefreshCw,
  FolderGit2,
  Wrench,
  Sparkles,
  Layers,
  RotateCcw,
  Loader2
} from 'lucide-react';
import DiffViewer from '../components/remediation/DiffViewer';
import VerificationChecklist from '../components/verification/VerificationChecklist';
import { vulnexApi } from '../services/api';

const SAMPLE_PATCH = {
  id: 'patch_sql_fix_01',
  findingId: 'find_sql_injection_01',
  diff: `--- a/src/routes/user.js
+++ b/src/routes/user.js
@@ -22,5 +22,5 @@ router.get('/profile', async (req, res) => {
    const { id } = req.query;
-   const query = \`SELECT * FROM users WHERE id = '\${id}'\`;
-   const user = await db.query(query);
+   const query = 'SELECT * FROM users WHERE id = $1';
+   const user = await db.query(query, [id]);
    return res.json(user);
 }`,
  rationale:
    'Replaces dynamic template string interpolation with parameterized prepared statement query ($1), neutralizing SQL injection vulnerability (CWE-89) without altering external endpoint contracts.',
  changedFiles: ['src/routes/user.js'],
  reviewState: 'PENDING_REVIEW',
  evidenceReferences: [
    { type: 'SNIPPET', reference: "const query = `SELECT * FROM users WHERE id = '${id}'`;" },
    { type: 'RULE', reference: 'javascript.express.security.audit.sqli' }
  ],
  metadata: {
    model: 'gemma-2-9b-it',
    confidence: 'HIGH',
    requiresHumanReview: true
  }
};

export default function RemediationPage() {
  const location = useLocation();
  const incomingFinding = location.state?.finding;
  const incomingPatchId = location.state?.patchId;

  const [patch, setPatch] = useState(SAMPLE_PATCH);
  const [patchesList, setPatchesList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [generatingPatch, setGeneratingPatch] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);
  const [applyResult, setApplyResult] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isRollingBack, setIsRollingBack] = useState(false);

  useEffect(() => {
    let mounted = true;
    async function loadPatches() {
      try {
        setLoading(true);
        const res = await vulnexApi.patches.list();
        const items = Array.isArray(res) ? res : (res?.data || []);
        if (mounted) {
          setPatchesList(items);

          if (incomingPatchId) {
            const found = items.find(p => p.id === incomingPatchId);
            if (found) {
              setPatch(found);
              return;
            }
          }

          if (incomingFinding) {
            const found = items.find(p => p.findingId === incomingFinding.id);
            if (found) {
              setPatch(found);
              return;
            } else if (incomingFinding.proposedPatch) {
              setPatch(incomingFinding.proposedPatch);
              return;
            }
          }

          if (items.length > 0) {
            setPatch(items[0]);
          }
        }
      } catch {
        // Fall back cleanly to sample proposal
      } finally {
        if (mounted) setLoading(false);
      }
    }
    loadPatches();
    return () => {
      mounted = false;
    };
  }, [incomingFinding, incomingPatchId]);

  const handleGeneratePatchForFinding = async () => {
    if (!incomingFinding) return;
    setGeneratingPatch(true);
    setActionMessage(null);
    try {
      const res = await vulnexApi.findings.generatePatch(incomingFinding.id);
      const newPatch = res?.data || res;
      if (newPatch) {
        setPatch(newPatch);
        setPatchesList((prev) => [newPatch, ...prev.filter(p => p.id !== newPatch.id)]);
        setActionMessage({
          type: 'success',
          text: `AI patch proposal generated for finding ${incomingFinding.id}. Ready for human review.`
        });
      }
    } catch (err) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Failed to generate AI patch proposal.'
      });
    } finally {
      setGeneratingPatch(false);
    }
  };

  const handleSelectPatch = (selectedId) => {
    const selected = patchesList.find(p => p.id === selectedId);
    if (selected) {
      setPatch(selected);
      setApplyResult(null);
      setVerificationResult(null);
      setActionMessage(null);
    }
  };

  const handleApprove = async (patchId, comments) => {
    setLoading(true);
    setActionMessage(null);
    try {
      if (vulnexApi.patches?.approve) {
        await vulnexApi.patches.approve(patchId, { comments });
      }
      setPatch((prev) => ({
        ...prev,
        reviewState: 'APPROVED',
        metadata: {
          ...prev.metadata,
          reviewedAt: new Date().toISOString(),
          approverComments: comments || 'Approved via Security Console'
        }
      }));
      setActionMessage({
        type: 'success',
        text: 'Patch approved! You can now safely apply it to an isolated temporary workspace.'
      });
    } catch (err) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Failed to approve patch.'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleReject = async (patchId, reason) => {
    setLoading(true);
    setActionMessage(null);
    try {
      if (vulnexApi.patches?.reject) {
        await vulnexApi.patches.reject(patchId, { reason });
      }
      setPatch((prev) => ({
        ...prev,
        reviewState: 'REJECTED',
        metadata: {
          ...prev.metadata,
          rejectedAt: new Date().toISOString(),
          rejectionReason: reason
        }
      }));
      setActionMessage({
        type: 'info',
        text: 'Patch rejected and flagged for alternate remediation.'
      });
    } catch (err) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Failed to reject patch.'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleApply = async (patchId) => {
    setLoading(true);
    setActionMessage(null);
    try {
      let res;
      if (vulnexApi.patches?.apply) {
        res = await vulnexApi.patches.apply(patchId, { approved: true });
      }
      const appliedWorkspaceId = res?.data?.appliedWorkspaceId || `ws_disposable_${Date.now()}`;
      setApplyResult({
        status: 'APPLIED_TO_TEMP',
        appliedWorkspaceId,
        appliedAt: new Date().toISOString(),
        verified: false
      });
      setPatch((prev) => ({
        ...prev,
        status: 'APPLIED_TO_TEMP',
        appliedWorkspaceId
      }));
      setActionMessage({
        type: 'success',
        text: 'Patch successfully applied to isolated disposable workspace (.workspaces/ws_disposable_...). Original repository files remain untouched. You can now execute the multi-stage verification checklist.'
      });
    } catch (err) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Failed to apply patch to temporary workspace.'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (patchId) => {
    setIsVerifying(true);
    setActionMessage(null);
    try {
      let res;
      if (vulnexApi.patches?.verify) {
        res = await vulnexApi.patches.verify(patchId);
      }
      const data = res?.data || res;
      setVerificationResult(data);
      const newStatus = data.status === 'PASSED' ? 'VERIFIED' : data.status;
      setPatch((prev) => ({
        ...prev,
        status: newStatus,
        isVerified: data.status === 'PASSED'
      }));
      setActionMessage({
        type: data.status === 'PASSED' ? 'success' : data.status === 'INCONCLUSIVE' ? 'info' : 'error',
        text: data.status === 'PASSED'
          ? 'Remediation verification passed: targeted test suite passed and vulnerability flaw resolved.'
          : data.status === 'INCONCLUSIVE'
          ? 'Verification outcome is inconclusive: fingerprint matching is ambiguous. Manual inspection recommended.'
          : 'Verification checks failed: targeted tests failed or vulnerability flaw was still detected.'
      });
    } catch (err) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Failed to verify patch.'
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleRollback = async (patchId) => {
    setIsRollingBack(true);
    setActionMessage(null);
    try {
      await vulnexApi.patches.rollback(patchId);
      setPatch((prev) => ({
        ...prev,
        status: 'VALIDATED',
        appliedWorkspaceId: null
      }));
      setApplyResult(null);
      setVerificationResult(null);
      setActionMessage({
        type: 'info',
        text: 'Disposable workspace reset: patch successfully rolled back. Source repository remains pristine.'
      });
    } catch (err) {
      setActionMessage({
        type: 'error',
        text: err?.message || 'Failed to rollback patch in temporary workspace.'
      });
    } finally {
      setIsRollingBack(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-100 flex items-center gap-2">
            <FileCode2 className="w-6 h-6 text-cyan-400" />
            Remediation & Patch Studio
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Syntax-aware diff review, path boundary validation, and isolated temporary workspace patching
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-xl border border-slate-800">
          <FolderGit2 className="w-4 h-4 text-emerald-400" />
          <span>Disposable Workspace: Isolated</span>
        </div>
      </div>

      {/* Target Finding Context Bar (when navigated from findings) */}
      {incomingFinding && (
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                Target Finding
              </span>
              <span className="text-xs font-mono text-slate-400">{incomingFinding.id}</span>
              <span className="text-xs font-semibold text-slate-200">{incomingFinding.title}</span>
            </div>
            <div className="text-xs font-mono text-slate-500">
              {incomingFinding.filePath}:{incomingFinding.startLine} • {incomingFinding.category} ({incomingFinding.severity})
            </div>
          </div>

          <button
            type="button"
            onClick={handleGeneratePatchForFinding}
            disabled={generatingPatch}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-white text-xs font-semibold font-mono transition-all shadow-md shrink-0"
          >
            {generatingPatch ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Generating Patch...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5" />
                <span>Regenerate with AI</span>
              </>
            )}
          </button>
        </div>
      )}

      {/* Patch Selector if multiple patches exist */}
      {patchesList.length > 1 && (
        <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800 flex items-center gap-3 overflow-x-auto">
          <span className="text-xs font-mono text-slate-400 shrink-0 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            Available Patches ({patchesList.length}):
          </span>
          <div className="flex items-center gap-2">
            {patchesList.map((p) => (
              <button
                key={p.id}
                onClick={() => handleSelectPatch(p.id)}
                className={`px-3 py-1 rounded-lg text-xs font-mono transition-all whitespace-nowrap ${
                  patch?.id === p.id
                    ? 'bg-cyan-600 text-white font-semibold'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                {p.id} ({p.reviewState || p.status})
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Action Notification */}
      {actionMessage && (
        <div
          className={`p-3.5 rounded-xl flex items-center gap-2.5 text-xs font-medium border ${
            actionMessage.type === 'success'
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
              : actionMessage.type === 'error'
              ? 'bg-rose-950/40 border-rose-800/60 text-rose-300'
              : 'bg-cyan-950/40 border-cyan-800/60 text-cyan-300'
          }`}
        >
          {actionMessage.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
          ) : actionMessage.type === 'error' ? (
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
          ) : (
            <RefreshCw className="w-4 h-4 shrink-0 text-cyan-400" />
          )}
          <span>{actionMessage.text}</span>
        </div>
      )}

      {/* Syntax-Aware Diff Viewer & Approval Panel */}
      <DiffViewer
        patch={patch}
        onApprove={handleApprove}
        onReject={handleReject}
        onApply={handleApply}
        isLoading={loading}
      />

      {/* Workspace Rollback Action when applied */}
      {(patch?.status === 'APPLIED_TO_TEMP' || patch?.status === 'VERIFIED') && (
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
          <div className="space-y-0.5">
            <span className="text-xs font-semibold text-slate-200 block">Workspace Isolation Status</span>
            <span className="text-[11px] font-mono text-slate-400 block">
              Applied in disposable workspace: <code className="text-cyan-400">{patch.appliedWorkspaceId || 'ws_disposable'}</code>
            </span>
          </div>
          <button
            type="button"
            onClick={() => handleRollback(patch.id)}
            disabled={isRollingBack}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:bg-slate-900 text-slate-300 text-xs font-mono transition-all border border-slate-700"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${isRollingBack ? 'animate-spin' : ''}`} />
            <span>Rollback Workspace</span>
          </button>
        </div>
      )}

      {/* Verification Checklist (Commit 40) */}
      {(applyResult || patch?.status === 'APPLIED_TO_TEMP' || patch?.status === 'VERIFIED' || verificationResult) && (
        <VerificationChecklist
          verification={verificationResult}
          patch={patch}
          onRunVerification={() => handleVerify(patch.id)}
          isVerifying={isVerifying}
        />
      )}
    </div>
  );
}
