import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  FileText,
  Download,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Cpu,
  Layers,
  CheckCircle2,
  XCircle,
  HelpCircle,
  MinusCircle,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  FolderGit2,
  Terminal,
  ExternalLink,
  Info
} from 'lucide-react';
import { vulnexApi } from '../services/api';
import VerificationChecklist, { StatusBadge } from '../components/verification/VerificationChecklist';
import DiffViewer from '../components/remediation/DiffViewer';

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-950/80 text-red-300 border-red-700/60',
  HIGH: 'bg-orange-950/80 text-orange-300 border-orange-700/60',
  MEDIUM: 'bg-amber-950/80 text-amber-300 border-amber-700/60',
  LOW: 'bg-blue-950/80 text-blue-300 border-blue-700/60',
  INFO: 'bg-slate-900 text-slate-400 border-slate-700/60',
};

const ASSESSMENT_COLORS = {
  LIKELY_TRUE: 'bg-rose-950/80 text-rose-300 border-rose-700/60',
  LIKELY_FALSE: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60',
  UNCERTAIN: 'bg-amber-950/80 text-amber-300 border-amber-700/60',
};

export default function ReportsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlScanId = searchParams.get('scanId');

  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(urlScanId || '');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedFindings, setExpandedFindings] = useState({});

  // 1. Fetch available scans
  useEffect(() => {
    let isMounted = true;
    async function loadScans() {
      try {
        const res = await vulnexApi.scans.list();
        const scanList = res?.data || res || [];
        if (isMounted) {
          setScans(scanList);
          if (!selectedScanId && scanList.length > 0) {
            const defaultId = scanList[scanList.length - 1].id;
            setSelectedScanId(defaultId);
            setSearchParams({ scanId: defaultId });
          }
        }
      } catch (err) {
        console.warn('Could not load scans list:', err);
      }
    }
    loadScans();
    return () => { isMounted = false; };
  }, []);

  // 2. Fetch Report for selected scan
  useEffect(() => {
    if (!selectedScanId) {
      setLoading(false);
      return;
    }

    let isMounted = true;
    async function loadReport() {
      setLoading(true);
      setError(null);
      try {
        const res = await vulnexApi.scans.getReport(selectedScanId);
        const reportData = res?.data || res;
        if (isMounted) {
          setReport(reportData);
        }
      } catch (err) {
        if (isMounted) {
          setError(err.message || `Failed to load report for scan ${selectedScanId}`);
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    loadReport();
    return () => { isMounted = false; };
  }, [selectedScanId]);

  const handleScanChange = (newScanId) => {
    setSelectedScanId(newScanId);
    setSearchParams({ scanId: newScanId });
  };

  const toggleFinding = (fId) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [fId]: !prev[fId],
    }));
  };

  const handleExportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnex-report-${report.scan?.id || selectedScanId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const scan = report?.scan;
  const tools = report?.tools || scan?.toolVersions || {};
  const findings = report?.findings || [];
  const summary = report?.summary || scan?.summary || {
    totalFindings: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    remediated: 0,
    inconclusive: 0,
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-6 h-6 text-cyan-400" />
            <h1 className="text-2xl font-extrabold text-slate-100 font-mono">
              Evidence-Backed Audit & Verification Reports
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic security audit records, tool versions, AI assessments, patch proposals, and verification receipts
          </p>
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          {/* Scan Selector */}
          {scans.length > 0 && (
            <select
              value={selectedScanId}
              onChange={(e) => handleScanChange(e.target.value)}
              className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-xl px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id} ({s.status}) - {s.ref || 'main'}
                </option>
              ))}
            </select>
          )}

          <button
            onClick={handleExportJson}
            disabled={!report || loading}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold shadow-md transition-all shrink-0"
          >
            <Download className="w-4 h-4" />
            <span>Export Report (JSON)</span>
          </button>
        </div>
      </div>

      {loading && (
        <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800">
          <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto mb-3" />
          <p className="text-xs font-mono text-slate-400">Loading consolidated security scan report...</p>
        </div>
      )}

      {error && !loading && (
        <div className="p-6 rounded-2xl bg-rose-950/20 border border-rose-800/60 text-xs font-mono text-rose-300 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
          <div>
            <div className="font-bold mb-1">Failed to retrieve scan report</div>
            <div>{error}</div>
          </div>
        </div>
      )}

      {!loading && !error && report && (
        <>
          {/* Executive Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 uppercase block mb-1">Total Findings</span>
              <span className="text-2xl font-bold font-mono text-slate-100">{summary.totalFindings}</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[11px] font-mono text-red-400 uppercase block mb-1">Critical</span>
              <span className="text-2xl font-bold font-mono text-red-400">{summary.critical}</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[11px] font-mono text-orange-400 uppercase block mb-1">High</span>
              <span className="text-2xl font-bold font-mono text-orange-400">{summary.high}</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[11px] font-mono text-amber-400 uppercase block mb-1">Medium</span>
              <span className="text-2xl font-bold font-mono text-amber-400">{summary.medium}</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[11px] font-mono text-emerald-400 uppercase block mb-1">Remediated</span>
              <span className="text-2xl font-bold font-mono text-emerald-400">{summary.remediated}</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[11px] font-mono text-amber-300 uppercase block mb-1">Inconclusive</span>
              <span className="text-2xl font-bold font-mono text-amber-300">{summary.inconclusive || 0}</span>
            </div>
          </div>

          {/* Engine Provenance & Tools (Acceptance Gate: Tools) */}
          <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                  Engine Provenance & Tool Versions
                </h2>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/40">
                Scan: {scan?.id}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
              {Object.entries(tools).map(([toolName, version]) => (
                <div key={toolName} className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400 uppercase font-semibold">{toolName}</span>
                  <span className="text-cyan-300">{String(version)}</span>
                </div>
              ))}
            </div>

            <div className="pt-2 flex flex-wrap items-center justify-between text-[11px] font-mono text-slate-500 gap-2">
              <span>Target Ref: <strong className="text-slate-300">{scan?.ref || 'main'}</strong></span>
              <span>Started: <strong className="text-slate-300">{scan?.startedAt || 'N/A'}</strong></span>
              <span>Completed: <strong className="text-slate-300">{scan?.completedAt || 'In Flight'}</strong></span>
            </div>
          </div>

          {/* Findings & Evidence Breakdown (Acceptance Gate: findings, AI, patch, checks) */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100 font-mono flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Findings & Remediation Verification Breakdown
              </h2>
              <span className="text-xs font-mono text-slate-400">
                {findings.length} {findings.length === 1 ? 'Finding' : 'Findings'} Recorded
              </span>
            </div>

            {findings.length === 0 ? (
              <div className="p-8 text-center rounded-2xl bg-slate-900/40 border border-slate-800 text-xs font-mono text-slate-400">
                No vulnerabilities were detected in this scan execution.
              </div>
            ) : (
              <div className="space-y-3">
                {findings.map((f) => {
                  const isExpanded = Boolean(expandedFindings[f.id]);
                  const sevClass = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.INFO;

                  return (
                    <div
                      key={f.id}
                      className="rounded-2xl border border-slate-800 bg-slate-900/60 overflow-hidden transition-colors hover:border-slate-700/80"
                    >
                      {/* Row Header */}
                      <div
                        onClick={() => toggleFinding(f.id)}
                        className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none"
                      >
                        <div className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase border ${sevClass}`}>
                              {f.severity}
                            </span>
                            <span className="text-xs font-bold text-slate-200 font-mono">
                              {f.ruleId}
                            </span>
                            <span className="text-[10px] font-mono text-slate-500">
                              ({f.scanner})
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 font-mono">
                            {f.filePath}:{f.startLine}
                          </p>
                        </div>

                        <div className="flex items-center gap-3 shrink-0">
                          <StatusBadge status={f.verification?.status || f.status} />
                          <button
                            type="button"
                            className="text-slate-400 hover:text-slate-200 p-1"
                            aria-label="Toggle details"
                          >
                            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>

                      {/* Expanded Evidence Drawer */}
                      {isExpanded && (
                        <div className="p-5 border-t border-slate-800/80 bg-slate-950/80 space-y-5 text-xs font-mono">
                          {/* 1. Finding Overview */}
                          <div>
                            <span className="text-slate-400 font-bold uppercase text-[10px] block mb-1">
                              Finding Description & Message
                            </span>
                            <p className="text-slate-200 leading-relaxed bg-slate-900/70 p-3 rounded-xl border border-slate-800">
                              {f.message || 'No additional message recorded by scanner.'}
                            </p>
                          </div>

                          {/* 2. AI Root-Cause Investigation (Acceptance Gate: AI) */}
                          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
                            <div className="flex items-center justify-between">
                              <span className="text-slate-300 font-bold uppercase text-[11px] flex items-center gap-1.5">
                                <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                                AI Root-Cause Investigation
                              </span>
                              {f.investigation ? (
                                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${ASSESSMENT_COLORS[f.investigation.assessment] || ASSESSMENT_COLORS.UNCERTAIN}`}>
                                  {f.investigation.assessment} (Confidence: {f.investigation.confidence})
                                </span>
                              ) : (
                                <span className="text-[10px] text-slate-500">Not Triaged with AI</span>
                              )}
                            </div>

                            {f.investigation ? (
                              <div className="space-y-2 text-slate-300">
                                <div>
                                  <strong className="text-slate-400">Summary: </strong>
                                  <span>{f.investigation.summary}</span>
                                </div>
                                {f.investigation.impact && (
                                  <div>
                                    <strong className="text-slate-400">Impact: </strong>
                                    <span>{f.investigation.impact}</span>
                                  </div>
                                )}
                                {f.investigation.recommendation && (
                                  <div>
                                    <strong className="text-slate-400">Recommendation: </strong>
                                    <span>{f.investigation.recommendation}</span>
                                  </div>
                                )}
                                {f.investigation.evidence && f.investigation.evidence.length > 0 && (
                                  <div>
                                    <strong className="text-slate-400">Evidence:</strong>
                                    <ul className="list-disc list-inside text-slate-400 pl-2 mt-1 space-y-0.5">
                                      {f.investigation.evidence.map((ev, i) => (
                                        <li key={i}>{ev}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                                <div className="text-[10px] text-slate-500 pt-1">
                                  Model: {f.investigation.model} ({f.investigation.promptVersion})
                                </div>
                              </div>
                            ) : (
                              <p className="text-slate-500">AI analysis has not been executed for this finding.</p>
                            )}
                          </div>

                          {/* 3. Patch Proposal (Acceptance Gate: Patch) */}
                          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
                            <div className="flex items-center justify-between">
                              <span className="text-slate-300 font-bold uppercase text-[11px] flex items-center gap-1.5">
                                <FolderGit2 className="w-3.5 h-3.5 text-cyan-400" />
                                Remediation Patch Proposal
                              </span>
                              {f.patch ? (
                                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
                                  State: {f.patch.reviewState} ({f.patch.status})
                                </span>
                              ) : (
                                <span className="text-[10px] text-slate-500">No Patch Generated</span>
                              )}
                            </div>

                            {f.patch ? (
                              <div className="space-y-3">
                                {f.patch.rationale && (
                                  <div className="text-slate-300">
                                    <strong className="text-slate-400">Rationale: </strong>
                                    <span>{f.patch.rationale}</span>
                                  </div>
                                )}
                                {f.patch.diff ? (
                                  <div className="mt-2">
                                    <DiffViewer diff={f.patch.diff} />
                                  </div>
                                ) : (
                                  <div className="p-2 rounded bg-black/40 text-slate-500">No diff contents available.</div>
                                )}
                              </div>
                            ) : (
                              <p className="text-slate-500">No remediation patch has been generated for this finding.</p>
                            )}
                          </div>

                          {/* 4. Verification Evidence & Checks (Acceptance Gate: Checks) */}
                          <div>
                            <VerificationChecklist
                              verification={f.verification}
                              patch={f.patch}
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
