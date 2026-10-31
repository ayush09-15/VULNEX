import { useState, useEffect, useMemo } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
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
  Info,
  History,
  Search,
  Filter,
  Copy,
  Check,
  ArrowRight,
  Code2,
  Calendar,
  Clock,
  FileCode,
  Table
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
  const urlTab = searchParams.get('tab') || (urlScanId ? 'report' : 'history');

  const [activeTab, setActiveTab] = useState(urlTab); // 'history' | 'report'
  const [scans, setScans] = useState([]);
  const [historyData, setHistoryData] = useState(null);
  const [selectedScanId, setSelectedScanId] = useState(urlScanId || '');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedFindings, setExpandedFindings] = useState({});
  const [copiedId, setCopiedId] = useState(null);
  const [exportingFormat, setExportingFormat] = useState(null);

  // Filters for Scan History view
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [outcomeFilter, setOutcomeFilter] = useState('ALL');

  // 1. Fetch available scans & history summary
  useEffect(() => {
    let isMounted = true;
    async function loadScansAndHistory() {
      setHistoryLoading(true);
      try {
        const [scansRes, historyRes] = await Promise.all([
          vulnexApi.scans.list().catch(() => []),
          vulnexApi.scans.getHistory().catch(() => null)
        ]);

        const scanList = scansRes?.data || scansRes || [];
        const hist = historyRes?.data || historyRes;

        if (isMounted) {
          setScans(scanList);
          setHistoryData(hist);

          // If no scan is selected yet and scans exist, select the latest one
          if (!selectedScanId && scanList.length > 0) {
            const defaultId = scanList[scanList.length - 1].id;
            setSelectedScanId(defaultId);
          }
        }
      } catch (err) {
        console.warn('Could not load scan history:', err);
      } finally {
        if (isMounted) setHistoryLoading(false);
      }
    }

    loadScansAndHistory();
    return () => { isMounted = false; };
  }, []);

  // 2. Fetch Report when selectedScanId changes
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
    setSearchParams({ scanId: newScanId, tab: 'report' });
    setActiveTab('report');
  };

  const handleTabSwitch = (tab) => {
    setActiveTab(tab);
    if (selectedScanId && tab === 'report') {
      setSearchParams({ scanId: selectedScanId, tab });
    } else {
      setSearchParams({ tab });
    }
  };

  const toggleFinding = (fId) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [fId]: !prev[fId],
    }));
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  /**
   * Handle Multi-Format Export (JSON, Markdown, SARIF, CSV)
   */
  const handleExport = async (format = 'json') => {
    if (!report && !selectedScanId) return;
    setExportingFormat(format);

    try {
      const res = await vulnexApi.scans.exportReport(selectedScanId, format);
      const data = res?.data || res;

      let fileContent = '';
      let mimeType = 'text/plain';
      let fileExt = format;

      if (format === 'json') {
        fileContent = JSON.stringify(data, null, 2);
        mimeType = 'application/json';
        fileExt = 'json';
      } else if (format === 'markdown' || format === 'md') {
        fileContent = data.content || (typeof data === 'string' ? data : JSON.stringify(data, null, 2));
        mimeType = 'text/markdown';
        fileExt = 'md';
      } else if (format === 'sarif') {
        fileContent = JSON.stringify(data.sarif || data, null, 2);
        mimeType = 'application/sarif+json';
        fileExt = 'sarif';
      } else if (format === 'csv') {
        fileContent = data.content || (typeof data === 'string' ? data : String(data));
        mimeType = 'text/csv';
        fileExt = 'csv';
      }

      const blob = new Blob([fileContent], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnex-report-${report?.scan?.id || selectedScanId}.${fileExt}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error(`Export failed for format ${format}:`, err);
    } finally {
      setExportingFormat(null);
    }
  };

  // Filtered Scan History
  const filteredHistory = useMemo(() => {
    const list = historyData?.scans || scans || [];
    return list.filter((scan) => {
      // Search Query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesId = scan.id?.toLowerCase().includes(q);
        const matchesRepo = scan.repositoryId?.toLowerCase().includes(q);
        const matchesRef = scan.ref?.toLowerCase().includes(q);
        if (!matchesId && !matchesRepo && !matchesRef) return false;
      }

      // Status filter
      if (statusFilter !== 'ALL' && scan.status !== statusFilter) {
        return false;
      }

      // Outcome filter
      if (outcomeFilter !== 'ALL') {
        const outcome = scan.verificationOutcome || 'NOT_RUN';
        if (outcome !== outcomeFilter) return false;
      }

      return true;
    });
  }, [historyData, scans, searchQuery, statusFilter, outcomeFilter]);

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
  const toolsAndRules = report?.toolsAndRules || {
    byScanner: {},
    byRule: []
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Header & Navigation Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-6 h-6 text-cyan-400" />
            <h1 className="text-2xl font-extrabold text-slate-100 font-mono">
              Audit Reports & Scan History
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Traceable security audit records, tool provenance, AI root-cause assessments, patch diffs, and verification receipts
          </p>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center p-1 rounded-xl bg-slate-900 border border-slate-800">
          <button
            onClick={() => handleTabSwitch('history')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
              activeTab === 'history'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <History className="w-4 h-4" />
            <span>Scan History ({filteredHistory.length})</span>
          </button>
          <button
            onClick={() => handleTabSwitch('report')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
              activeTab === 'report'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>Active Report {selectedScanId ? `(${selectedScanId.slice(0, 12)}...)` : ''}</span>
          </button>
        </div>
      </div>

      {/* =================================================================== */}
      {/* TAB 1: SCAN HISTORY VIEW (Commit 47) */}
      {/* =================================================================== */}
      {activeTab === 'history' && (
        <div className="space-y-6 animate-fadeIn">
          {/* Global Statistics Banner */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 uppercase block mb-1">Total Scans Executed</span>
              <span className="text-2xl font-bold font-mono text-slate-100">
                {historyData?.summary?.totalScans || scans.length}
              </span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[11px] font-mono text-red-400 uppercase block mb-1">Vulnerabilities Detected</span>
              <span className="text-2xl font-bold font-mono text-red-400">
                {historyData?.summary?.totalFindingsDetected || 0}
              </span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[11px] font-mono text-cyan-400 uppercase block mb-1">Patches Proposed</span>
              <span className="text-2xl font-bold font-mono text-cyan-400">
                {historyData?.summary?.totalPatchAttempts || 0}
              </span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[11px] font-mono text-emerald-400 uppercase block mb-1">Verified Remediations</span>
              <span className="text-2xl font-bold font-mono text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                {historyData?.summary?.totalRemediated || 0}
              </span>
            </div>
          </div>

          {/* Search & Filter Bar */}
          <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search by Scan ID, Repository, or Branch Ref..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 shrink-0">
                <Filter className="w-3.5 h-3.5" />
                <span>Status:</span>
              </div>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-950/80 border border-slate-800 text-slate-200 text-xs rounded-xl px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="COMPLETED">COMPLETED</option>
                <option value="SCANNING">SCANNING</option>
                <option value="FAILED">FAILED</option>
                <option value="PARTIAL">PARTIAL</option>
              </select>

              <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 shrink-0">
                <span>Outcome:</span>
              </div>
              <select
                value={outcomeFilter}
                onChange={(e) => setOutcomeFilter(e.target.value)}
                className="bg-slate-950/80 border border-slate-800 text-slate-200 text-xs rounded-xl px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Outcomes</option>
                <option value="PASSED">PASSED</option>
                <option value="FAILED">FAILED</option>
                <option value="INCONCLUSIVE">INCONCLUSIVE</option>
                <option value="NOT_RUN">NOT_RUN</option>
              </select>
            </div>
          </div>

          {/* Historical Scans Table */}
          {historyLoading ? (
            <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800">
              <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto mb-3" />
              <p className="text-xs font-mono text-slate-400">Loading historical security scans...</p>
            </div>
          ) : filteredHistory.length === 0 ? (
            <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800 space-y-3">
              <History className="w-8 h-8 text-slate-600 mx-auto" />
              <p className="text-sm font-mono text-slate-300">No historical scans matched your filter criteria.</p>
              <Link
                to="/scan"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-all font-mono"
              >
                <Terminal className="w-4 h-4" />
                <span>Launch New Scan</span>
              </Link>
            </div>
          ) : (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="py-3.5 px-4">Scan Identifier & Ref</th>
                      <th className="py-3.5 px-4">Repository</th>
                      <th className="py-3.5 px-4">Status</th>
                      <th className="py-3.5 px-4">Engines / Tools</th>
                      <th className="py-3.5 px-4">Findings</th>
                      <th className="py-3.5 px-4">Remediated</th>
                      <th className="py-3.5 px-4">Verification</th>
                      <th className="py-3.5 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {filteredHistory.map((s) => {
                      const outcome = s.verificationOutcome || 'NOT_RUN';
                      const outcomeBadge = outcome === 'PASSED'
                        ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
                        : outcome === 'FAILED'
                        ? 'bg-rose-950/80 text-rose-300 border-rose-700/60'
                        : outcome === 'INCONCLUSIVE'
                        ? 'bg-amber-950/80 text-amber-300 border-amber-700/60'
                        : 'bg-slate-900 text-slate-400 border-slate-700/60';

                      return (
                        <tr key={s.id} className="hover:bg-slate-800/30 transition-colors">
                          <td className="py-3.5 px-4">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-slate-100">{s.id}</span>
                              <button
                                onClick={() => copyToClipboard(s.id, s.id)}
                                title="Copy Scan ID"
                                className="text-slate-500 hover:text-slate-300 transition-colors"
                              >
                                {copiedId === s.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                              </button>
                            </div>
                            <div className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-1.5">
                              <FolderGit2 className="w-3 h-3 text-cyan-400" />
                              <span>{s.ref || 'main'}</span>
                            </div>
                          </td>

                          <td className="py-3.5 px-4 text-slate-300 font-semibold">
                            {s.repositoryId || 'Local Workspace'}
                          </td>

                          <td className="py-3.5 px-4">
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${
                              s.status === 'COMPLETED'
                                ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
                                : s.status === 'FAILED'
                                ? 'bg-rose-950/80 text-rose-300 border-rose-700/60'
                                : 'bg-cyan-950/80 text-cyan-300 border-cyan-700/60'
                            }`}>
                              {s.status}
                            </span>
                            <div className="text-[10px] text-slate-500 mt-1">
                              {s.durationSeconds ? `${s.durationSeconds}s` : 'Real-time'}
                            </div>
                          </td>

                          <td className="py-3.5 px-4">
                            <div className="flex flex-wrap gap-1">
                              {Object.entries(s.toolVersions || { semgrep: '1.98.0', 'npm-audit': '10.0.0' }).map(([tool, ver]) => (
                                <span key={tool} className="px-1.5 py-0.5 rounded bg-slate-950 text-[10px] text-slate-400 border border-slate-800">
                                  {tool}:{String(ver)}
                                </span>
                              ))}
                            </div>
                          </td>

                          <td className="py-3.5 px-4">
                            <div className="flex items-center gap-1.5">
                              <span className="font-bold text-slate-200">
                                {s.summary?.totalFindings || 0}
                              </span>
                              {(s.summary?.critical || 0) > 0 && (
                                <span className="px-1.5 py-0.2 rounded text-[10px] bg-red-950/80 text-red-400 border border-red-800/60 font-bold">
                                  {s.summary.critical} Crit
                                </span>
                              )}
                              {(s.summary?.high || 0) > 0 && (
                                <span className="px-1.5 py-0.2 rounded text-[10px] bg-orange-950/80 text-orange-400 border border-orange-800/60 font-bold">
                                  {s.summary.high} High
                                </span>
                              )}
                            </div>
                          </td>

                          <td className="py-3.5 px-4">
                            <span className={`font-semibold ${
                              (s.summary?.remediated || 0) > 0 ? 'text-emerald-400' : 'text-slate-400'
                            }`}>
                              {s.summary?.remediated || 0} Fixes
                            </span>
                            <div className="text-[10px] text-slate-500">
                              {s.summary?.patchAttempts || 0} Patches
                            </div>
                          </td>

                          <td className="py-3.5 px-4">
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${outcomeBadge}`}>
                              {outcome}
                            </span>
                          </td>

                          <td className="py-3.5 px-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => handleScanChange(s.id)}
                                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800/60 text-cyan-300 text-[11px] font-semibold transition-colors"
                              >
                                <span>Report</span>
                                <ArrowRight className="w-3 h-3" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tools & Rules Breakdown Aggregated across Scans */}
          {historyData?.rulesAggregated && Object.keys(historyData.rulesAggregated).length > 0 && (
            <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                    Frequently Triggered Security Rules Across Scans
                  </h2>
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  {Object.keys(historyData.rulesAggregated).length} Unique Rules
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {Object.entries(historyData.rulesAggregated).map(([ruleId, count]) => (
                  <div key={ruleId} className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-300 truncate max-w-[220px]" title={ruleId}>
                      {ruleId}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-bold shrink-0">
                      {count} {count === 1 ? 'hit' : 'hits'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 2: ACTIVE REPORT VIEW (Commit 41 & 47) */}
      {/* =================================================================== */}
      {activeTab === 'report' && (
        <div className="space-y-6 animate-fadeIn">
          {/* Subheader Controls */}
          <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-slate-400 shrink-0">Selected Scan:</span>
              {scans.length > 0 ? (
                <select
                  value={selectedScanId}
                  onChange={(e) => handleScanChange(e.target.value)}
                  className="bg-slate-950/80 border border-slate-800 text-slate-200 text-xs rounded-xl px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
                >
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.id} ({s.status}) - {s.ref || 'main'}
                    </option>
                  ))}
                </select>
              ) : (
                <span className="text-xs font-mono text-slate-500">No scans available</span>
              )}

              <button
                onClick={() => handleTabSwitch('history')}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 underline underline-offset-4 ml-2"
              >
                Browse all scans
              </button>
            </div>

            {/* Multi-Format Export Buttons (Commit 47) */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => handleExport('json')}
                disabled={!report || loading || exportingFormat !== null}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono font-semibold transition-all disabled:opacity-50"
                title="Download JSON Report"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                <span>JSON</span>
              </button>

              <button
                onClick={() => handleExport('markdown')}
                disabled={!report || loading || exportingFormat !== null}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono font-semibold transition-all disabled:opacity-50"
                title="Download Executive Markdown Summary"
              >
                <FileText className="w-3.5 h-3.5 text-amber-400" />
                <span>Markdown</span>
              </button>

              <button
                onClick={() => handleExport('sarif')}
                disabled={!report || loading || exportingFormat !== null}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono font-semibold transition-all disabled:opacity-50"
                title="Download GitHub SARIF Schema"
              >
                <Code2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>SARIF</span>
              </button>

              <button
                onClick={() => handleExport('csv')}
                disabled={!report || loading || exportingFormat !== null}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono font-semibold transition-all disabled:opacity-50"
                title="Download Spreadsheet CSV"
              >
                <Table className="w-3.5 h-3.5 text-purple-400" />
                <span>CSV</span>
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

              {/* Engine Provenance & Tools */}
              <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-cyan-400" />
                    <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                      Engine Provenance & Tool Versions
                    </h2>
                  </div>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/40">
                    Scan ID: {scan?.id}
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

              {/* Tools & Rules Breakdown (Acceptance Gate: identify tools/rules producing results) */}
              {toolsAndRules.byRule && toolsAndRules.byRule.length > 0 && (
                <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-cyan-400" />
                      <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                        Tools & Security Rules Producing Results
                      </h2>
                    </div>
                    <div className="flex items-center gap-2 text-[11px] font-mono">
                      {Object.entries(toolsAndRules.byScanner || {}).map(([scanner, count]) => (
                        <span key={scanner} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                          {scanner}: <strong>{count}</strong>
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {toolsAndRules.byRule.map((rule) => {
                      const sevClass = SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.INFO;
                      return (
                        <div key={rule.ruleId} className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs font-mono">
                          <div className="space-y-1 truncate pr-2">
                            <div className="flex items-center gap-2">
                              <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold uppercase border ${sevClass}`}>
                                {rule.severity}
                              </span>
                              <span className="font-bold text-slate-200 truncate" title={rule.ruleId}>
                                {rule.ruleId}
                              </span>
                            </div>
                            <div className="text-[10px] text-slate-500">
                              Scanner: {rule.scanner}
                            </div>
                          </div>

                          <div className="text-right shrink-0">
                            <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-bold block text-center">
                              {rule.occurrences} {rule.occurrences === 1 ? 'finding' : 'findings'}
                            </span>
                            {rule.remediatedCount > 0 && (
                              <span className="text-[10px] text-emerald-400 font-semibold block mt-0.5">
                                {rule.remediatedCount} verified fix
                              </span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Findings & Evidence Breakdown */}
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

                              {/* 2. AI Root-Cause Investigation */}
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

                              {/* 3. Patch Proposal */}
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

                              {/* 4. Verification Evidence Checklist */}
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
      )}
    </div>
  );
}
