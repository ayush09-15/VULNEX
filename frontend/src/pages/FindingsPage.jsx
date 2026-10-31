import { useState, useEffect, useMemo } from 'react';
import { useNavigate, useLocation, useSearchParams, useOutletContext } from 'react-router-dom';
import { FolderGit2, Shield, RefreshCw } from 'lucide-react';
import FindingFilterBar from '../components/findings/FindingFilterBar';
import FindingsTable from '../components/findings/FindingsTable';
import FindingDetailDrawer from '../components/findings/FindingDetailDrawer';
import { filterAndSortFindings } from '../utils/findingFilter';
import vulnexApi from '../services/api';

const INITIAL_FILTERS = {
  severity: 'ALL',
  category: 'ALL',
  scanner: 'ALL',
  status: 'ALL',
  file: '',
  search: '',
};

export default function FindingsPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();

  const [scansList, setScansList] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [findings, setFindings] = useState([]);
  const [filters, setFilters] = useState(INITIAL_FILTERS);
  const [sortConfig, setSortConfig] = useState({ key: 'severity', direction: 'desc' });
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  // 1. Fetch available scans on mount & determine active scan ID
  useEffect(() => {
    let isMounted = true;

    const loadScans = async () => {
      try {
        const res = await vulnexApi.scans.list().catch(() => null);
        const scans = Array.isArray(res) ? res : (res?.data || []);

        if (isMounted) {
          setScansList(scans);

          // Determine target scanId in order of priority:
          // 1. URL search parameter (?scanId=...)
          // 2. React Router location state
          // 3. localStorage preference
          // 4. Latest completed scan
          const paramScanId = searchParams.get('scanId');
          const stateScanId = location.state?.scanId;
          const localScanId = localStorage.getItem('vulnex_selected_scan_id');

          let targetScanId = paramScanId || stateScanId;

          if (!targetScanId && localScanId && scans.some((s) => s.id === localScanId)) {
            targetScanId = localScanId;
          }

          if (!targetScanId && scans.length > 0) {
            targetScanId = scans[scans.length - 1].id;
          }

          if (targetScanId) {
            setSelectedScanId(targetScanId);
            if (targetScanId !== 'ALL') {
              localStorage.setItem('vulnex_selected_scan_id', targetScanId);
            }
          }
        }
      } catch (err) {
        console.warn('Failed to load scans:', err);
      }
    };

    loadScans();
    return () => { isMounted = false; };
  }, [location.state?.scanId, searchParams]);

  // 2. Fetch findings scoped to the selected scan
  const fetchFindingsForScan = async (scanId) => {
    setIsLoading(true);
    try {
      let items = [];
      if (scanId && scanId !== 'ALL') {
        const res = await vulnexApi.scans.getFindings(scanId);
        items = Array.isArray(res) ? res : (res?.data || []);
      } else if (scanId === 'ALL') {
        const res = await vulnexApi.findings.list();
        items = Array.isArray(res) ? res : (res?.data || []);
      } else {
        // Fallback if no specific scan is yet chosen
        const res = await vulnexApi.findings.list();
        items = Array.isArray(res) ? res : (res?.data || []);
      }
      setFindings(Array.isArray(items) ? items : []);
    } catch {
      setFindings([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (selectedScanId) {
      fetchFindingsForScan(selectedScanId);
    }
  }, [selectedScanId]);

  const handleScanChange = (newScanId) => {
    setSelectedScanId(newScanId);
    if (newScanId && newScanId !== 'ALL') {
      setSearchParams({ scanId: newScanId });
      localStorage.setItem('vulnex_selected_scan_id', newScanId);
    } else if (newScanId === 'ALL') {
      setSearchParams({ scanId: 'ALL' });
      localStorage.removeItem('vulnex_selected_scan_id');
    }
  };

  const handleRefresh = () => {
    if (selectedScanId) {
      fetchFindingsForScan(selectedScanId);
    }
  };

  const handleChangeFilter = (key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const handleResetFilters = () => {
    setFilters(INITIAL_FILTERS);
    setSortConfig({ key: 'severity', direction: 'desc' });
  };

  const handleChangeSort = (key, direction) => {
    setSortConfig({ key, direction });
  };

  const handleUpdateFinding = (findingId, updates) => {
    setFindings((prev) =>
      prev.map((f) => (f.id === findingId ? { ...f, ...updates } : f))
    );
    if (selectedFinding?.id === findingId) {
      setSelectedFinding((prev) => ({ ...prev, ...updates }));
    }
  };

  const handleNavigateToPatch = (finding) => {
    setSelectedFinding(null);
    navigate('/remediation', { state: { finding, autoGenerate: true } });
  };

  const filteredFindings = useMemo(() => {
    return filterAndSortFindings(findings, filters, sortConfig);
  }, [findings, filters, sortConfig]);

  const activeScan = scansList.find((s) => s.id === selectedScanId);
  const { setActiveRepo } = useOutletContext() || {};

  useEffect(() => {
    if (activeScan && setActiveRepo) {
      setActiveRepo({
        id: activeScan.repositoryId || 'repo_active',
        displayName: activeScan.repositoryId || 'active-repository',
        defaultRef: activeScan.ref || 'main',
        sourceType: 'ACTIVE_SCAN'
      });
    }
  }, [activeScan?.id, activeScan?.repositoryId, activeScan?.ref, setActiveRepo]);

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Title & Scope Selector Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-100 flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" />
            <span>Findings Explorer</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Search, filter, inspect and investigate normalized vulnerability records with strict repository isolation
          </p>
        </div>

        {/* Scan Scope Dropdown */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800">
            <FolderGit2 className="w-4 h-4 text-cyan-400" />
            <label htmlFor="scan-selector" className="text-xs font-mono text-slate-400 whitespace-nowrap">
              Active Scope:
            </label>
            <select
              id="scan-selector"
              value={selectedScanId}
              onChange={(e) => handleScanChange(e.target.value)}
              className="px-2 py-1 rounded-lg bg-slate-950 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 max-w-xs md:max-w-sm truncate"
            >
              {scansList.length > 0 ? (
                <>
                  {scansList.slice().reverse().map((scan) => (
                    <option key={scan.id} value={scan.id}>
                      {scan.repositoryId} — {scan.id.slice(0, 16)} ({scan.summary?.totalFindings ?? 0} findings) [{scan.status}]
                    </option>
                  ))}
                  <option value="ALL">All Scans (Global View)</option>
                </>
              ) : (
                <option value="">No completed scans</option>
              )}
            </select>
          </div>

          <button
            onClick={handleRefresh}
            disabled={isLoading}
            className="p-2 rounded-xl bg-slate-900/80 border border-slate-800 text-slate-400 hover:text-cyan-400 transition-colors"
            title="Refresh Findings"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Active Scan Indicator Banner */}
      {activeScan && (
        <div className="px-4 py-2.5 rounded-xl bg-cyan-950/20 border border-cyan-900/40 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2 text-cyan-300">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            <span>Scoped to Scan: <strong>{activeScan.id}</strong> ({activeScan.repositoryId})</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400 text-[11px]">
            <span>Ref: <strong>{activeScan.ref || 'main'}</strong></span>
            <span>Stage: <strong className="text-slate-200">{activeScan.stage || activeScan.status}</strong></span>
            <span>Total Findings: <strong className="text-cyan-400">{findings.length}</strong></span>
          </div>
        </div>
      )}

      {/* Filter & Search Controls */}
      <FindingFilterBar
        filters={filters}
        onChangeFilter={handleChangeFilter}
        onResetFilters={handleResetFilters}
        sortConfig={sortConfig}
        onChangeSort={handleChangeSort}
        totalCount={findings.length}
        filteredCount={filteredFindings.length}
      />

      {/* Findings Table */}
      <FindingsTable
        findings={filteredFindings}
        onSelectFinding={(finding) => setSelectedFinding(finding)}
        selectedFindingId={selectedFinding?.id}
      />

      {/* Detail Drawer & Evidence Panel */}
      <FindingDetailDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onUpdateFinding={handleUpdateFinding}
        onNavigateToPatch={handleNavigateToPatch}
      />
    </div>
  );
}
