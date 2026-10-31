import { useState, useEffect, useMemo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
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
  const [findings, setFindings] = useState([]);
  const [filters, setFilters] = useState(INITIAL_FILTERS);
  const [sortConfig, setSortConfig] = useState({ key: 'severity', direction: 'desc' });
  const [selectedFinding, setSelectedFinding] = useState(null);

  useEffect(() => {
    let isMounted = true;
    const fetchLiveFindings = async () => {
      try {
        const targetScanId = location.state?.scanId;
        let items = null;
        if (targetScanId) {
          const res = await vulnexApi.scans.getFindings(targetScanId);
          items = Array.isArray(res) ? res : (res?.data || []);
        } else {
          try {
            const listRes = await vulnexApi.findings.list();
            items = Array.isArray(listRes) ? listRes : (listRes?.data || []);
          } catch {
            const res = await vulnexApi.scans.getFindings('scan_default');
            items = Array.isArray(res) ? res : (res?.data || []);
          }
        }
        if (isMounted) {
          setFindings(Array.isArray(items) ? items : []);
        }
      } catch {
        // Fall back gracefully to initialized findings
      }
    };

    fetchLiveFindings();
    return () => { isMounted = false; };
  }, [location.state?.scanId]);

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
    navigate('/remediation', { state: { finding } });
  };

  const filteredFindings = useMemo(() => {
    return filterAndSortFindings(findings, filters, sortConfig);
  }, [findings, filters, sortConfig]);

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Title & Introduction */}
      <div>
        <h1 className="text-2xl font-extrabold text-slate-100">Findings Explorer</h1>
        <p className="text-xs text-slate-400 mt-1">
          Search, filter, inspect and investigate normalized vulnerability records with strict evidence separation
        </p>
      </div>

      {/* Filter & Search Controls (Commit 17) */}
      <FindingFilterBar
        filters={filters}
        onChangeFilter={handleChangeFilter}
        onResetFilters={handleResetFilters}
        sortConfig={sortConfig}
        onChangeSort={handleChangeSort}
        totalCount={findings.length}
        filteredCount={filteredFindings.length}
      />

      {/* Findings Table (Commit 17) */}
      <FindingsTable
        findings={filteredFindings}
        onSelectFinding={(finding) => setSelectedFinding(finding)}
        selectedFindingId={selectedFinding?.id}
      />

      {/* Detail Drawer & Evidence Panel (Commit 20) */}
      <FindingDetailDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onUpdateFinding={handleUpdateFinding}
        onNavigateToPatch={handleNavigateToPatch}
      />
    </div>
  );
}
