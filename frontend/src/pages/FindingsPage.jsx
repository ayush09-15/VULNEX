import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import FindingFilterBar from '../components/findings/FindingFilterBar';
import FindingsTable from '../components/findings/FindingsTable';
import FindingDetailDrawer from '../components/findings/FindingDetailDrawer';
import { filterAndSortFindings } from '../utils/findingFilter';
import vulnexApi from '../services/api';

const INITIAL_FINDINGS = [
  {
    id: 'find_sql_001',
    scanId: 'scan_01JAZZ80',
    title: 'Potential SQL Injection via unparameterized string concatenation',
    ruleId: 'security.node.sql-injection',
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    filePath: 'src/routes/user.js',
    startLine: 24,
    endLine: 24,
    scanner: 'semgrep',
    status: 'DETECTED',
    message: 'Detected untrusted user input directly concatenated into database query without parameterization.',
    fingerprint: 'sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    createdAt: '2026-10-31T03:14:00.000Z',
    aiInvestigation: null,
  },
  {
    id: 'find_xss_002',
    scanId: 'scan_01JAZZ80',
    title: 'Reflected Cross-Site Scripting (XSS) in search handler',
    ruleId: 'security.node.xss',
    category: 'XSS',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    filePath: 'src/controllers/search.js',
    startLine: 45,
    endLine: 45,
    scanner: 'semgrep',
    status: 'PATCH_PROPOSED',
    message: 'Unescaped user input rendered directly to response body in HTML execution context.',
    fingerprint: 'sha256_ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
    createdAt: '2026-10-31T03:14:10.000Z',
    aiInvestigation: {
      assessment: 'LIKELY_TRUE',
      severity: 'HIGH',
      summary: 'Input parameter "q" reflected into HTML response without context-aware output encoding.',
      evidence: ['Direct res.send with string interpolation'],
      preconditions: ['User clicks crafted URL containing HTML payload'],
      potentialImpact: 'Session hijacking, DOM manipulation, credential theft.',
      recommendedFix: 'Encode query parameter using html-entities or sanitize with DOMPurify.',
      confidence: 'HIGH',
      limitations: ['Static AST match without browser runtime execution'],
    },
  },
  {
    id: 'find_dep_003',
    scanId: 'scan_01JAZZ80',
    title: 'Prototype Pollution in json-schema (CVE-2021-3918)',
    ruleId: 'npm.audit.cve-2021-3918',
    category: 'VULNERABLE_DEPENDENCY',
    severity: 'HIGH',
    confidence: 'HIGH',
    filePath: 'package.json',
    startLine: 18,
    endLine: 18,
    scanner: 'npm-audit',
    status: 'TRIAGED',
    message: 'Package json-schema version 0.2.3 has published high-severity prototype pollution advisory.',
    fingerprint: 'sha256_4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce',
    createdAt: '2026-10-31T03:14:20.000Z',
    aiInvestigation: null,
  },
  {
    id: 'find_cmd_004',
    scanId: 'scan_01JAZZ80',
    title: 'Command Injection via child_process.exec concatenation',
    ruleId: 'security.node.command-injection',
    category: 'COMMAND_INJECTION',
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    filePath: 'src/utils/system.js',
    startLine: 89,
    endLine: 89,
    scanner: 'semgrep',
    status: 'VERIFIED',
    message: 'Shell command assembled from untrusted parameter string.',
    fingerprint: 'sha256_4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    createdAt: '2026-10-31T03:14:30.000Z',
    aiInvestigation: {
      assessment: 'LIKELY_TRUE',
      severity: 'MEDIUM',
      summary: 'child_process.exec invoked with shell interpolation.',
      evidence: ['child_process.exec(`ping -c 1 ${host}`)'],
      preconditions: ['Host parameter accepts arbitrary characters like semicolon or pipe'],
      potentialImpact: 'Arbitrary host command execution under server user permissions.',
      recommendedFix: 'Use child_process.execFile with argument array rather than shell concatenation.',
      confidence: 'HIGH',
      limitations: ['Host OS command shell behavior differences'],
    },
  },
];

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
  const [findings, setFindings] = useState(INITIAL_FINDINGS);
  const [filters, setFilters] = useState(INITIAL_FILTERS);
  const [sortConfig, setSortConfig] = useState({ key: 'severity', direction: 'desc' });
  const [selectedFinding, setSelectedFinding] = useState(null);

  useEffect(() => {
    let isMounted = true;
    const fetchLiveFindings = async () => {
      try {
        const res = await vulnexApi.scans.getFindings('scan_default');
        if (isMounted && res && Array.isArray(res) && res.length > 0) {
          setFindings(res);
        }
      } catch {
        // Fall back gracefully to initialized findings
      }
    };

    fetchLiveFindings();
    return () => { isMounted = false; };
  }, []);

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
