import { useState } from 'react';
import { Search, Filter } from 'lucide-react';
import SeverityBadge from '../components/common/SeverityBadge';

export default function FindingsPage() {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const findings = [
    {
      id: 'find_sql_001',
      title: 'Potential SQL Injection via unparameterized string concatenation',
      category: 'SQL_INJECTION',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      filePath: 'src/routes/user.js',
      startLine: 24,
      scanner: 'semgrep',
      status: 'DETECTED',
      message: 'Detected untrusted user input directly concatenated into database query.',
    },
    {
      id: 'find_xss_002',
      title: 'Reflected Cross-Site Scripting (XSS) in search handler',
      category: 'XSS',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      filePath: 'src/controllers/search.js',
      startLine: 45,
      scanner: 'semgrep',
      status: 'PATCH_PROPOSED',
      message: 'Unescaped user input rendered directly to response body.',
    },
    {
      id: 'find_sec_003',
      title: 'Hard-coded JWT signing secret detected in source',
      category: 'SECRETS',
      severity: 'HIGH',
      confidence: 'HIGH',
      filePath: 'src/config/jwt.js',
      startLine: 12,
      scanner: 'semgrep',
      status: 'TRIAGED',
      message: 'Static secret key present. Secrets must be supplied via environment variables.',
    },
  ];

  const filtered = findings.filter((f) => {
    if (filterSeverity !== 'ALL' && f.severity !== filterSeverity) return false;
    if (searchQuery && !f.title.toLowerCase().includes(searchQuery.toLowerCase()) && !f.filePath.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-100">Findings Explorer</h1>
          <p className="text-xs text-slate-400 mt-1">
            Search, filter, inspect and investigate normalized vulnerability records
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by title, rule ID, or file path..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Findings Table */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono tracking-wider">
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Title</th>
                <th className="py-3 px-4">Location</th>
                <th className="py-3 px-4">Scanner</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filtered.map((item) => (
                <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4 whitespace-nowrap">
                    <SeverityBadge severity={item.severity} />
                  </td>
                  <td className="py-3 px-4 font-sans font-medium text-slate-200">
                    <div>{item.title}</div>
                    <div className="text-[11px] text-slate-500 font-mono mt-0.5">{item.message}</div>
                  </td>
                  <td className="py-3 px-4 text-cyan-400 whitespace-nowrap">
                    {item.filePath}:{item.startLine}
                  </td>
                  <td className="py-3 px-4 text-slate-400 uppercase whitespace-nowrap">
                    {item.scanner}
                  </td>
                  <td className="py-3 px-4 text-slate-300 whitespace-nowrap">
                    {item.confidence}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {item.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <button className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-sans text-xs font-medium transition-colors">
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
