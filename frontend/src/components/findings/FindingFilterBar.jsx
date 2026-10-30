import { Search, RotateCcw } from 'lucide-react';
import { VULNERABILITY_CATEGORIES } from '../../types';

export default function FindingFilterBar({
  filters,
  onChangeFilter,
  onResetFilters,
  sortConfig,
  onChangeSort,
  availableScanners = ['semgrep', 'npm-audit'],
  totalCount = 0,
  filteredCount = 0
}) {
  const isFiltered =
    filters.severity !== 'ALL' ||
    filters.category !== 'ALL' ||
    filters.scanner !== 'ALL' ||
    filters.status !== 'ALL' ||
    Boolean(filters.file) ||
    Boolean(filters.search);

  return (
    <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
      {/* Top Search & Reset Row */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
        {/* Search Input */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={filters.search || ''}
            onChange={(e) => onChangeFilter('search', e.target.value)}
            placeholder="Search by title, rule ID, path, or finding ID..."
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        {/* Sort Controls */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono uppercase text-slate-500">Sort:</span>
          <select
            value={sortConfig.key}
            onChange={(e) => onChangeSort(e.target.value, sortConfig.direction)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="severity">Severity</option>
            <option value="file">File Path</option>
            <option value="confidence">Confidence</option>
            <option value="newest">Newest First</option>
          </select>

          <button
            onClick={() => onChangeSort(sortConfig.key, sortConfig.direction === 'asc' ? 'desc' : 'asc')}
            className="px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-400 hover:text-slate-200"
            title="Toggle Sort Direction"
          >
            {sortConfig.direction === 'asc' ? '▲ ASC' : '▼ DESC'}
          </button>
        </div>

        {/* Reset Filter Button */}
        {isFiltered && (
          <button
            onClick={onResetFilters}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition-colors font-mono"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset</span>
          </button>
        )}
      </div>

      {/* Dropdown Filters Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2.5 pt-1 border-t border-slate-800/60">
        {/* Severity Filter */}
        <div>
          <label className="block text-[10px] uppercase font-mono text-slate-500 mb-1">
            Severity
          </label>
          <select
            value={filters.severity || 'ALL'}
            onChange={(e) => onChangeFilter('severity', e.target.value)}
            className="w-full px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        {/* Category Filter */}
        <div>
          <label className="block text-[10px] uppercase font-mono text-slate-500 mb-1">
            Category
          </label>
          <select
            value={filters.category || 'ALL'}
            onChange={(e) => onChangeFilter('category', e.target.value)}
            className="w-full px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Categories</option>
            {Object.entries(VULNERABILITY_CATEGORIES).map(([catKey, label]) => (
              <option key={catKey} value={catKey}>{label}</option>
            ))}
          </select>
        </div>

        {/* Scanner Filter */}
        <div>
          <label className="block text-[10px] uppercase font-mono text-slate-500 mb-1">
            Scanner
          </label>
          <select
            value={filters.scanner || 'ALL'}
            onChange={(e) => onChangeFilter('scanner', e.target.value)}
            className="w-full px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Scanners</option>
            {availableScanners.map((sc) => (
              <option key={sc} value={sc}>{sc.toUpperCase()}</option>
            ))}
          </select>
        </div>

        {/* Status Filter */}
        <div>
          <label className="block text-[10px] uppercase font-mono text-slate-500 mb-1">
            Remediation Status
          </label>
          <select
            value={filters.status || 'ALL'}
            onChange={(e) => onChangeFilter('status', e.target.value)}
            className="w-full px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="DETECTED">Detected</option>
            <option value="TRIAGED">Triaged</option>
            <option value="PATCH_PROPOSED">Patch Proposed</option>
            <option value="PATCH_APPLIED">Patch Applied</option>
            <option value="VERIFIED">Verified</option>
          </select>
        </div>

        {/* File Filter Input */}
        <div>
          <label className="block text-[10px] uppercase font-mono text-slate-500 mb-1">
            File Filter
          </label>
          <input
            type="text"
            value={filters.file || ''}
            onChange={(e) => onChangeFilter('file', e.target.value)}
            placeholder="e.g. routes/user"
            className="w-full px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Filter Stats Badge */}
      <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1">
        <span>
          Showing <strong className="text-slate-300">{filteredCount}</strong> of {totalCount} findings
        </span>
        {isFiltered && (
          <span className="text-cyan-400">
            Active filters applied
          </span>
        )}
      </div>
    </div>
  );
}
