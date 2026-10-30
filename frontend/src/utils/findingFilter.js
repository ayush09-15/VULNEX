/**
 * Utility functions for filtering, searching, and sorting vulnerability findings.
 * Adheres strictly to Master Antigravity Execution Bible Section 3.3 and Commit 17 gates.
 */

export const SEVERITY_ORDER = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export const CONFIDENCE_ORDER = {
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

/**
 * Filter and sort a list of findings according to user controls.
 * 
 * @param {Array} findings - List of finding objects
 * @param {Object} filters - Active filter settings
 * @param {string} [filters.severity='ALL']
 * @param {string} [filters.category='ALL']
 * @param {string} [filters.scanner='ALL']
 * @param {string} [filters.status='ALL']
 * @param {string} [filters.file='']
 * @param {string} [filters.search='']
 * @param {Object} [sortConfig]
 * @param {string} [sortConfig.key='severity'] - 'severity' | 'file' | 'confidence' | 'newest'
 * @param {string} [sortConfig.direction='desc'] - 'asc' | 'desc'
 * @returns {Array} Filtered and sorted findings
 */
export function filterAndSortFindings(findings = [], filters = {}, sortConfig = { key: 'severity', direction: 'desc' }) {
  if (!Array.isArray(findings)) return [];

  const severityFilter = (filters.severity || 'ALL').toUpperCase();
  const categoryFilter = (filters.category || 'ALL').toUpperCase();
  const scannerFilter = (filters.scanner || 'ALL').toUpperCase();
  const statusFilter = (filters.status || 'ALL').toUpperCase();
  const fileFilter = (filters.file || '').trim().toLowerCase();
  const searchFilter = (filters.search || '').trim().toLowerCase();

  // 1. Filter phase
  const filtered = findings.filter((finding) => {
    // Severity filter
    if (severityFilter !== 'ALL' && (finding.severity || '').toUpperCase() !== severityFilter) {
      return false;
    }

    // Category filter
    if (categoryFilter !== 'ALL' && (finding.category || '').toUpperCase() !== categoryFilter) {
      return false;
    }

    // Scanner filter (e.g. semgrep, npm-audit)
    if (scannerFilter !== 'ALL' && (finding.scanner || '').toUpperCase() !== scannerFilter) {
      return false;
    }

    // Status filter
    if (statusFilter !== 'ALL' && (finding.status || '').toUpperCase() !== statusFilter) {
      return false;
    }

    // File path filter
    if (fileFilter && !(finding.filePath || '').toLowerCase().includes(fileFilter)) {
      return false;
    }

    // Freeform search (searches title, ruleId, filePath, and id)
    if (searchFilter) {
      const titleMatch = (finding.title || '').toLowerCase().includes(searchFilter);
      const ruleMatch = (finding.ruleId || '').toLowerCase().includes(searchFilter);
      const pathMatch = (finding.filePath || '').toLowerCase().includes(searchFilter);
      const idMatch = (finding.id || '').toLowerCase().includes(searchFilter);
      if (!titleMatch && !ruleMatch && !pathMatch && !idMatch) {
        return false;
      }
    }

    return true;
  });

  // 2. Sort phase
  return filtered.sort((a, b) => {
    let comparison;

    switch (sortConfig.key) {
      case 'file': {
        const fileA = (a.filePath || '').toLowerCase();
        const fileB = (b.filePath || '').toLowerCase();
        comparison = fileA.localeCompare(fileB);
        break;
      }
      case 'confidence': {
        const confA = CONFIDENCE_ORDER[(a.confidence || '').toUpperCase()] || 0;
        const confB = CONFIDENCE_ORDER[(b.confidence || '').toUpperCase()] || 0;
        comparison = confA - confB;
        break;
      }
      case 'newest': {
        const timeA = new Date(a.createdAt || 0).getTime();
        const timeB = new Date(b.createdAt || 0).getTime();
        comparison = timeA - timeB;
        break;
      }
      case 'severity':
      default: {
        const sevA = SEVERITY_ORDER[(a.severity || '').toUpperCase()] || 0;
        const sevB = SEVERITY_ORDER[(b.severity || '').toUpperCase()] || 0;
        comparison = sevA - sevB;
        break;
      }
    }

    return sortConfig.direction === 'desc' ? -comparison : comparison;
  });
}
