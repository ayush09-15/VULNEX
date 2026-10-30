import test from 'node:test';
import assert from 'node:assert/strict';
import { filterAndSortFindings } from '../src/utils/findingFilter.js';

const mockFindings = [
  {
    id: 'find_01',
    title: 'SQL Injection in user route',
    ruleId: 'security.node.sql-injection',
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    filePath: 'src/routes/user.js',
    startLine: 24,
    scanner: 'semgrep',
    status: 'DETECTED',
    createdAt: '2026-10-31T01:00:00.000Z',
  },
  {
    id: 'find_02',
    title: 'Reflected XSS in search',
    ruleId: 'security.node.xss',
    category: 'XSS',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    filePath: 'src/controllers/search.js',
    startLine: 45,
    scanner: 'semgrep',
    status: 'PATCH_PROPOSED',
    createdAt: '2026-10-31T02:00:00.000Z',
  },
  {
    id: 'find_03',
    title: 'Prototype Pollution CVE-2021-3918',
    ruleId: 'npm.audit.cve-2021-3918',
    category: 'VULNERABLE_DEPENDENCY',
    severity: 'HIGH',
    confidence: 'HIGH',
    filePath: 'package.json',
    startLine: 18,
    scanner: 'npm-audit',
    status: 'TRIAGED',
    createdAt: '2026-10-31T03:00:00.000Z',
  },
  {
    id: 'find_04',
    title: 'Hard-coded secret key',
    ruleId: 'security.secrets.jwt',
    category: 'HARDCODED_SECRET',
    severity: 'MEDIUM',
    confidence: 'LOW',
    filePath: 'src/config/jwt.js',
    startLine: 12,
    scanner: 'semgrep',
    status: 'VERIFIED',
    createdAt: '2026-10-31T04:00:00.000Z',
  },
];

test('Findings Filtering & Sorting (Commit 17)', async (t) => {
  await t.test('filters strictly by severity', () => {
    const criticalOnly = filterAndSortFindings(mockFindings, { severity: 'CRITICAL' });
    assert.equal(criticalOnly.length, 1);
    assert.equal(criticalOnly[0].id, 'find_01');

    const highOnly = filterAndSortFindings(mockFindings, { severity: 'HIGH' });
    assert.equal(highOnly.length, 2);
  });

  await t.test('filters strictly by category', () => {
    const xssOnly = filterAndSortFindings(mockFindings, { category: 'XSS' });
    assert.equal(xssOnly.length, 1);
    assert.equal(xssOnly[0].id, 'find_02');
  });

  await t.test('filters strictly by scanner provenance', () => {
    const semgrepOnly = filterAndSortFindings(mockFindings, { scanner: 'semgrep' });
    assert.equal(semgrepOnly.length, 3);

    const npmAuditOnly = filterAndSortFindings(mockFindings, { scanner: 'npm-audit' });
    assert.equal(npmAuditOnly.length, 1);
    assert.equal(npmAuditOnly[0].id, 'find_03');
  });

  await t.test('filters strictly by remediation status', () => {
    const verifiedOnly = filterAndSortFindings(mockFindings, { status: 'VERIFIED' });
    assert.equal(verifiedOnly.length, 1);
    assert.equal(verifiedOnly[0].id, 'find_04');
  });

  await t.test('filters by file path substring', () => {
    const controllerOnly = filterAndSortFindings(mockFindings, { file: 'controllers/' });
    assert.equal(controllerOnly.length, 1);
    assert.equal(controllerOnly[0].id, 'find_02');
  });

  await t.test('searches across title, rule ID, and finding ID', () => {
    const byRule = filterAndSortFindings(mockFindings, { search: 'sql-injection' });
    assert.equal(byRule.length, 1);
    assert.equal(byRule[0].id, 'find_01');

    const byId = filterAndSortFindings(mockFindings, { search: 'find_03' });
    assert.equal(byId.length, 1);
    assert.equal(byId[0].id, 'find_03');
  });

  await t.test('sorts by severity in descending order by default', () => {
    const sorted = filterAndSortFindings(mockFindings, {}, { key: 'severity', direction: 'desc' });
    assert.equal(sorted[0].severity, 'CRITICAL');
    assert.equal(sorted[sorted.length - 1].severity, 'MEDIUM');
  });

  await t.test('sorts by file path alphabetically', () => {
    const sorted = filterAndSortFindings(mockFindings, {}, { key: 'file', direction: 'asc' });
    assert.equal(sorted[0].filePath, 'package.json');
    assert.equal(sorted[sorted.length - 1].filePath, 'src/routes/user.js');
  });
});
