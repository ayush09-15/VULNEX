import test from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, vulnexApi } from '../src/services/api.js';
import { formatScannerStatusList } from '../src/utils/scanStateFormatter.js';

test('ApiError encapsulates canonical error attributes', () => {
  const err = new ApiError('Repository URL not supported', {
    code: 'INVALID_URL',
    status: 400,
    requestId: 'req_test_123',
    details: [{ field: 'sourceUrl', issue: 'Private IP disallowed' }],
  });

  assert.equal(err.name, 'ApiError');
  assert.equal(err.message, 'Repository URL not supported');
  assert.equal(err.code, 'INVALID_URL');
  assert.equal(err.status, 400);
  assert.equal(err.requestId, 'req_test_123');
  assert.equal(err.isApiError, true);
  assert.equal(err.details.length, 1);
});

test('vulnexApi exposes canonical domain resource handlers', () => {
  assert.equal(typeof vulnexApi.health.check, 'function');
  assert.equal(typeof vulnexApi.repositories.list, 'function');
  assert.equal(typeof vulnexApi.repositories.get, 'function');
  assert.equal(typeof vulnexApi.repositories.register, 'function');
  assert.equal(typeof vulnexApi.scans.list, 'function');
  assert.equal(typeof vulnexApi.scans.start, 'function');
  assert.equal(typeof vulnexApi.scans.get, 'function');
  assert.equal(typeof vulnexApi.scans.getEvents, 'function');
  assert.equal(typeof vulnexApi.scans.getFindings, 'function');
  assert.equal(typeof vulnexApi.scans.getReport, 'function');
  assert.equal(typeof vulnexApi.findings.list, 'function');
  assert.equal(typeof vulnexApi.findings.get, 'function');
  assert.equal(typeof vulnexApi.findings.investigate, 'function');
  assert.equal(typeof vulnexApi.findings.generatePatch, 'function');
  assert.equal(typeof vulnexApi.patches.list, 'function');
  assert.equal(typeof vulnexApi.patches.get, 'function');
  assert.equal(typeof vulnexApi.patches.approve, 'function');
  assert.equal(typeof vulnexApi.patches.reject, 'function');
  assert.equal(typeof vulnexApi.patches.apply, 'function');
  assert.equal(typeof vulnexApi.patches.verify, 'function');
  assert.equal(typeof vulnexApi.patches.rollback, 'function');
  assert.equal(typeof vulnexApi.scans.cancel, 'function');
  assert.equal(typeof vulnexApi.scans.delete, 'function');
});

test('formatScannerStatusList handles scannersFailed array of objects safely', () => {
  const scanRecord = {
    summary: {
      scannersRun: ['pattern-sast'],
      scannersFailed: [
        {
          scanner: 'npm-audit',
          error: 'Process execution error for "npm": spawn npm ENOENT'
        }
      ]
    }
  };

  const list = formatScannerStatusList(scanRecord);
  assert.equal(list.length, 2);

  const npmAudit = list.find((s) => s.name === 'npm-audit');
  assert.ok(npmAudit);
  assert.equal(typeof npmAudit.label, 'string');
  assert.equal(npmAudit.label, 'npm Dependency Audit');
  assert.equal(npmAudit.status, 'FAILED');
  assert.equal(typeof npmAudit.error, 'string');
  assert.ok(npmAudit.error.includes('npm ENOENT'));
});
