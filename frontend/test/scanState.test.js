import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ScanStateView from '../src/components/common/ScanStateView.js';
import {
  SCAN_UI_STATES,
  determineScanUIState,
  sanitizeDisplayError,
  formatScannerStatusList,
  formatScanMetrics,
} from '../src/utils/scanStateFormatter.js';

const h = React.createElement;

test('Asynchronous Scan State & Truthful UI Contract (Commit 44)', async (t) => {
  await t.test('1. Initial Loading State: renders spinner and truthful stage without invented metrics', () => {
    const uiState = determineScanUIState({ isScanning: true, scanRecord: null });
    assert.equal(uiState, SCAN_UI_STATES.LOADING);

    const html = renderToStaticMarkup(
      h(ScanStateView, {
        isScanning: true,
        scanRecord: { stage: 'SCANNING' },
      })
    );

    assert.ok(html.includes('data-testid="state-loading"'), 'Must render loading testid');
    assert.ok(html.includes('Executing Security Scanners'), 'Must have truthful title');
    assert.ok(html.includes('Active Phase: <strong>SCANNING</strong>'), 'Must display active backend phase');
    // Verify no fake percentages or invented metrics
    assert.ok(!html.includes('100%') && !html.includes('75%') && !html.includes('progress-bar'), 'Must not invent fake progress percentage');
  });

  await t.test('2. Empty Scan Results State: clean repo (0 findings) is never displayed as failure', () => {
    const cleanRecord = {
      id: 'scan_clean_001',
      status: 'COMPLETED',
      summary: {
        totalFindings: 0,
        scannersRun: ['semgrep', 'npm-audit'],
        scannersFailed: [],
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      },
    };

    const uiState = determineScanUIState({ scanRecord: cleanRecord });
    assert.equal(uiState, SCAN_UI_STATES.EMPTY, 'Clean scan must evaluate to EMPTY');
    assert.notEqual(uiState, SCAN_UI_STATES.COMPLETE_FAILURE, 'Clean scan must never be failure');

    const html = renderToStaticMarkup(
      h(ScanStateView, {
        scanRecord: cleanRecord,
        onReset: () => {},
      })
    );

    assert.ok(html.includes('data-testid="state-empty"'), 'Must render empty state testid');
    assert.ok(html.includes('CLEAN - 0 FINDINGS'), 'Must display clean banner');
    assert.ok(html.includes('No Security Vulnerabilities Detected'), 'Must state clean status');
    assert.ok(html.includes('Semgrep SAST'), 'Must list executed clean scanner');
    assert.ok(html.includes('npm Dependency Audit'), 'Must list executed clean scanner');
    assert.ok(!html.includes('FAILED'), 'Must not show failure in clean scan');
  });

  await t.test('3. Partial Scanner Failure State: displays partial results and preserves healthy scanner findings', () => {
    const partialRecord = {
      id: 'scan_partial_002',
      status: 'PARTIAL',
      summary: {
        totalFindings: 2,
        scannersRun: ['semgrep'],
        scannersFailed: ['npm-audit'],
        errors: ['npm audit returned exit code 1: network ETIMEDOUT'],
        bySeverity: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      },
    };

    const uiState = determineScanUIState({ scanRecord: partialRecord });
    assert.equal(uiState, SCAN_UI_STATES.PARTIAL_FAILURE);

    let retryClicked = false;
    let viewClicked = false;

    const html = renderToStaticMarkup(
      h(ScanStateView, {
        scanRecord: partialRecord,
        onRetry: () => { retryClicked = true; },
        onViewFindings: () => { viewClicked = true; },
      })
    );

    assert.ok(html.includes('data-testid="state-partial-failure"'), 'Must render partial failure testid');
    assert.ok(html.includes('PARTIAL_RESULTS'), 'Must display partial results badge');
    assert.ok(html.includes('2 findings preserved from operational scanners'), 'Must state preserved count');
    assert.ok(html.includes('Semgrep SAST'), 'Must list Semgrep');
    assert.ok(html.includes('SUCCESS'), 'Semgrep must be marked SUCCESS');
    assert.ok(html.includes('npm Dependency Audit'), 'Must list npm audit');
    assert.ok(html.includes('FAILED'), 'npm audit must be marked FAILED');
    assert.ok(html.includes('Retry Failed Scanners'), 'Must provide retry action button');
    assert.ok(html.includes('View Preserved Findings'), 'Must provide view findings CTA');
  });

  await t.test('4. Complete Scan Failure State: clearly identified as failed, never shown as success', () => {
    const failedRecord = {
      id: 'scan_failed_003',
      status: 'FAILED',
      errorCode: 'ORCHESTRATOR_HALTED',
      summary: {
        totalFindings: 0,
        scannersRun: [],
        scannersFailed: ['semgrep', 'npm-audit'],
        errors: ['Semgrep syntax crash at line 1', 'npm audit missing package-lock.json'],
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      },
    };

    const uiState = determineScanUIState({ scanRecord: failedRecord });
    assert.equal(uiState, SCAN_UI_STATES.COMPLETE_FAILURE);
    assert.notEqual(uiState, SCAN_UI_STATES.SUCCESS, 'Failed scan must never be SUCCESS');

    const html = renderToStaticMarkup(
      h(ScanStateView, {
        scanRecord: failedRecord,
        onRetry: () => {},
      })
    );

    assert.ok(html.includes('data-testid="state-complete-failure"'), 'Must render complete failure testid');
    assert.ok(html.includes('Scan Execution Failed'), 'Must state scan failed');
    assert.ok(html.includes('ORCHESTRATOR_HALTED'), 'Must display error code');
    assert.ok(html.includes('Retry Scan'), 'Must provide retry action');
    assert.ok(!html.includes('Deterministic Scan Completed'), 'Must not claim scan completed successfully');
  });

  await t.test('5. API / Network Error State: renders connection failure with code and retry action', () => {
    const apiError = {
      code: 'NETWORK_TIMEOUT',
      message: 'Failed to connect to VULNEX backend orchestrator at localhost:3001',
      requestId: 'req_err_999',
    };

    const uiState = determineScanUIState({ scanRecord: null, error: apiError });
    assert.equal(uiState, SCAN_UI_STATES.API_ERROR);

    const html = renderToStaticMarkup(
      h(ScanStateView, {
        scanRecord: null,
        error: apiError,
        onRetry: () => {},
      })
    );

    assert.ok(html.includes('data-testid="state-api-error"'), 'Must render API error testid');
    assert.ok(html.includes('API Connection Error'), 'Must describe API error');
    assert.ok(html.includes('NETWORK_TIMEOUT'), 'Must show error code');
    assert.ok(html.includes('req_err_999'), 'Must show request ID');
    assert.ok(html.includes('Retry Request'), 'Must have retry button');
  });

  await t.test('6. Retry In Progress State: disables buttons and displays retry spinner', () => {
    const uiState = determineScanUIState({ isRetrying: true });
    assert.equal(uiState, SCAN_UI_STATES.RETRYING);

    const html = renderToStaticMarkup(
      h(ScanStateView, {
        isRetrying: true,
        scanRecord: { id: 'scan_prev_001' },
      })
    );

    assert.ok(html.includes('data-testid="state-retrying"'), 'Must render retrying testid');
    assert.ok(html.includes('Retrying Scan Execution'), 'Must describe retry');
    assert.ok(html.includes('disabled=""') || html.includes('disabled'), 'Retry action must be disabled while retrying');
  });

  await t.test('7. Successful Retry: simulates transition from failure/partial to success', () => {
    // 1. Initial State: Complete failure
    const failedRecord = {
      id: 'scan_initial_fail',
      status: 'FAILED',
      summary: { totalFindings: 0, scannersRun: [], scannersFailed: ['semgrep'] },
    };
    assert.equal(determineScanUIState({ scanRecord: failedRecord }), SCAN_UI_STATES.COMPLETE_FAILURE);

    // 2. Retry In Progress
    assert.equal(determineScanUIState({ isRetrying: true, scanRecord: failedRecord }), SCAN_UI_STATES.RETRYING);

    // 3. Retry Succeeded
    const resolvedRecord = {
      id: 'scan_resolved_ok',
      status: 'COMPLETED',
      summary: {
        totalFindings: 1,
        scannersRun: ['semgrep', 'npm-audit'],
        scannersFailed: [],
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      },
    };
    assert.equal(determineScanUIState({ isRetrying: false, scanRecord: resolvedRecord }), SCAN_UI_STATES.SUCCESS);

    const html = renderToStaticMarkup(
      h(ScanStateView, {
        scanRecord: resolvedRecord,
        onViewFindings: () => {},
      })
    );

    assert.ok(html.includes('data-testid="state-success"'), 'Must render success state');
    assert.ok(html.includes('Deterministic Scan Completed'), 'Must display completed banner');
    assert.ok(html.includes('1 unique security findings detected'), 'Must display truthful finding count');
  });

  await t.test('8. Failed Retry: preserves existing scan findings when retry fails', () => {
    // Initial partial scan with 4 findings
    const initialPartialRecord = {
      id: 'scan_partial_persisted',
      status: 'PARTIAL',
      summary: {
        totalFindings: 4,
        scannersRun: ['semgrep'],
        scannersFailed: ['npm-audit'],
        errors: ['npm-audit failed'],
        bySeverity: { CRITICAL: 2, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 },
      },
    };

    // Retry fails with network error
    const retryError = new Error('Retry connection timed out');

    // UI state with existing record and new retry error
    const uiState = determineScanUIState({
      isRetrying: false,
      scanRecord: initialPartialRecord,
      error: retryError,
    });

    // Partial failure remains preserved
    assert.equal(uiState, SCAN_UI_STATES.PARTIAL_FAILURE);

    const html = renderToStaticMarkup(
      h(ScanStateView, {
        scanRecord: initialPartialRecord,
        error: retryError,
        onRetry: () => {},
      })
    );

    assert.ok(html.includes('data-testid="state-partial-failure"'), 'Must render partial failure view');
    assert.ok(html.includes('4 findings preserved from operational scanners'), 'Preserved findings must remain visible');
    assert.ok(html.includes('Retry connection timed out'), 'Must show latest sanitized retry error');
    assert.ok(!html.includes('disabled'), 'Retry button must be re-enabled for another try');
  });

  await t.test('9. Secret and Stack Trace Redaction: cleans credentials and traces from user view', () => {
    const sensitiveError = new Error(
      'Database connection failed: postgres://admin:super_secret_pw@db.corp.internal:5432/vulnex\n' +
      '  at Connection.connect (/Users/alice/Desktop/VULNEX/node_modules/pg/lib/connection.js:12:34)\n' +
      '  at async ScanEngine.execute (C:\\Users\\Bob\\app.js:50:5)'
    );

    const sanitized = sanitizeDisplayError(sensitiveError);
    assert.ok(!sanitized.includes('super_secret_pw'), 'Must redact database password');
    assert.ok(sanitized.includes('[REDACTED_PASSWORD]'), 'Must replace with placeholder');
    assert.ok(!sanitized.includes('/Users/alice/'), 'Must redact user home directory');
    assert.ok(!sanitized.includes('at Connection.connect'), 'Must strip stack trace');

    // Test token and AWS key redaction
    const fakeToken = ['ghp', '123456789012345678901234567890123456'].join('_');
    const fakeKey = ['AK', 'IA', 'IOSFODNN7EXAMPLE'].join('');
    const tokenErr = `Failed with token: ${fakeToken} and key ${fakeKey}`;
    const sanitizedToken = sanitizeDisplayError(tokenErr);
    assert.ok(!sanitizedToken.includes(fakeToken));
    assert.ok(sanitizedToken.includes('[REDACTED_TOKEN]'));
    assert.ok(!sanitizedToken.includes(fakeKey));
    assert.ok(sanitizedToken.includes('[REDACTED_AWS_KEY]'));
  });

  await t.test('10. formatScanMetrics: truthful metrics without invented durations or percentages', () => {
    // Both timestamps present -> calculates exact duration
    const validMetrics = formatScanMetrics({
      startedAt: '2026-10-31T12:00:00.000Z',
      completedAt: '2026-10-31T12:00:04.500Z',
      summary: { totalFindings: 5, bySeverity: { CRITICAL: 1, HIGH: 2, MEDIUM: 2, LOW: 0, INFO: 0 } },
    });
    assert.equal(validMetrics.durationMs, 4500);
    assert.equal(validMetrics.totalFindings, 5);

    // Missing completedAt -> durationMs is null (never invented or estimated)
    const incompleteMetrics = formatScanMetrics({
      startedAt: '2026-10-31T12:00:00.000Z',
      completedAt: null,
      summary: { totalFindings: 0 },
    });
    assert.equal(incompleteMetrics.durationMs, null);

    // Empty record
    const emptyMetrics = formatScanMetrics(null);
    assert.equal(emptyMetrics.totalFindings, 0);
    assert.equal(emptyMetrics.durationMs, null);
  });

  await t.test('11. Object scannersFailed handling: renders cleanly when scannersFailed contains objects { scanner, error }', () => {
    const scanRecordWithObjectErrors = {
      id: 'scan_with_object_errors',
      status: 'PARTIAL',
      summary: {
        totalFindings: 3,
        scannersRun: ['deterministic'],
        scannersFailed: [
          { scanner: 'semgrep', error: 'Semgrep CLI binary not detected on PATH' },
          { scanner: 'npm-audit', error: 'npm audit returned exit code 1' }
        ],
        bySeverity: { CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 },
      },
    };

    // 1. Check formatted scanner list has string labels and errors, never objects
    const scannerList = formatScannerStatusList(scanRecordWithObjectErrors);
    assert.equal(scannerList.length, 3);
    for (const item of scannerList) {
      assert.equal(typeof item.name, 'string', 'name must be string');
      assert.equal(typeof item.label, 'string', 'label must be string');
      if (item.error) {
        assert.equal(typeof item.error, 'string', 'error must be string');
      }
    }

    // 2. Render to static markup - must NOT throw React child exception
    const html = renderToStaticMarkup(
      h(ScanStateView, {
        scanRecord: scanRecordWithObjectErrors,
        onRetry: () => {},
        onViewFindings: () => {},
      })
    );

    assert.ok(html.includes('Semgrep SAST'), 'Must render Semgrep label');
    assert.ok(html.includes('Semgrep CLI binary not detected on PATH'), 'Must render Semgrep error string');
    assert.ok(html.includes('npm Dependency Audit'), 'Must render npm audit label');
    assert.ok(html.includes('Deterministic Pattern Engine'), 'Must render deterministic engine');
    assert.ok(!html.includes('[object Object]'), 'Must never render [object Object]');
  });
});
