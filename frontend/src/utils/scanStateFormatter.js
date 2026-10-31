/**
 * VULNEX Scan State Formatter & Truthful UI Contract
 *
 * Implements:
 * 1. Explicit UI state determination:
 *    - LOADING, RETRYING, SUCCESS, EMPTY, PARTIAL_FAILURE, COMPLETE_FAILURE, API_ERROR, IDLE
 * 2. Truthful metrics and scanner status representation (no invented progress or fake success)
 * 3. Client-side error sanitization (no stack traces, credentials, or internal secrets)
 * 4. Preservation of partial findings when one scanner fails
 */

export const SCAN_UI_STATES = Object.freeze({
  IDLE: 'IDLE',
  LOADING: 'LOADING',
  RETRYING: 'RETRYING',
  SUCCESS: 'SUCCESS',
  EMPTY: 'EMPTY',
  PARTIAL_FAILURE: 'PARTIAL_FAILURE',
  COMPLETE_FAILURE: 'COMPLETE_FAILURE',
  API_ERROR: 'API_ERROR',
});

/**
 * Strips stack traces, credentials, tokens, and host paths from user-visible error text.
 *
 * @param {string|Error|Object} err
 * @returns {string} Sanitized, client-safe error message
 */
export function sanitizeDisplayError(err) {
  if (!err) return 'An unexpected error occurred.';
  let raw = '';
  if (typeof err === 'string') {
    raw = err;
  } else if (typeof err === 'object' && err !== null) {
    if (typeof err.error === 'string') {
      raw = err.error;
    } else if (typeof err.message === 'string') {
      raw = err.message;
    } else if (err.error && typeof err.error === 'object' && typeof err.error.message === 'string') {
      raw = err.error.message;
    } else {
      raw = typeof err.toString === 'function' && err.toString() !== '[object Object]'
        ? err.toString()
        : JSON.stringify(err);
    }
  } else {
    raw = String(err);
  }

  // 1. Strip stack traces (lines starting with 'at ...' or containing stack traces)
  let primaryLine = raw.split(/\r?\n/)[0] || '';
  primaryLine = primaryLine.replace(/\s+at\s+[\w$.<>]+\s+\([^)]+:\d+:\d+\)$/, '').trim();

  // 2. Strip user directory host paths (/Users/..., /home/..., C:\...)
  let sanitized = primaryLine.replace(/(?:\/Users\/|\/home\/|[A-Za-z]:[\\/]Users[\\/])[^/\\]+[/\\]?/g, '~/');

  // 3. Redact AWS credentials
  sanitized = sanitized.replace(/\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{12,24}\b/g, '[REDACTED_AWS_KEY]');

  // 4. Redact GitHub / OAuth tokens
  sanitized = sanitized.replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b/g, '[REDACTED_TOKEN]');
  sanitized = sanitized.replace(/\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, '[REDACTED_TOKEN]');

  // 5. Redact Bearer / JWT tokens
  sanitized = sanitized.replace(/Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g, 'Bearer [REDACTED_TOKEN]');
  sanitized = sanitized.replace(/\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b/g, 'Bearer [REDACTED_TOKEN]');

  // 6. Redact Database connection URIs
  sanitized = sanitized.replace(/((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis(?:s)?|amqp(?:s)?):\/\/[^:\s\/]+:)([^@\s\/]+)(@)/gi, '$1[REDACTED_PASSWORD]$3');

  // 7. Redact generic password/secret assignments
  sanitized = sanitized.replace(/(password|passwd|pwd|secret|api_key|apikey|token)\s*([:=])\s*(['"`]?)(?!\[REDACTED_)[^\s'"`\r\n]{4,}\3/gi, '$1$2$3[REDACTED_SECRET]$3');

  return sanitized || 'An unexpected error occurred.';
}

/**
 * Determines the truthful UI state from current execution parameters.
 * Strict rules:
 * - Empty results (0 findings on completed/partial scan) are NEVER shown as failures.
 * - Failed scans are NEVER shown as successful scans.
 * - API errors take precedence if no valid scan completed, or are flagged when a retry fails.
 *
 * @param {Object} params
 * @param {boolean} [params.isScanning=false]
 * @param {boolean} [params.isRetrying=false]
 * @param {Object|null} [params.scanRecord=null]
 * @param {Object|null} [params.error=null]
 * @returns {string} One of SCAN_UI_STATES
 */
export function determineScanUIState({ isScanning = false, isRetrying = false, scanRecord = null, error = null }) {
  if (isRetrying) {
    return SCAN_UI_STATES.RETRYING;
  }

  if (isScanning && !scanRecord) {
    return SCAN_UI_STATES.LOADING;
  }

  // If scan record exists, evaluate actual backend status
  if (scanRecord) {
    const status = String(scanRecord.status || scanRecord.stage || '').toUpperCase();

    if (status === 'FAILED') {
      return SCAN_UI_STATES.COMPLETE_FAILURE;
    }

    if (status === 'PARTIAL') {
      // Partial scan with findings or empty
      const totalFindings = scanRecord.summary?.totalFindings ?? 0;
      if (totalFindings === 0) {
        return SCAN_UI_STATES.EMPTY;
      }
      return SCAN_UI_STATES.PARTIAL_FAILURE;
    }

    if (status === 'COMPLETED' || status === 'NORMALIZING') {
      const totalFindings = scanRecord.summary?.totalFindings ?? 0;
      if (totalFindings === 0) {
        return SCAN_UI_STATES.EMPTY;
      }
      return SCAN_UI_STATES.SUCCESS;
    }

    if (['QUEUED', 'PREPARING', 'SCANNING'].includes(status)) {
      return SCAN_UI_STATES.LOADING;
    }
  }

  // If no scan record and error is present
  if (error) {
    return SCAN_UI_STATES.API_ERROR;
  }

  return SCAN_UI_STATES.IDLE;
}

/**
 * Formats scanner execution breakdown using actual backend response data.
 * Identifies which scanners succeeded and which failed.
 *
 * @param {Object|null} scanRecord
 * @returns {Array<{ name: string, label: string, status: 'SUCCESS'|'FAILED'|'SKIPPED', error: string|null, version: string|null }>}
 */
export function formatScannerStatusList(scanRecord) {
  if (!scanRecord || typeof scanRecord !== 'object') return [];

  const summary = scanRecord.summary || {};
  const rawScannersRun = Array.isArray(summary.scannersRun) ? summary.scannersRun : [];
  const rawScannersFailed = Array.isArray(summary.scannersFailed) ? summary.scannersFailed : [];
  const scannerErrors = Array.isArray(summary.errors) ? summary.errors : [];
  const toolVersions = scanRecord.toolVersions || scanRecord.scan?.toolVersions || {};

  // Build normalized failed scanner mapping: string name -> error message string
  const failedScannerMap = new Map();
  for (const item of rawScannersFailed) {
    if (!item) continue;
    if (typeof item === 'object') {
      const name = item.scanner ? String(item.scanner) : 'unknown';
      const err = item.error ? sanitizeDisplayError(item.error) : 'Scanner execution failed';
      failedScannerMap.set(name, err);
    } else {
      failedScannerMap.set(String(item), null);
    }
  }

  // Build normalized run scanner set of string names
  const runScannerSet = new Set(
    rawScannersRun.map((s) => (typeof s === 'object' && s !== null ? String(s.scanner || '') : String(s))).filter(Boolean)
  );

  const allScanners = new Set([
    ...runScannerSet,
    ...failedScannerMap.keys(),
    ...Object.keys(toolVersions),
  ]);

  // If no scanners listed, fallback to events
  if (allScanners.size === 0 && Array.isArray(scanRecord.events)) {
    for (const evt of scanRecord.events) {
      if (evt.stage && typeof evt.stage === 'string') {
        allScanners.add(evt.stage.toLowerCase());
      }
    }
  }

  const SCANNER_LABELS = {
    semgrep: 'Semgrep SAST',
    'npm-audit': 'npm Dependency Audit',
    patterns: 'Deterministic Pattern Engine',
    deterministic: 'Deterministic Pattern Engine',
    'pattern-sast': 'Deterministic Pattern Engine',
  };

  const list = [];
  let errIndex = 0;

  for (const rawScanner of allScanners) {
    const scanner = typeof rawScanner === 'object' && rawScanner !== null
      ? String(rawScanner.scanner || 'unknown')
      : String(rawScanner);

    const isFailed = failedScannerMap.has(scanner);
    const isSuccess = runScannerSet.has(scanner);
    const version = toolVersions[scanner] || null;

    let scannerErr = null;
    if (isFailed) {
      const recordedErr = failedScannerMap.get(scanner);
      if (recordedErr) {
        scannerErr = recordedErr;
      } else if (scannerErrors[errIndex]) {
        scannerErr = sanitizeDisplayError(scannerErrors[errIndex]);
        errIndex++;
      } else {
        scannerErr = 'Scanner execution failed';
      }
    }

    list.push({
      name: scanner,
      label: SCANNER_LABELS[scanner] || (scanner ? scanner.toUpperCase() : 'Scanner'),
      status: isFailed ? 'FAILED' : (isSuccess ? 'SUCCESS' : 'SKIPPED'),
      error: scannerErr ? String(scannerErr) : null,
      version: typeof version === 'string' ? version : null,
    });
  }

  return list;
}

/**
 * Extracts and calculates scan metrics strictly from actual backend response.
 * Never invents durations, completion percentages, or finding counts.
 *
 * @param {Object|null} scanRecord
 * @returns {{ totalFindings: number, bySeverity: Object, startedAt: string|null, completedAt: string|null, durationMs: number|null }}
 */
export function formatScanMetrics(scanRecord) {
  if (!scanRecord) {
    return {
      totalFindings: 0,
      bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      startedAt: null,
      completedAt: null,
      durationMs: null,
    };
  }

  const summary = scanRecord.summary || {};
  const totalFindings = typeof summary.totalFindings === 'number' ? summary.totalFindings : 0;
  const bySeverity = summary.bySeverity || {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  const startedAt = scanRecord.startedAt || scanRecord.createdAt || null;
  const completedAt = scanRecord.completedAt || null;

  let durationMs = null;
  if (startedAt && completedAt) {
    const start = new Date(startedAt).getTime();
    const end = new Date(completedAt).getTime();
    if (!isNaN(start) && !isNaN(end) && end >= start) {
      durationMs = end - start;
    }
  }

  return {
    totalFindings,
    bySeverity,
    startedAt,
    completedAt,
    durationMs,
  };
}
