import React from 'react';
import {
  Loader2,
  CheckCircle2,
  AlertTriangle,
  AlertCircle,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  RotateCcw,
  RefreshCw,
  Terminal,
} from 'lucide-react';
import {
  SCAN_UI_STATES,
  determineScanUIState,
  sanitizeDisplayError,
  formatScannerStatusList,
  formatScanMetrics,
} from '../../utils/scanStateFormatter.js';

const h = React.createElement;

/**
 * ScanStateView Component
 * Renders explicit, truthful asynchronous scan states:
 * - Loading
 * - Empty (Clean, 0 findings)
 * - Successful with findings
 * - Partial scanner failure with preserved findings
 * - Complete scan failure
 * - API / Network error
 * - Retry in progress
 */
export default function ScanStateView({
  scanRecord = null,
  error = null,
  isScanning = false,
  isRetrying = false,
  onRetry = null,
  onViewFindings = null,
  onReset = null,
}) {
  const uiState = determineScanUIState({
    isScanning,
    isRetrying,
    scanRecord,
    error,
  });

  const metrics = formatScanMetrics(scanRecord);
  const scannerList = formatScannerStatusList(scanRecord);
  const displayError = error
    ? sanitizeDisplayError(error)
    : scanRecord?.summary?.errors?.[0]
    ? sanitizeDisplayError(scanRecord.summary.errors[0])
    : null;

  // 1. Initial Loading State
  if (uiState === SCAN_UI_STATES.LOADING) {
    const stage = scanRecord?.stage || 'SCANNING';
    return h(
      'div',
      {
        'data-testid': 'state-loading',
        className: 'p-8 rounded-2xl bg-slate-900/60 border border-slate-800 text-center space-y-4 animate-pulse',
      },
      h(
        'div',
        {
          className:
            'w-12 h-12 rounded-2xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center mx-auto text-cyan-400',
        },
        h(Loader2, { className: 'w-6 h-6 animate-spin' })
      ),
      h(
        'div',
        null,
        h('h3', { className: 'text-base font-bold text-slate-100' }, 'Executing Security Scanners'),
        h(
          'p',
          { className: 'text-xs text-slate-400 mt-1 max-w-md mx-auto' },
          'Orchestrating active scanners against workspace. Awaiting truthful backend results.'
        )
      ),
      h(
        'div',
        {
          className:
            'inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-950 border border-cyan-800/40 text-[11px] font-mono text-cyan-300',
        },
        h('span', { className: 'w-2 h-2 rounded-full bg-cyan-400 animate-ping' }),
        h('span', null, 'Active Phase: ', h('strong', null, stage))
      )
    );
  }

  // 2. Retry In Progress State
  if (uiState === SCAN_UI_STATES.RETRYING) {
    return h(
      'div',
      {
        'data-testid': 'state-retrying',
        className: 'p-8 rounded-2xl bg-slate-900/60 border border-cyan-800/60 text-center space-y-4',
      },
      h(
        'div',
        {
          className:
            'w-12 h-12 rounded-2xl bg-cyan-950 border border-cyan-500 flex items-center justify-center mx-auto text-cyan-400',
        },
        h(RefreshCw, { className: 'w-6 h-6 animate-spin' })
      ),
      h(
        'div',
        null,
        h('h3', { className: 'text-base font-bold text-cyan-200' }, 'Retrying Scan Execution'),
        h(
          'p',
          { className: 'text-xs text-slate-400 mt-1 max-w-md mx-auto' },
          'Re-dispatching scan request to backend orchestrator. Existing data preserved.'
        )
      ),
      h(
        'button',
        {
          type: 'button',
          disabled: true,
          className:
            'inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 text-slate-400 text-xs font-mono cursor-not-allowed border border-slate-700',
        },
        h(Loader2, { className: 'w-3.5 h-3.5 animate-spin' }),
        h('span', null, 'Retry in Progress...')
      )
    );
  }

  // 3. API / Network Error State (No valid scan record)
  if (uiState === SCAN_UI_STATES.API_ERROR && !scanRecord) {
    const errorCode = error?.code || 'NETWORK_ERROR';
    const requestId = error?.requestId || null;

    return h(
      'div',
      {
        'data-testid': 'state-api-error',
        className: 'p-6 rounded-2xl bg-red-950/40 border border-red-800/80 space-y-4',
      },
      h(
        'div',
        { className: 'flex items-start gap-3' },
        h(
          'div',
          {
            className:
              'w-10 h-10 rounded-xl bg-red-900/40 border border-red-700/60 flex items-center justify-center text-red-400 shrink-0 mt-0.5',
          },
          h(AlertCircle, { className: 'w-5 h-5' })
        ),
        h(
          'div',
          { className: 'flex-1 space-y-1' },
          h(
            'div',
            { className: 'flex items-center gap-2 flex-wrap' },
            h('span', { className: 'text-xs font-bold text-red-200' }, 'API Connection Error'),
            h(
              'span',
              { className: 'font-mono text-[10px] px-1.5 py-0.5 rounded bg-red-900/60 border border-red-700 text-red-300' },
              errorCode
            ),
            requestId &&
              h(
                'span',
                { className: 'font-mono text-[10px] text-slate-400' },
                `Request ID: ${requestId}`
              )
          ),
          h('p', { className: 'text-xs text-red-300/90 leading-relaxed' }, displayError)
        )
      ),
      onRetry &&
        h(
          'div',
          { className: 'pt-2 flex items-center gap-3' },
          h(
            'button',
            {
              type: 'button',
              onClick: onRetry,
              disabled: isRetrying || isScanning,
              className: `inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold shadow transition-all ${
                isRetrying || isScanning
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  : 'bg-red-800 hover:bg-red-700 active:scale-[0.98] text-white border border-red-600'
              }`,
            },
            h(RotateCcw, { className: 'w-3.5 h-3.5' }),
            h('span', null, isRetrying ? 'Retrying...' : 'Retry Request')
          ),
          onReset &&
            h(
              'button',
              {
                type: 'button',
                onClick: onReset,
                className:
                  'px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors',
              },
              'Reset'
            )
        )
    );
  }

  // 4. Complete Scan Failure State
  if (uiState === SCAN_UI_STATES.COMPLETE_FAILURE) {
    const errorCode = scanRecord?.errorCode || error?.code || 'SCANNER_FAILURE';

    return h(
      'div',
      {
        'data-testid': 'state-complete-failure',
        className: 'p-6 rounded-2xl bg-red-950/40 border border-red-800/80 space-y-4',
      },
      h(
        'div',
        { className: 'flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-red-900/40 pb-3' },
        h(
          'div',
          { className: 'flex items-center gap-3' },
          h(
            'div',
            {
              className:
                'w-10 h-10 rounded-xl bg-red-900/50 border border-red-600/60 flex items-center justify-center text-red-300',
            },
            h(ShieldAlert, { className: 'w-5 h-5' })
          ),
          h(
            'div',
            null,
            h(
              'div',
              { className: 'flex items-center gap-2' },
              h(
                'span',
                {
                  className:
                    'px-2 py-0.5 rounded text-[10px] font-bold font-mono tracking-wider uppercase bg-red-900/80 text-red-200 border border-red-700',
                },
                'FAILED'
              ),
              h(
                'span',
                { className: 'text-xs font-mono text-slate-400' },
                'Scan ID: ',
                h('strong', null, scanRecord?.id || 'unknown')
              )
            ),
            h('h3', { className: 'text-sm font-bold text-red-100 mt-0.5' }, 'Scan Execution Failed')
          )
        ),
        onRetry &&
          h(
            'button',
            {
              type: 'button',
              onClick: onRetry,
              disabled: isRetrying || isScanning,
              className: `inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold shadow transition-all ${
                isRetrying || isScanning
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  : 'bg-red-700 hover:bg-red-600 active:scale-[0.98] text-white border border-red-500'
              }`,
            },
            h(RotateCcw, { className: 'w-3.5 h-3.5' }),
            h('span', null, isRetrying ? 'Retrying...' : 'Retry Scan')
          )
      ),
      h(
        'div',
        { className: 'space-y-2 text-xs' },
        h('div', { className: 'flex items-center gap-2 text-red-300 font-semibold font-mono text-[11px]' }, `Error Code: ${errorCode}`),
        h(
          'p',
          { className: 'text-red-300/90 leading-relaxed bg-red-950/60 p-3 rounded-xl border border-red-900/60' },
          displayError || 'All configured security scanners failed to execute.'
        )
      ),
      scannerList.length > 0 &&
        h(
          'div',
          { className: 'pt-2 border-t border-red-900/40' },
          h('div', { className: 'text-[11px] font-mono text-slate-400 mb-2 font-semibold' }, 'Scanner Outcomes:'),
          h(
            'div',
            { className: 'grid grid-cols-1 sm:grid-cols-2 gap-2' },
            scannerList.map((s) =>
              h(
                'div',
                {
                  key: s.name,
                  className: 'p-2.5 rounded-lg bg-slate-950/60 border border-red-900/50 flex items-start gap-2 text-xs',
                },
                h(AlertCircle, { className: 'w-4 h-4 text-red-400 shrink-0 mt-0.5' }),
                h(
                  'div',
                  null,
                  h('div', { className: 'font-semibold text-slate-200' }, s.label),
                  h('div', { className: 'text-[10px] text-red-400 font-mono' }, s.error || 'Execution failed')
                )
              )
            )
          )
        )
    );
  }

  // 5. Empty Scan Results State (Clean Repository)
  if (uiState === SCAN_UI_STATES.EMPTY) {
    return h(
      'div',
      {
        'data-testid': 'state-empty',
        className: 'p-8 rounded-2xl bg-emerald-950/20 border border-emerald-900/40 text-center space-y-4',
      },
      h(
        'div',
        {
          className:
            'w-12 h-12 rounded-2xl bg-emerald-950/80 border border-emerald-500/60 flex items-center justify-center mx-auto text-emerald-400 shadow-inner',
        },
        h(ShieldCheck, { className: 'w-6 h-6' })
      ),
      h(
        'div',
        null,
        h(
          'div',
          {
            className:
              'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono tracking-wider uppercase bg-emerald-950 text-emerald-300 border border-emerald-800 mb-2',
          },
          h('span', null, 'CLEAN - 0 FINDINGS')
        ),
        h('h3', { className: 'text-base font-bold text-slate-100' }, 'No Security Vulnerabilities Detected'),
        h(
          'p',
          { className: 'text-xs text-slate-400 mt-1 max-w-md mx-auto' },
          'All scanned files and dependencies passed active security rules with zero findings detected.'
        )
      ),
      scannerList.length > 0 &&
        h(
          'div',
          { className: 'inline-flex items-center gap-3 pt-2 text-[11px] font-mono text-slate-400' },
          scannerList.map((s) =>
            h(
              'span',
              { key: s.name, className: 'flex items-center gap-1 text-emerald-400' },
              h(CheckCircle2, { className: 'w-3.5 h-3.5' }),
              h('span', null, s.label)
            )
          )
        ),
      h(
        'div',
        { className: 'pt-2 flex items-center justify-center gap-3' },
        onReset &&
          h(
            'button',
            {
              type: 'button',
              onClick: onReset,
              className:
                'px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors',
            },
            'Scan Another Target'
          )
      )
    );
  }

  // 6. Partial Scanner Failure State (Preserved findings from healthy scanners)
  if (uiState === SCAN_UI_STATES.PARTIAL_FAILURE) {
    return h(
      'div',
      {
        'data-testid': 'state-partial-failure',
        className:
          'p-6 rounded-2xl bg-gradient-to-r from-slate-900/90 via-amber-950/20 to-slate-900/60 border border-amber-800/60 space-y-4 shadow-xl',
      },
      h(
        'div',
        { className: 'flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-amber-900/40 pb-4' },
        h(
          'div',
          null,
          h(
            'div',
            { className: 'flex items-center gap-2 mb-1' },
            h(
              'span',
              {
                className:
                  'px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono tracking-wider uppercase bg-amber-950 text-amber-300 border border-amber-800 flex items-center gap-1',
              },
              h(AlertTriangle, { className: 'w-3 h-3 text-amber-400' }),
              h('span', null, 'PARTIAL_RESULTS')
            ),
            h(
              'span',
              { className: 'text-xs font-mono text-slate-400' },
              'Scan ID: ',
              h('strong', { className: 'text-slate-200' }, scanRecord?.id)
            )
          ),
          h(
            'h3',
            { className: 'text-base font-bold text-slate-100 flex items-center gap-2' },
            h('span', null, 'Partial Scanner Failure'),
            h(
              'span',
              { className: 'text-xs font-normal text-amber-300/90' },
              `(${metrics.totalFindings} findings preserved from operational scanners)`
            )
          )
        ),
        h(
          'div',
          { className: 'flex items-center gap-3' },
          onRetry &&
            h(
              'button',
              {
                type: 'button',
                onClick: onRetry,
                disabled: isRetrying || isScanning,
                className: `inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold shadow transition-all ${
                  isRetrying || isScanning
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                    : 'bg-amber-600 hover:bg-amber-500 active:scale-[0.98] text-white border border-amber-400'
                }`,
              },
              h(RotateCcw, { className: 'w-3.5 h-3.5' }),
              h('span', null, isRetrying ? 'Retrying...' : 'Retry Failed Scanners')
            ),
          onViewFindings &&
            h(
              'button',
              {
                type: 'button',
                onClick: onViewFindings,
                className:
                  'inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold shadow-md transition-all group',
              },
              h('span', null, 'View Preserved Findings'),
              h(ArrowRight, { className: 'w-4 h-4 group-hover:translate-x-0.5 transition-transform' })
            )
        )
      ),
      error &&
        h(
          'div',
          { className: 'p-3 rounded-xl bg-amber-950/40 border border-amber-800/80 text-xs text-amber-200 flex items-start gap-2' },
          h(AlertCircle, { className: 'w-4 h-4 text-amber-400 shrink-0 mt-0.5' }),
          h('div', null, h('span', { className: 'font-semibold' }, 'Latest Retry Error: '), displayError)
        ),
      // Scanner Engine Breakdown
      h(
        'div',
        { className: 'space-y-2' },
        h('div', { className: 'text-[11px] font-mono text-slate-400 font-semibold' }, 'Scanner Engine Breakdown:'),
        h(
          'div',
          { className: 'grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5' },
          scannerList.map((s) =>
            h(
              'div',
              {
                key: s.name,
                className: `p-3 rounded-xl border text-xs space-y-1 ${
                  s.status === 'SUCCESS'
                    ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300'
                    : 'bg-amber-950/30 border-amber-800/50 text-amber-300'
                }`,
              },
              h(
                'div',
                { className: 'flex items-center justify-between font-semibold' },
                h(
                  'span',
                  { className: 'flex items-center gap-1.5' },
                  s.status === 'SUCCESS'
                    ? h(CheckCircle2, { className: 'w-3.5 h-3.5 text-emerald-400' })
                    : h(AlertTriangle, { className: 'w-3.5 h-3.5 text-amber-400' }),
                  h('span', null, s.label)
                ),
                h('span', { className: 'font-mono text-[10px] uppercase' }, s.status)
              ),
              s.error &&
                h('p', { className: 'text-[10px] text-amber-400/90 font-mono leading-tight' }, s.error),
              s.status === 'SUCCESS' &&
                h('p', { className: 'text-[10px] text-emerald-400/80 font-mono' }, 'Findings cataloged and normalized')
            )
          )
        )
      ),
      // Severity Metrics Bar
      h(
        'div',
        { className: 'grid grid-cols-2 sm:grid-cols-6 gap-2.5 pt-2 border-t border-slate-800/80' },
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-red-400 font-semibold uppercase' }, 'Critical'),
          h('div', { className: 'text-lg font-extrabold text-red-300 mt-0.5' }, metrics.bySeverity.CRITICAL || 0)
        ),
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-orange-400 font-semibold uppercase' }, 'High'),
          h('div', { className: 'text-lg font-extrabold text-orange-300 mt-0.5' }, metrics.bySeverity.HIGH || 0)
        ),
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-amber-400 font-semibold uppercase' }, 'Medium'),
          h('div', { className: 'text-lg font-extrabold text-amber-300 mt-0.5' }, metrics.bySeverity.MEDIUM || 0)
        ),
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-blue-400 font-semibold uppercase' }, 'Low'),
          h('div', { className: 'text-lg font-extrabold text-blue-300 mt-0.5' }, metrics.bySeverity.LOW || 0)
        ),
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-slate-400 font-semibold uppercase' }, 'Info'),
          h('div', { className: 'text-lg font-extrabold text-slate-300 mt-0.5' }, metrics.bySeverity.INFO || 0)
        ),
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-slate-400 font-semibold uppercase' }, 'Preserved Total'),
          h('div', { className: 'text-lg font-extrabold text-slate-200 mt-0.5' }, metrics.totalFindings)
        )
      )
    );
  }

  // 7. Successful Scan Results State
  if (uiState === SCAN_UI_STATES.SUCCESS) {
    return h(
      'div',
      {
        'data-testid': 'state-success',
        className:
          'p-6 rounded-2xl bg-gradient-to-r from-slate-900/90 via-slate-900/60 to-cyan-950/20 border border-cyan-900/50 space-y-4 animate-slideDown shadow-xl',
      },
      h(
        'div',
        { className: 'flex flex-col md:flex-row items-start md:items-center justify-between gap-4' },
        h(
          'div',
          null,
          h(
            'div',
            { className: 'flex items-center gap-2 mb-1' },
            h(
              'span',
              {
                className:
                  'px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono tracking-wider uppercase bg-emerald-950 text-emerald-300 border border-emerald-800',
              },
              'COMPLETED'
            ),
            h(
              'span',
              { className: 'text-xs font-mono text-slate-400' },
              'Scan ID: ',
              h('strong', { className: 'text-slate-200' }, scanRecord?.id)
            )
          ),
          h(
            'h3',
            { className: 'text-base font-bold text-slate-100 flex items-center gap-2' },
            h('span', null, 'Deterministic Scan Completed'),
            h(
              'span',
              { className: 'text-xs font-normal text-slate-400' },
              `(${metrics.totalFindings} unique security findings detected)`
            )
          )
        ),
        onViewFindings &&
          h(
            'button',
            {
              type: 'button',
              onClick: onViewFindings,
              className:
                'inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold shadow-md transition-all group',
            },
            h('span', null, 'View Findings & Triage Issues'),
            h(ArrowRight, { className: 'w-4 h-4 group-hover:translate-x-0.5 transition-transform' })
          )
      ),
      // Severity Metrics Bar
      h(
        'div',
        { className: 'grid grid-cols-2 sm:grid-cols-6 gap-2.5 pt-2 border-t border-slate-800/80' },
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-red-400 font-semibold uppercase' }, 'Critical'),
          h('div', { className: 'text-lg font-extrabold text-red-300 mt-0.5' }, metrics.bySeverity.CRITICAL || 0)
        ),
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-orange-400 font-semibold uppercase' }, 'High'),
          h('div', { className: 'text-lg font-extrabold text-orange-300 mt-0.5' }, metrics.bySeverity.HIGH || 0)
        ),
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-amber-400 font-semibold uppercase' }, 'Medium'),
          h('div', { className: 'text-lg font-extrabold text-amber-300 mt-0.5' }, metrics.bySeverity.MEDIUM || 0)
        ),
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-blue-400 font-semibold uppercase' }, 'Low'),
          h('div', { className: 'text-lg font-extrabold text-blue-300 mt-0.5' }, metrics.bySeverity.LOW || 0)
        ),
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-slate-400 font-semibold uppercase' }, 'Info'),
          h('div', { className: 'text-lg font-extrabold text-slate-300 mt-0.5' }, metrics.bySeverity.INFO || 0)
        ),
        h(
          'div',
          { className: 'p-3 rounded-xl bg-slate-950/60 border border-slate-800' },
          h('span', { className: 'text-[10px] font-mono text-slate-400 font-semibold uppercase' }, 'Total'),
          h('div', { className: 'text-lg font-extrabold text-slate-200 mt-0.5' }, metrics.totalFindings)
        )
      ),
      // Events Timeline Log
      scanRecord?.events &&
        scanRecord.events.length > 0 &&
        h(
          'div',
          { className: 'pt-2' },
          h(
            'div',
            { className: 'text-[11px] font-mono text-slate-400 mb-2 flex items-center gap-1.5' },
            h(Terminal, { className: 'w-3.5 h-3.5 text-cyan-400' }),
            h('span', null, 'Scan Stage Execution Log')
          ),
          h(
            'div',
            {
              className:
                'max-h-36 overflow-y-auto rounded-lg bg-slate-950/80 p-3 font-mono text-[11px] space-y-1 border border-slate-800/80',
            },
            scanRecord.events.map((evt, idx) =>
              h(
                'div',
                { key: idx, className: 'flex items-center gap-2' },
                h(
                  'span',
                  { className: 'text-slate-600' },
                  new Date(evt.timestamp).toLocaleTimeString()
                ),
                h(
                  'span',
                  {
                    className: `px-1.5 py-0.2 rounded text-[10px] font-semibold ${
                      evt.status === 'SUCCESS'
                        ? 'text-emerald-400 bg-emerald-950/60'
                        : evt.status === 'FAILED'
                        ? 'text-red-400 bg-red-950/60'
                        : 'text-cyan-400 bg-cyan-950/60'
                    }`,
                  },
                  `[${evt.stage}]`
                ),
                h('span', { className: 'text-slate-300' }, evt.message)
              )
            )
          )
        )
    );
  }

  return null;
}
