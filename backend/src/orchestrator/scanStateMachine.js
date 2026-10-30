/**
 * VULNEX Scan State Machine & Transition Guards
 * 
 * Source of Truth:
 * - VULNEX Master Antigravity Execution Bible (Part IV Section 4.10, Part V Section 5.1, Part VIII Section 8.7)
 * - docs/DATA_MODELS.md (Section 3.1: Scan State Machine)
 * - docs/API_CONTRACTS.md (Section 1.2: Machine-Readable Error Codes)
 */

/**
 * Canonical Scan States / Stages
 * @readonly
 * @enum {string}
 */
const SCAN_STATES = Object.freeze({
  QUEUED: 'QUEUED',
  PREPARING: 'PREPARING',
  SCANNING: 'SCANNING',
  NORMALIZING: 'NORMALIZING',
  INVESTIGATING: 'INVESTIGATING',
  COMPLETED: 'COMPLETED',
  PARTIAL: 'PARTIAL',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED'
});

/**
 * Terminal States from which no further transitions are permitted
 * @type {ReadonlySet<string>}
 */
const TERMINAL_STATES = Object.freeze(new Set([
  SCAN_STATES.COMPLETED,
  SCAN_STATES.PARTIAL,
  SCAN_STATES.FAILED,
  SCAN_STATES.CANCELLED
]));

/**
 * Allowed Transition Graph
 * Key: current state -> Value: array of allowed next states
 * @type {Readonly<Record<string, readonly string[]>>}
 */
const ALLOWED_TRANSITIONS = Object.freeze({
  [SCAN_STATES.QUEUED]: Object.freeze([
    SCAN_STATES.PREPARING,
    SCAN_STATES.CANCELLED
  ]),
  [SCAN_STATES.PREPARING]: Object.freeze([
    SCAN_STATES.SCANNING,
    SCAN_STATES.FAILED,
    SCAN_STATES.CANCELLED
  ]),
  [SCAN_STATES.SCANNING]: Object.freeze([
    SCAN_STATES.NORMALIZING,
    SCAN_STATES.FAILED,
    SCAN_STATES.CANCELLED
  ]),
  [SCAN_STATES.NORMALIZING]: Object.freeze([
    SCAN_STATES.INVESTIGATING,
    SCAN_STATES.COMPLETED,
    SCAN_STATES.PARTIAL,
    SCAN_STATES.FAILED,
    SCAN_STATES.CANCELLED
  ]),
  [SCAN_STATES.INVESTIGATING]: Object.freeze([
    SCAN_STATES.COMPLETED,
    SCAN_STATES.PARTIAL,
    SCAN_STATES.FAILED,
    SCAN_STATES.CANCELLED
  ]),
  // Terminal states allow no outbound transitions
  [SCAN_STATES.COMPLETED]: Object.freeze([]),
  [SCAN_STATES.PARTIAL]: Object.freeze([]),
  [SCAN_STATES.FAILED]: Object.freeze([]),
  [SCAN_STATES.CANCELLED]: Object.freeze([])
});

/**
 * Custom error thrown when an invalid state transition is attempted
 */
class InvalidStateTransitionError extends Error {
  /**
   * @param {string} currentStatus
   * @param {string} targetStatus
   * @param {string} [customMessage]
   */
  constructor(currentStatus, targetStatus, customMessage) {
    const message = customMessage || 
      `Invalid scan state transition: Cannot transition from '${currentStatus}' to '${targetStatus}'.`;
    super(message);
    this.name = 'InvalidStateTransitionError';
    this.code = 'INVALID_STATE_TRANSITION';
    this.statusCode = 409;
    this.status = 409;
    this.currentStatus = currentStatus;
    this.targetStatus = targetStatus;
    this.allowedTransitions = ALLOWED_TRANSITIONS[currentStatus] || [];
  }
}

/**
 * Check whether a string represents a known valid scan state
 * @param {string} state
 * @returns {boolean}
 */
function isValidState(state) {
  return typeof state === 'string' && Object.values(SCAN_STATES).includes(state);
}

/**
 * Check whether a state is terminal
 * @param {string} state
 * @returns {boolean}
 */
function isTerminalState(state) {
  return TERMINAL_STATES.has(state);
}

/**
 * Return list of permitted target states from the current state
 * @param {string} currentState
 * @returns {readonly string[]}
 */
function getPermittedTransitions(currentState) {
  if (!isValidState(currentState)) {
    return Object.freeze([]);
  }
  return ALLOWED_TRANSITIONS[currentState] || Object.freeze([]);
}

/**
 * Guard predicate: returns true if the transition is permitted, false otherwise
 * @param {string} currentStatus
 * @param {string} targetStatus
 * @returns {boolean}
 */
function canTransition(currentStatus, targetStatus) {
  if (!isValidState(currentStatus) || !isValidState(targetStatus)) {
    return false;
  }
  const allowed = ALLOWED_TRANSITIONS[currentStatus];
  return Boolean(allowed && allowed.includes(targetStatus));
}

/**
 * Transition guard: asserts that transition is permitted, throwing InvalidStateTransitionError otherwise
 * @param {string} currentStatus
 * @param {string} targetStatus
 * @param {string} [reason]
 * @throws {InvalidStateTransitionError}
 * @returns {true}
 */
function validateTransition(currentStatus, targetStatus, reason) {
  if (!isValidState(currentStatus)) {
    throw new InvalidStateTransitionError(
      currentStatus,
      targetStatus,
      `Invalid scan state transition: Unknown current state '${currentStatus}'.`
    );
  }

  if (!isValidState(targetStatus)) {
    throw new InvalidStateTransitionError(
      currentStatus,
      targetStatus,
      `Invalid scan state transition: Unknown target state '${targetStatus}'.`
    );
  }

  if (isTerminalState(currentStatus)) {
    throw new InvalidStateTransitionError(
      currentStatus,
      targetStatus,
      `Invalid scan state transition: Scan is already in terminal state '${currentStatus}' and cannot transition to '${targetStatus}'.`
    );
  }

  const allowed = ALLOWED_TRANSITIONS[currentStatus] || [];
  if (!allowed.includes(targetStatus)) {
    const allowedStr = allowed.length > 0 ? allowed.join(', ') : 'none';
    const detail = reason ? ` (Reason: ${reason})` : '';
    throw new InvalidStateTransitionError(
      currentStatus,
      targetStatus,
      `Invalid scan state transition: Cannot transition from '${currentStatus}' to '${targetStatus}'${detail}. Allowed transitions: [${allowedStr}].`
    );
  }

  return true;
}

/**
 * Managed Scan State Machine instance
 */
class ScanStateMachine {
  /**
   * @param {string} [initialState=SCAN_STATES.QUEUED]
   * @param {Object} [options={}]
   * @param {string} [options.scanId]
   * @param {Function} [options.onTransition]
   */
  constructor(initialState = SCAN_STATES.QUEUED, options = {}) {
    if (!isValidState(initialState)) {
      throw new Error(`Cannot initialize ScanStateMachine with unknown state: '${initialState}'`);
    }

    this.scanId = options.scanId || null;
    this._state = initialState;
    this._stage = initialState;
    this._onTransition = typeof options.onTransition === 'function' ? options.onTransition : null;
    this._history = [
      {
        from: null,
        to: initialState,
        stage: initialState,
        timestamp: new Date().toISOString(),
        reason: 'Initial state'
      }
    ];
  }

  get state() {
    return this._state;
  }

  get stage() {
    return this._stage;
  }

  get isTerminal() {
    return isTerminalState(this._state);
  }

  get history() {
    return [...this._history];
  }

  /**
   * Transition to a new state with validation and event recording
   * @param {string} targetState
   * @param {Object} [meta={}]
   * @param {string} [meta.reason]
   * @param {Object} [meta.details]
   * @param {string} [meta.errorCode]
   * @returns {{ from: string, to: string, stage: string, timestamp: string, reason?: string, details?: Object, errorCode?: string }}
   */
  transition(targetState, meta = {}) {
    validateTransition(this._state, targetState, meta.reason);

    const from = this._state;
    const timestamp = new Date().toISOString();

    this._state = targetState;
    this._stage = targetState;

    const event = {
      from,
      to: targetState,
      stage: targetState,
      timestamp,
      ...(meta.reason ? { reason: meta.reason } : {}),
      ...(meta.errorCode ? { errorCode: meta.errorCode } : {}),
      ...(meta.details ? { details: meta.details } : {})
    };

    this._history.push(event);

    if (this._onTransition) {
      try {
        this._onTransition({
          scanId: this.scanId,
          event,
          machine: this
        });
      } catch (callbackErr) {
        // Callback errors should not corrupt the state machine itself
        console.error('[ScanStateMachine] Transition listener error:', callbackErr.message);
      }
    }

    return event;
  }

  /**
   * Convenience helper to cancel the scan
   * @param {string} [reason='Scan cancelled by user']
   */
  cancel(reason = 'Scan cancelled by user') {
    return this.transition(SCAN_STATES.CANCELLED, { reason });
  }

  /**
   * Convenience helper to fail the scan
   * @param {string} errorCode
   * @param {string} [reason='Scan execution failed']
   * @param {Object} [details]
   */
  fail(errorCode = 'SCAN_FAILED', reason = 'Scan execution failed', details) {
    return this.transition(SCAN_STATES.FAILED, { errorCode, reason, details });
  }

  /**
   * Convenience helper to complete the scan
   * @param {boolean} [isPartial=false]
   * @param {string} [reason]
   */
  complete(isPartial = false, reason) {
    const target = isPartial ? SCAN_STATES.PARTIAL : SCAN_STATES.COMPLETED;
    const defaultReason = isPartial 
      ? 'Scan completed with partial scanner results'
      : 'All scanners completed successfully';
    return this.transition(target, { reason: reason || defaultReason });
  }

  /**
   * Snapshot representation of state
   */
  toJSON() {
    return {
      scanId: this.scanId,
      status: this._state,
      stage: this._stage,
      isTerminal: this.isTerminal,
      history: this.history
    };
  }
}

module.exports = {
  SCAN_STATES,
  TERMINAL_STATES,
  ALLOWED_TRANSITIONS,
  InvalidStateTransitionError,
  isValidState,
  isTerminalState,
  getPermittedTransitions,
  canTransition,
  validateTransition,
  ScanStateMachine
};
