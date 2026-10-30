const { describe, it } = require('node:test');
const assert = require('node:assert');
const {
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
} = require('../src/orchestrator/scanStateMachine');

describe('Scan State Machine & Transition Guards (Task 08)', () => {
  // --------------------------------------------------------------------------
  // 1. Enumerations and Basic State Checks
  // --------------------------------------------------------------------------
  describe('States and Terminal Definitions', () => {
    it('should define all 9 canonical scan states', () => {
      const expected = [
        'QUEUED',
        'PREPARING',
        'SCANNING',
        'NORMALIZING',
        'INVESTIGATING',
        'COMPLETED',
        'PARTIAL',
        'FAILED',
        'CANCELLED'
      ];
      assert.deepStrictEqual(Object.values(SCAN_STATES), expected);
    });

    it('should identify terminal states correctly', () => {
      assert.strictEqual(isTerminalState(SCAN_STATES.COMPLETED), true);
      assert.strictEqual(isTerminalState(SCAN_STATES.PARTIAL), true);
      assert.strictEqual(isTerminalState(SCAN_STATES.FAILED), true);
      assert.strictEqual(isTerminalState(SCAN_STATES.CANCELLED), true);

      assert.strictEqual(isTerminalState(SCAN_STATES.QUEUED), false);
      assert.strictEqual(isTerminalState(SCAN_STATES.PREPARING), false);
      assert.strictEqual(isTerminalState(SCAN_STATES.SCANNING), false);
      assert.strictEqual(isTerminalState(SCAN_STATES.NORMALIZING), false);
      assert.strictEqual(isTerminalState(SCAN_STATES.INVESTIGATING), false);
    });

    it('should validate state membership correctly', () => {
      assert.strictEqual(isValidState('QUEUED'), true);
      assert.strictEqual(isValidState('SCANNING'), true);
      assert.strictEqual(isValidState('INVALID_FOO'), false);
      assert.strictEqual(isValidState(null), false);
      assert.strictEqual(isValidState(123), false);
    });
  });

  // --------------------------------------------------------------------------
  // 2. Allowed Transitions Tests
  // --------------------------------------------------------------------------
  describe('Allowed Transitions', () => {
    const validPairs = [
      // From QUEUED
      [SCAN_STATES.QUEUED, SCAN_STATES.PREPARING],
      [SCAN_STATES.QUEUED, SCAN_STATES.CANCELLED],

      // From PREPARING
      [SCAN_STATES.PREPARING, SCAN_STATES.SCANNING],
      [SCAN_STATES.PREPARING, SCAN_STATES.FAILED],
      [SCAN_STATES.PREPARING, SCAN_STATES.CANCELLED],

      // From SCANNING
      [SCAN_STATES.SCANNING, SCAN_STATES.NORMALIZING],
      [SCAN_STATES.SCANNING, SCAN_STATES.FAILED],
      [SCAN_STATES.SCANNING, SCAN_STATES.CANCELLED],

      // From NORMALIZING
      [SCAN_STATES.NORMALIZING, SCAN_STATES.INVESTIGATING],
      [SCAN_STATES.NORMALIZING, SCAN_STATES.COMPLETED],
      [SCAN_STATES.NORMALIZING, SCAN_STATES.PARTIAL],
      [SCAN_STATES.NORMALIZING, SCAN_STATES.FAILED],
      [SCAN_STATES.NORMALIZING, SCAN_STATES.CANCELLED],

      // From INVESTIGATING
      [SCAN_STATES.INVESTIGATING, SCAN_STATES.COMPLETED],
      [SCAN_STATES.INVESTIGATING, SCAN_STATES.PARTIAL],
      [SCAN_STATES.INVESTIGATING, SCAN_STATES.FAILED],
      [SCAN_STATES.INVESTIGATING, SCAN_STATES.CANCELLED]
    ];

    for (const [from, to] of validPairs) {
      it(`should allow transition from ${from} -> ${to}`, () => {
        assert.strictEqual(canTransition(from, to), true);
        assert.strictEqual(validateTransition(from, to), true);
      });
    }

    it('should return permitted outbound transitions list', () => {
      const fromQueued = getPermittedTransitions(SCAN_STATES.QUEUED);
      assert.deepStrictEqual([...fromQueued], [SCAN_STATES.PREPARING, SCAN_STATES.CANCELLED]);

      const fromCompleted = getPermittedTransitions(SCAN_STATES.COMPLETED);
      assert.deepStrictEqual([...fromCompleted], []);
    });
  });

  // --------------------------------------------------------------------------
  // 3. Rejected Transitions Tests (Guards & Error Classification)
  // --------------------------------------------------------------------------
  describe('Rejected Transitions & Transition Guards', () => {
    it('should reject transitions attempting to skip pipeline stages', () => {
      const invalidSkips = [
        [SCAN_STATES.QUEUED, SCAN_STATES.SCANNING],
        [SCAN_STATES.QUEUED, SCAN_STATES.NORMALIZING],
        [SCAN_STATES.QUEUED, SCAN_STATES.COMPLETED],
        [SCAN_STATES.PREPARING, SCAN_STATES.NORMALIZING],
        [SCAN_STATES.PREPARING, SCAN_STATES.COMPLETED],
        [SCAN_STATES.SCANNING, SCAN_STATES.COMPLETED]
      ];

      for (const [from, to] of invalidSkips) {
        assert.strictEqual(canTransition(from, to), false);
        assert.throws(
          () => validateTransition(from, to),
          (err) => {
            assert.strictEqual(err.name, 'InvalidStateTransitionError');
            assert.strictEqual(err.code, 'INVALID_STATE_TRANSITION');
            assert.strictEqual(err.statusCode, 409);
            assert.strictEqual(err.currentStatus, from);
            assert.strictEqual(err.targetStatus, to);
            return true;
          }
        );
      }
    });

    it('should reject backward transitions', () => {
      const backwardTransitions = [
        [SCAN_STATES.SCANNING, SCAN_STATES.PREPARING],
        [SCAN_STATES.SCANNING, SCAN_STATES.QUEUED],
        [SCAN_STATES.NORMALIZING, SCAN_STATES.SCANNING],
        [SCAN_STATES.NORMALIZING, SCAN_STATES.PREPARING],
        [SCAN_STATES.INVESTIGATING, SCAN_STATES.NORMALIZING]
      ];

      for (const [from, to] of backwardTransitions) {
        assert.strictEqual(canTransition(from, to), false);
        assert.throws(
          () => validateTransition(from, to),
          (err) => err.code === 'INVALID_STATE_TRANSITION' && err.statusCode === 409
        );
      }
    });

    it('should reject transitions out of terminal states', () => {
      const terminalList = [
        SCAN_STATES.COMPLETED,
        SCAN_STATES.PARTIAL,
        SCAN_STATES.FAILED,
        SCAN_STATES.CANCELLED
      ];

      for (const terminal of terminalList) {
        for (const target of Object.values(SCAN_STATES)) {
          assert.strictEqual(canTransition(terminal, target), false);
          assert.throws(
            () => validateTransition(terminal, target),
            (err) => {
              assert.strictEqual(err.code, 'INVALID_STATE_TRANSITION');
              assert.strictEqual(err.statusCode, 409);
              assert.ok(err.message.includes('terminal state'));
              return true;
            }
          );
        }
      }
    });

    it('should reject invalid or unknown state strings', () => {
      assert.strictEqual(canTransition('UNKNOWN', SCAN_STATES.SCANNING), false);
      assert.throws(
        () => validateTransition('UNKNOWN', SCAN_STATES.SCANNING),
        (err) => err.code === 'INVALID_STATE_TRANSITION' && err.statusCode === 409
      );

      assert.strictEqual(canTransition(SCAN_STATES.QUEUED, 'UNKNOWN'), false);
      assert.throws(
        () => validateTransition(SCAN_STATES.QUEUED, 'UNKNOWN'),
        (err) => err.code === 'INVALID_STATE_TRANSITION' && err.statusCode === 409
      );
    });
  });

  // --------------------------------------------------------------------------
  // 4. Managed ScanStateMachine Instance Tests
  // --------------------------------------------------------------------------
  describe('ScanStateMachine Instance Lifecycle', () => {
    it('should execute standard complete scan flow (happy path)', () => {
      const sm = new ScanStateMachine(SCAN_STATES.QUEUED, { scanId: 'scan_001' });

      assert.strictEqual(sm.state, SCAN_STATES.QUEUED);
      assert.strictEqual(sm.stage, SCAN_STATES.QUEUED);
      assert.strictEqual(sm.isTerminal, false);

      sm.transition(SCAN_STATES.PREPARING, { reason: 'Workspace created' });
      assert.strictEqual(sm.state, SCAN_STATES.PREPARING);

      sm.transition(SCAN_STATES.SCANNING, { reason: 'Semgrep initiated' });
      assert.strictEqual(sm.state, SCAN_STATES.SCANNING);

      sm.transition(SCAN_STATES.NORMALIZING, { reason: 'Semgrep output parsed' });
      assert.strictEqual(sm.state, SCAN_STATES.NORMALIZING);

      sm.complete(false, 'All checks passed');
      assert.strictEqual(sm.state, SCAN_STATES.COMPLETED);
      assert.strictEqual(sm.isTerminal, true);

      // Verify event history contains full audit trail
      const history = sm.history;
      assert.strictEqual(history.length, 5);
      assert.strictEqual(history[0].to, SCAN_STATES.QUEUED);
      assert.strictEqual(history[1].to, SCAN_STATES.PREPARING);
      assert.strictEqual(history[2].to, SCAN_STATES.SCANNING);
      assert.strictEqual(history[3].to, SCAN_STATES.NORMALIZING);
      assert.strictEqual(history[4].to, SCAN_STATES.COMPLETED);
    });

    it('should execute AI investigation scan flow', () => {
      const sm = new ScanStateMachine(SCAN_STATES.QUEUED, { scanId: 'scan_002' });

      sm.transition(SCAN_STATES.PREPARING);
      sm.transition(SCAN_STATES.SCANNING);
      sm.transition(SCAN_STATES.NORMALIZING);
      sm.transition(SCAN_STATES.INVESTIGATING, { reason: 'Deep diagnostic on SQL injection' });
      assert.strictEqual(sm.state, SCAN_STATES.INVESTIGATING);

      sm.complete(false);
      assert.strictEqual(sm.state, SCAN_STATES.COMPLETED);
    });

    it('should support partial failure completion', () => {
      const sm = new ScanStateMachine(SCAN_STATES.QUEUED);

      sm.transition(SCAN_STATES.PREPARING);
      sm.transition(SCAN_STATES.SCANNING);
      sm.transition(SCAN_STATES.NORMALIZING);
      sm.complete(true, 'npm audit timed out but Semgrep succeeded');

      assert.strictEqual(sm.state, SCAN_STATES.PARTIAL);
      assert.strictEqual(sm.isTerminal, true);
    });

    it('should support early failure with errorCode', () => {
      const sm = new ScanStateMachine(SCAN_STATES.QUEUED);

      sm.transition(SCAN_STATES.PREPARING);
      sm.fail('WORKSPACE_CLONE_ERROR', 'Git clone timed out after 120s');

      assert.strictEqual(sm.state, SCAN_STATES.FAILED);
      assert.strictEqual(sm.isTerminal, true);

      const lastEvent = sm.history[sm.history.length - 1];
      assert.strictEqual(lastEvent.to, SCAN_STATES.FAILED);
      assert.strictEqual(lastEvent.errorCode, 'WORKSPACE_CLONE_ERROR');
      assert.strictEqual(lastEvent.reason, 'Git clone timed out after 120s');
    });

    it('should support cancellation by user', () => {
      const sm = new ScanStateMachine(SCAN_STATES.QUEUED);

      sm.transition(SCAN_STATES.PREPARING);
      sm.transition(SCAN_STATES.SCANNING);
      sm.cancel('User aborted scan from UI');

      assert.strictEqual(sm.state, SCAN_STATES.CANCELLED);
      assert.strictEqual(sm.isTerminal, true);
    });

    it('should invoke onTransition listener if provided', () => {
      const recordedEvents = [];
      const sm = new ScanStateMachine(SCAN_STATES.QUEUED, {
        scanId: 'scan_listener_test',
        onTransition: ({ scanId, event }) => {
          recordedEvents.push({ scanId, to: event.to });
        }
      });

      sm.transition(SCAN_STATES.PREPARING);
      sm.transition(SCAN_STATES.SCANNING);

      assert.strictEqual(recordedEvents.length, 2);
      assert.strictEqual(recordedEvents[0].scanId, 'scan_listener_test');
      assert.strictEqual(recordedEvents[0].to, SCAN_STATES.PREPARING);
      assert.strictEqual(recordedEvents[1].to, SCAN_STATES.SCANNING);
    });
  });
});
