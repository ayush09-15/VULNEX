import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildVerificationChecklist,
  normalizeCheckStatus,
  getScopedStatusWording,
  VERIFICATION_STATUS_CONFIG,
} from '../src/utils/verificationFormatter.js';

test('Verification Checklist Contract & Scoped Status (Commit 40)', async (t) => {
  await t.test('normalizeCheckStatus maps statuses canonically', () => {
    assert.equal(normalizeCheckStatus('passed'), 'PASSED');
    assert.equal(normalizeCheckStatus('VERIFIED'), 'PASSED');
    assert.equal(normalizeCheckStatus('failed'), 'FAILED');
    assert.equal(normalizeCheckStatus('ERROR'), 'FAILED');
    assert.equal(normalizeCheckStatus('inconclusive'), 'INCONCLUSIVE');
    assert.equal(normalizeCheckStatus('AMBIGUOUS'), 'INCONCLUSIVE');
    assert.equal(normalizeCheckStatus('NOT_RUN'), 'NOT_RUN');
    assert.equal(normalizeCheckStatus(null), 'NOT_RUN');
    assert.equal(normalizeCheckStatus(undefined), 'NOT_RUN');
  });

  await t.test('VERIFICATION_STATUS_CONFIG defines all four canonical gate states', () => {
    const states = ['PASSED', 'FAILED', 'INCONCLUSIVE', 'NOT_RUN'];
    for (const state of states) {
      assert.ok(VERIFICATION_STATUS_CONFIG[state], `Missing config for ${state}`);
      assert.ok(VERIFICATION_STATUS_CONFIG[state].label);
      assert.ok(VERIFICATION_STATUS_CONFIG[state].badgeClass);
      assert.ok(VERIFICATION_STATUS_CONFIG[state].description);
    }
  });

  await t.test('buildVerificationChecklist produces the 5 canonical checks with NOT_RUN when unverified', () => {
    const checklist = buildVerificationChecklist(null, null);
    assert.equal(checklist.length, 5);

    const ids = checklist.map((c) => c.id);
    assert.deepEqual(ids, [
      'patch_apply',
      'syntax_validation',
      'targeted_tests',
      'post_patch_scan',
      'defect_regression',
    ]);

    for (const item of checklist) {
      assert.equal(item.status, 'NOT_RUN');
    }
  });

  await t.test('buildVerificationChecklist marks all checks PASSED on clean verification', () => {
    const patch = { status: 'APPLIED_TO_TEMP', appliedWorkspaceId: 'ws_test_01' };
    const verification = {
      status: 'PASSED',
      testResults: { testsPassed: true, syntaxValid: true },
      scannerResults: { originalFindingResolved: true, newFindingsCount: 0 },
      beforeAfterComparison: { comparisonOutcome: 'RESOLVED', ambiguousMatch: false, regressionDetected: false },
    };

    const checklist = buildVerificationChecklist(verification, patch);
    assert.equal(checklist.length, 5);
    for (const item of checklist) {
      assert.equal(item.status, 'PASSED', `Check ${item.id} should be PASSED`);
    }
  });

  await t.test('buildVerificationChecklist handles targeted test failure (FAILED)', () => {
    const patch = { status: 'APPLIED_TO_TEMP' };
    const verification = {
      status: 'FAILED',
      testResults: { testsPassed: false, syntaxValid: true },
      scannerResults: { originalFindingResolved: true, newFindingsCount: 0 },
      beforeAfterComparison: { comparisonOutcome: 'RESOLVED' },
    };

    const checklist = buildVerificationChecklist(verification, patch);
    const testCheck = checklist.find((c) => c.id === 'targeted_tests');
    assert.equal(testCheck.status, 'FAILED');
  });

  await t.test('buildVerificationChecklist reflects INCONCLUSIVE on ambiguous fingerprint matching', () => {
    const patch = { status: 'APPLIED_TO_TEMP' };
    const verification = {
      status: 'INCONCLUSIVE',
      testResults: { testsPassed: true, syntaxValid: true },
      scannerResults: { originalFindingResolved: false, newFindingsCount: 0 },
      beforeAfterComparison: { comparisonOutcome: 'AMBIGUOUS', ambiguousMatch: true },
    };

    const checklist = buildVerificationChecklist(verification, patch);
    const rescanCheck = checklist.find((c) => c.id === 'post_patch_scan');
    const regressionCheck = checklist.find((c) => c.id === 'defect_regression');

    assert.equal(rescanCheck.status, 'INCONCLUSIVE');
    assert.equal(regressionCheck.status, 'INCONCLUSIVE');
  });

  await t.test('buildVerificationChecklist reflects FAILED on defect regression', () => {
    const patch = { status: 'APPLIED_TO_TEMP' };
    const verification = {
      status: 'FAILED',
      testResults: { testsPassed: true, syntaxValid: true },
      scannerResults: { originalFindingResolved: true, newFindingsCount: 1 },
      beforeAfterComparison: { comparisonOutcome: 'REGRESSION_DETECTED', regressionDetected: true },
    };

    const checklist = buildVerificationChecklist(verification, patch);
    const regressionCheck = checklist.find((c) => c.id === 'defect_regression');
    assert.equal(regressionCheck.status, 'FAILED');
  });

  await t.test('getScopedStatusWording provides truthful scoped wording per Bible Section 9.3', () => {
    const passedWording = getScopedStatusWording('PASSED');
    assert.ok(passedWording.includes('Targeted finding is no longer detected'));
    assert.ok(passedWording.includes('scoped to the executed test commands'));
    assert.equal(passedWording.includes('100% secure'), false);

    const inconclusiveWording = getScopedStatusWording('INCONCLUSIVE');
    assert.ok(inconclusiveWording.includes('ambiguous fingerprint matching'));

    const failedWording = getScopedStatusWording('FAILED');
    assert.ok(failedWording.includes('Verification checks detected flaws'));
  });
});
