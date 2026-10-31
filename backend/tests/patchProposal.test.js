const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  PATCH_REVIEW_STATES,
  PatchReviewStateEnum,
  InvalidReviewStateTransitionError,
  OutOfScopeProposalError,
  parseUnifiedDiff,
  validateUnifiedDiff,
  PatchProposalSchema,
  CreatePatchProposalSchema,
  validatePatchProposal,
  validateCreatePatchProposal,
  validateProposalScope,
  assertProposalScope,
  isValidReviewStateTransition,
  transitionReviewState
} = require('../src/validators/patchProposal.schema');

describe('Unified Diff Proposal Contract & Validation (Task 26)', () => {

  const sampleValidDiff = [
    '--- a/src/controllers/user.js',
    '+++ b/src/controllers/user.js',
    '@@ -10,3 +10,3 @@',
    '-  const query = `SELECT * FROM users WHERE id = ${req.query.id}`;',
    '+  const query = "SELECT * FROM users WHERE id = ?";',
    '   db.query(query, [req.query.id]);'
  ].join('\n');

  const sampleValidProposal = {
    id: 'patch_prop_01JAZZ80001',
    findingId: 'find_sqli_01JAZZ001',
    diff: sampleValidDiff,
    rationale: 'Replace unsafe SQL string template interpolation with parameterized query binding.',
    changedFiles: ['src/controllers/user.js'],
    evidenceReferences: [
      'fingerprint:3a1f4b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a',
      'src/controllers/user.js#L10-L12'
    ],
    reviewState: 'PENDING_REVIEW',
    createdAt: '2026-10-31T14:00:00.000Z'
  };

  const sampleFinding = {
    id: 'find_sqli_01JAZZ001',
    scanId: 'scan_01JAZZ000',
    scanner: 'semgrep',
    ruleId: 'javascript.express.security.audit.sqli',
    title: 'SQL Injection via query interpolation',
    category: 'SQL_INJECTION',
    severity: 'HIGH',
    confidence: 'HIGH',
    filePath: 'src/controllers/user.js',
    startLine: 10,
    endLine: 12,
    message: 'Direct interpolation of req.query.id into SQL query',
    evidence: 'const query = `SELECT * FROM users WHERE id = ${req.query.id}`;',
    fingerprint: '3a1f4b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a',
    status: 'DETECTED',
    createdAt: '2026-10-31T13:50:00.000Z'
  };

  // --------------------------------------------------------------------------
  // 1. Valid Patch Proposal Acceptance
  // --------------------------------------------------------------------------
  describe('1. Valid Patch Proposal Acceptance', () => {
    it('should validate a complete, canonical patch proposal', () => {
      const result = validatePatchProposal(sampleValidProposal);
      assert.equal(result.success, true);
      assert.equal(result.data.id, sampleValidProposal.id);
      assert.equal(result.data.findingId, sampleValidProposal.findingId);
      assert.equal(result.data.reviewState, 'PENDING_REVIEW');
      assert.deepEqual(result.data.changedFiles, ['src/controllers/user.js']);
    });

    it('should accept structured evidence reference objects linking proposal to finding', () => {
      const proposalWithStructuredEvidence = {
        ...sampleValidProposal,
        evidenceReferences: [
          {
            type: 'FINGERPRINT',
            reference: '3a1f4b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a',
            description: 'Stable finding SHA-256 fingerprint'
          },
          {
            type: 'LINE_RANGE',
            reference: 'src/controllers/user.js#L10-L12',
            description: 'Vulnerable route query lines'
          },
          {
            type: 'SNIPPET',
            reference: 'const query = `SELECT * FROM users WHERE id = ${req.query.id}`;'
          }
        ]
      };

      const result = validatePatchProposal(proposalWithStructuredEvidence);
      assert.equal(result.success, true);
      assert.equal(result.data.evidenceReferences.length, 3);
      assert.equal(result.data.evidenceReferences[0].type, 'FINGERPRINT');
    });

    it('should validate CreatePatchProposal input schema with default PENDING_REVIEW', () => {
      const createInput = {
        findingId: 'find_sqli_01JAZZ001',
        diff: sampleValidDiff,
        rationale: 'Sanitize query using parameterized driver statement.',
        changedFiles: ['src/controllers/user.js'],
        evidenceReferences: ['src/controllers/user.js#L10']
      };

      const result = validateCreatePatchProposal(createInput);
      assert.equal(result.success, true);
      assert.equal(result.data.reviewState, 'PENDING_REVIEW');
    });
  });

  // --------------------------------------------------------------------------
  // 2. Required Fields & Missing Field Rejection
  // --------------------------------------------------------------------------
  describe('2. Required Fields & Schema Violations', () => {
    it('should reject proposal missing unique ID', () => {
      const { id, ...invalid } = sampleValidProposal;
      const result = validatePatchProposal(invalid);
      assert.equal(result.success, false);
      const paths = result.error.issues.map(i => i.path.join('.'));
      assert.ok(paths.includes('id'));
    });

    it('should reject proposal missing findingId', () => {
      const { findingId, ...invalid } = sampleValidProposal;
      const result = validatePatchProposal(invalid);
      assert.equal(result.success, false);
      const paths = result.error.issues.map(i => i.path.join('.'));
      assert.ok(paths.includes('findingId'));
    });

    it('should reject proposal missing rationale or rationale shorter than 5 chars', () => {
      const missingRationale = { ...sampleValidProposal, rationale: '' };
      assert.equal(validatePatchProposal(missingRationale).success, false);

      const shortRationale = { ...sampleValidProposal, rationale: 'fix' };
      assert.equal(validatePatchProposal(shortRationale).success, false);
    });

    it('should reject proposal with empty changedFiles array', () => {
      const emptyChanged = { ...sampleValidProposal, changedFiles: [] };
      const result = validatePatchProposal(emptyChanged);
      assert.equal(result.success, false);
      const paths = result.error.issues.map(i => i.path.join('.'));
      assert.ok(paths.includes('changedFiles'));
    });

    it('should reject proposal with empty evidenceReferences array', () => {
      const emptyRefs = { ...sampleValidProposal, evidenceReferences: [] };
      const result = validatePatchProposal(emptyRefs);
      assert.equal(result.success, false);
      const paths = result.error.issues.map(i => i.path.join('.'));
      assert.ok(paths.includes('evidenceReferences'));
    });

    it('should reject proposal with invalid creation timestamp', () => {
      const badTimestamp = { ...sampleValidProposal, createdAt: 'not-a-timestamp' };
      const result = validatePatchProposal(badTimestamp);
      assert.equal(result.success, false);
      const paths = result.error.issues.map(i => i.path.join('.'));
      assert.ok(paths.includes('createdAt'));
    });
  });

  // --------------------------------------------------------------------------
  // 3. Unified Diff Structure Validation
  // --------------------------------------------------------------------------
  describe('3. Unified Diff Structure Validation', () => {
    it('should reject empty or whitespace-only diffs', () => {
      assert.equal(validateUnifiedDiff('').valid, false);
      assert.equal(validateUnifiedDiff('   \n  ').valid, false);
      assert.equal(validatePatchProposal({ ...sampleValidProposal, diff: '' }).success, false);
    });

    it('should reject arbitrary text missing unified diff file headers', () => {
      const nonDiffText = 'Just some explanation without diff headers or hunk markers';
      const result = validateUnifiedDiff(nonDiffText);
      assert.equal(result.valid, false);
      assert.ok(result.error.includes('headers'));
    });

    it('should reject diff missing hunk header (@@ ... @@)', () => {
      const missingHunk = [
        '--- a/src/app.js',
        '+++ b/src/app.js',
        '-old line',
        '+new line'
      ].join('\n');

      const result = validateUnifiedDiff(missingHunk);
      assert.equal(result.valid, false);
      assert.ok(result.error.includes('hunk header'));
    });

    it('should reject diff with malformed hunk line prefixes', () => {
      const badPrefix = [
        '--- a/src/app.js',
        '+++ b/src/app.js',
        '@@ -1,2 +1,2 @@',
        'x invalid prefix line',
        '+valid add'
      ].join('\n');

      const result = validateUnifiedDiff(badPrefix);
      assert.equal(result.valid, false);
      assert.ok(result.error.includes('Invalid diff hunk line prefix'));
    });

    it('should reject diff containing zero additions or deletions', () => {
      const noChangeDiff = [
        '--- a/src/app.js',
        '+++ b/src/app.js',
        '@@ -1,2 +1,2 @@',
        ' context line 1',
        ' context line 2'
      ].join('\n');

      const result = validateUnifiedDiff(noChangeDiff);
      assert.equal(result.valid, false);
      assert.ok(result.error.includes('any added (+) or deleted (-) lines'));
    });

    it('should accept valid diff with "\\ No newline at end of file" marker', () => {
      const diffWithNoNewline = [
        '--- a/src/config.js',
        '+++ b/src/config.js',
        '@@ -1,1 +1,1 @@',
        '-module.exports = { secret: "123" };',
        '\\ No newline at end of file',
        '+module.exports = { secret: process.env.SECRET };',
        '\\ No newline at end of file'
      ].join('\n');

      const result = validateUnifiedDiff(diffWithNoNewline);
      assert.equal(result.valid, true);
      assert.deepEqual(result.files, ['src/config.js']);
    });

    it('should reject mismatch between diff header target and changedFiles array', () => {
      const mismatchedProposal = {
        ...sampleValidProposal,
        changedFiles: ['src/different/path.js'] // diff modifies src/controllers/user.js
      };

      const result = validatePatchProposal(mismatchedProposal);
      assert.equal(result.success, false);
      assert.ok(result.error.issues[0].message.includes('must match changedFiles list'));
    });
  });

  // --------------------------------------------------------------------------
  // 4. Path Traversal & Safe Path Enforcement
  // --------------------------------------------------------------------------
  describe('4. Path Traversal & Safe Path Enforcement', () => {
    it('should reject changed file paths containing traversal sequences ("..")', () => {
      const traversalProposal = {
        ...sampleValidProposal,
        changedFiles: ['../outside.js']
      };

      const result = validatePatchProposal(traversalProposal);
      assert.equal(result.success, false);
    });

    it('should reject changed file paths that are absolute host paths', () => {
      const absolutePathProposal = {
        ...sampleValidProposal,
        changedFiles: ['/etc/passwd']
      };

      const result = validatePatchProposal(absolutePathProposal);
      assert.equal(result.success, false);
    });

    it('should reject diff headers containing path traversal sequences', () => {
      const traversalDiff = [
        '--- a/../../secret.txt',
        '+++ b/../../secret.txt',
        '@@ -1,1 +1,1 @@',
        '-old',
        '+new'
      ].join('\n');

      const result = validateUnifiedDiff(traversalDiff);
      assert.equal(result.valid, false);
      assert.ok(result.error.includes('unsafe path traversal'));
    });

    it('should reject diff headers containing absolute file paths', () => {
      const absoluteDiff = [
        '--- /etc/shadow',
        '+++ /etc/shadow',
        '@@ -1,1 +1,1 @@',
        '-root:x:1:0',
        '+root:x:1:1'
      ].join('\n');

      const result = validateUnifiedDiff(absoluteDiff);
      assert.equal(result.valid, false);
      assert.ok(result.error.includes('absolute file path'));
    });
  });

  // --------------------------------------------------------------------------
  // 5. Scope Bounding Against Target Finding
  // --------------------------------------------------------------------------
  describe('5. Scope Bounding Against Target Finding', () => {
    it('should pass scope validation when proposal targets the finding file accurately', () => {
      const scopeCheck = validateProposalScope(sampleValidProposal, sampleFinding);
      assert.equal(scopeCheck.valid, true);

      // assertProposalScope does not throw
      assert.doesNotThrow(() => {
        assertProposalScope(sampleValidProposal, sampleFinding);
      });
    });

    it('should reject proposal if findingId does not match target finding id', () => {
      const mismatchedFindingProposal = {
        ...sampleValidProposal,
        findingId: 'find_different_999'
      };

      const scopeCheck = validateProposalScope(mismatchedFindingProposal, sampleFinding);
      assert.equal(scopeCheck.valid, false);
      assert.ok(scopeCheck.error.includes('does not match target finding id'));

      assert.throws(() => {
        assertProposalScope(mismatchedFindingProposal, sampleFinding);
      }, OutOfScopeProposalError);
    });

    it('should reject proposal silently modifying additional files outside the finding scope', () => {
      // Attacker or hallucinated proposal attempts to modify user.js AND auth.js
      const multiFileDiff = [
        '--- a/src/controllers/user.js',
        '+++ b/src/controllers/user.js',
        '@@ -1,1 +1,1 @@',
        '-old',
        '+new',
        '--- a/src/auth/secret.js',
        '+++ b/src/auth/secret.js',
        '@@ -1,1 +1,1 @@',
        '-token',
        '+compromised'
      ].join('\n');

      const sneakyProposal = {
        ...sampleValidProposal,
        diff: multiFileDiff,
        changedFiles: ['src/controllers/user.js', 'src/auth/secret.js']
      };

      const scopeCheck = validateProposalScope(sneakyProposal, sampleFinding);
      assert.equal(scopeCheck.valid, false);
      assert.ok(scopeCheck.error.includes('silently modifies files outside finding scope'));

      assert.throws(() => {
        assertProposalScope(sneakyProposal, sampleFinding);
      }, OutOfScopeProposalError);
    });

    it('should reject proposal whose diff header targets a file outside finding scope', () => {
      const differentFileDiff = [
        '--- a/src/unrelated.js',
        '+++ b/src/unrelated.js',
        '@@ -1,1 +1,1 @@',
        '-line1',
        '+line2'
      ].join('\n');

      const sneakyDiffProposal = {
        ...sampleValidProposal,
        diff: differentFileDiff,
        changedFiles: ['src/unrelated.js']
      };

      const scopeCheck = validateProposalScope(sneakyDiffProposal, sampleFinding);
      assert.equal(scopeCheck.valid, false);
      assert.ok(scopeCheck.error.includes('must include finding target file') || scopeCheck.error.includes('outside finding scope'));
    });

    it('should be compatible with Common Finding schema (path attribute)', () => {
      const commonFinding = {
        id: 'find_sqli_01JAZZ001',
        rule: 'vulnex.sqli',
        path: 'src/controllers/user.js',
        startLine: 10,
        endLine: 12,
        message: 'SQL Injection',
        evidence: 'db.query',
        severity: 'HIGH',
        confidence: 'HIGH',
        fingerprint: '3a1f4b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a'
      };

      const scopeCheck = validateProposalScope(sampleValidProposal, commonFinding);
      assert.equal(scopeCheck.valid, true);
    });
  });

  // --------------------------------------------------------------------------
  // 6. Review State Machine & Transitions
  // --------------------------------------------------------------------------
  describe('6. Review State Machine & Transitions', () => {
    it('should support PENDING_REVIEW, APPROVED, and REJECTED states', () => {
      for (const state of ['PENDING_REVIEW', 'APPROVED', 'REJECTED']) {
        const parsed = PatchReviewStateEnum.safeParse(state);
        assert.equal(parsed.success, true);
        assert.equal(parsed.data, state);
      }

      // Reject non-review lifecycle states
      assert.equal(PatchReviewStateEnum.safeParse('APPLIED').success, false);
      assert.equal(PatchReviewStateEnum.safeParse('VERIFIED').success, false);
      assert.equal(PatchReviewStateEnum.safeParse('GENERATED').success, false);
      assert.equal(PatchReviewStateEnum.safeParse('INVALID').success, false);
    });

    it('should transition from PENDING_REVIEW to APPROVED recording reviewer metadata', () => {
      const approvedProposal = transitionReviewState(sampleValidProposal, PATCH_REVIEW_STATES.APPROVED, {
        reviewer: 'security-lead@vulnex.internal',
        comments: 'Verified parameterized query syntax and AST safety.'
      });

      assert.equal(approvedProposal.reviewState, PATCH_REVIEW_STATES.APPROVED);
      assert.equal(approvedProposal.reviewedBy, 'security-lead@vulnex.internal');
      assert.equal(approvedProposal.reviewComments, 'Verified parameterized query syntax and AST safety.');
      assert.ok(approvedProposal.reviewedAt);
    });

    it('should transition from PENDING_REVIEW to REJECTED recording rejection reason', () => {
      const rejectedProposal = transitionReviewState(sampleValidProposal, PATCH_REVIEW_STATES.REJECTED, {
        reviewer: 'tech-lead@vulnex.internal',
        comments: 'Query placeholder syntax is incompatible with configured database driver.'
      });

      assert.equal(rejectedProposal.reviewState, PATCH_REVIEW_STATES.REJECTED);
      assert.equal(rejectedProposal.reviewedBy, 'tech-lead@vulnex.internal');
      assert.ok(rejectedProposal.reviewComments.includes('incompatible'));
      assert.ok(rejectedProposal.reviewedAt);
    });

    it('should allow revoking approval from APPROVED to REJECTED', () => {
      const approvedProposal = {
        ...sampleValidProposal,
        reviewState: PATCH_REVIEW_STATES.APPROVED,
        reviewedBy: 'security-lead@vulnex.internal'
      };

      const revokedProposal = transitionReviewState(approvedProposal, PATCH_REVIEW_STATES.REJECTED, {
        reviewer: 'security-lead@vulnex.internal',
        comments: 'Revoking approval: discovered edge-case defect.'
      });

      assert.equal(revokedProposal.reviewState, PATCH_REVIEW_STATES.REJECTED);
    });

    it('should allow reopening REJECTED proposal back to PENDING_REVIEW for re-evaluation', () => {
      const rejectedProposal = {
        ...sampleValidProposal,
        reviewState: PATCH_REVIEW_STATES.REJECTED
      };

      const reopened = transitionReviewState(rejectedProposal, PATCH_REVIEW_STATES.PENDING_REVIEW, {
        reviewer: 'developer@vulnex.internal',
        comments: 'Reopening for re-review after context clarification.'
      });

      assert.equal(reopened.reviewState, PATCH_REVIEW_STATES.PENDING_REVIEW);
    });

    it('should throw InvalidReviewStateTransitionError when attempting invalid transition from REJECTED directly to APPROVED', () => {
      const rejectedProposal = {
        ...sampleValidProposal,
        reviewState: PATCH_REVIEW_STATES.REJECTED
      };

      assert.throws(() => {
        transitionReviewState(rejectedProposal, PATCH_REVIEW_STATES.APPROVED);
      }, InvalidReviewStateTransitionError);
    });

    it('should handle idempotent transitions cleanly', () => {
      assert.equal(isValidReviewStateTransition(PATCH_REVIEW_STATES.APPROVED, PATCH_REVIEW_STATES.APPROVED), true);
      assert.equal(isValidReviewStateTransition(PATCH_REVIEW_STATES.PENDING_REVIEW, PATCH_REVIEW_STATES.PENDING_REVIEW), true);
    });
  });

  // --------------------------------------------------------------------------
  // 7. Strict Separation Invariant
  // --------------------------------------------------------------------------
  describe('7. Strict Separation from Patch Application', () => {
    it('should not contain execution flags or automatic application attributes in proposal schema', () => {
      const proposalWithExecutionFlags = {
        ...sampleValidProposal,
        autoApply: true,
        executeCommand: 'rm -rf /',
        bypassHumanReview: true
      };

      // Zod schema strip/reject check: the canonical proposal schema does not define or authorize execution flags
      const parsed = PatchProposalSchema.safeParse(proposalWithExecutionFlags);
      // In Zod object by default extra keys are stripped unless passthrough()
      assert.equal(parsed.success, true);
      assert.equal('autoApply' in parsed.data, false, 'autoApply must not exist on proposal schema');
      assert.equal('executeCommand' in parsed.data, false, 'executeCommand must not exist on proposal schema');
      assert.equal('bypassHumanReview' in parsed.data, false, 'bypassHumanReview must not exist on proposal schema');
    });
  });
});
