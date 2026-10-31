import test from 'node:test';
import assert from 'node:assert/strict';
import { formatInvestigationData, ASSESSMENT_CONFIG } from '../src/utils/investigationFormatter.js';

test('AI Investigation Formatter & Result Panel Contract (Commit 27)', async (t) => {
  const sampleInvestigation = {
    id: 'inv_01JAZZ80001',
    findingId: 'find_sql_001',
    assessment: 'LIKELY_TRUE',
    confidence: 'HIGH',
    summary: 'Direct user input reaches database query sink without parameterization.',
    evidence: [
      'Untrusted query parameter concatenated into SQL string at line 24',
      'No ORM escaping or input validation detected'
    ],
    preconditions: [
      'Attacker must have network access to HTTP GET endpoint',
      'Database driver allows SQL injection execution'
    ],
    potentialImpact: 'Full database read access, credential exfiltration, potential remote code execution.',
    recommendedFix: 'Refactor SQL query to use parameterized query bind parameters ($1, $2).',
    limitations: [
      'Static AST analysis without live database verification',
      'Input validation middleware upstream not inspected in current bounded slice'
    ],
    model: 'gemma-2-9b-it',
    promptVersion: 'vulnex-investigation-v1',
    createdAt: '2026-10-31T03:15:00.000Z'
  };

  await t.test('formats complete structured investigation payload matching Commit 27 gate', () => {
    const data = formatInvestigationData(sampleInvestigation);

    assert.ok(data !== null);
    assert.equal(data.assessment, 'LIKELY_TRUE');
    assert.equal(data.confidence, 'HIGH');
    assert.equal(data.summary, sampleInvestigation.summary);

    // Evidence
    assert.equal(Array.isArray(data.evidence), true);
    assert.equal(data.evidence.length, 2);
    assert.equal(data.evidence[0], sampleInvestigation.evidence[0]);

    // Preconditions
    assert.equal(Array.isArray(data.preconditions), true);
    assert.equal(data.preconditions.length, 2);

    // Impact
    assert.equal(data.potentialImpact, sampleInvestigation.potentialImpact);

    // Recommendations & Limitations
    assert.equal(data.recommendedFix, sampleInvestigation.recommendedFix);
    assert.equal(Array.isArray(data.limitations), true);
    assert.equal(data.limitations.length, 2);

    // Provenance
    assert.equal(data.model, 'gemma-2-9b-it');
    assert.equal(data.promptVersion, 'vulnex-investigation-v1');
  });

  await t.test('safely handles UNCERTAIN and LIKELY_FALSE assessment states', () => {
    const uncertainPayload = { ...sampleInvestigation, assessment: 'UNCERTAIN' };
    const dataUncertain = formatInvestigationData(uncertainPayload);
    assert.equal(dataUncertain.assessment, 'UNCERTAIN');
    assert.equal(dataUncertain.assessmentMeta.label, ASSESSMENT_CONFIG.UNCERTAIN.label);

    const falsePayload = { ...sampleInvestigation, assessment: 'LIKELY_FALSE' };
    const dataFalse = formatInvestigationData(falsePayload);
    assert.equal(dataFalse.assessment, 'LIKELY_FALSE');
    assert.equal(dataFalse.assessmentMeta.label, ASSESSMENT_CONFIG.LIKELY_FALSE.label);
  });

  await t.test('safely coerces scalar string evidence and preconditions into arrays', () => {
    const scalarPayload = {
      ...sampleInvestigation,
      evidence: 'Single string evidence point',
      preconditions: 'Single prerequisite',
      limitations: 'Single boundary note'
    };

    const data = formatInvestigationData(scalarPayload);
    assert.equal(Array.isArray(data.evidence), true);
    assert.equal(data.evidence.length, 1);
    assert.equal(data.evidence[0], 'Single string evidence point');

    assert.equal(Array.isArray(data.preconditions), true);
    assert.equal(data.preconditions.length, 1);

    assert.equal(Array.isArray(data.limitations), true);
    assert.equal(data.limitations.length, 1);
  });

  await t.test('returns null gracefully for invalid or empty inputs', () => {
    assert.equal(formatInvestigationData(null), null);
    assert.equal(formatInvestigationData(undefined), null);
    assert.equal(formatInvestigationData('invalid-string'), null);
  });
});
