/**
 * VULNEX Finding Routes & Investigation Integration Tests
 *
 * Implements acceptance gates for Task 28:
 * - Master Antigravity Execution Bible Section 4.7 & 4.9
 * - POST /api/findings/:id/investigate
 * - GET  /api/findings/:id/investigation
 * - GET  /api/findings/:id
 * - GET  /api/findings
 * - State machine transition: DETECTED -> TRIAGED
 * - Structured AI result and provenance validation
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/app');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const scannerService = require('../src/services/scanner.service');
const { investigationService } = require('../src/services/investigation.service');
const { validateInvestigation } = require('../src/validators/investigation.schema');

// In-memory HTTP dispatch helper (bypasses TCP socket binding in sandboxed runners)
function dispatch(method, url, { body = {}, query = {}, headers = {} } = {}) {
  return new Promise((resolve) => {
    const [pathPart, queryPart] = url.split('?');
    const parsedQuery = {};
    if (queryPart) {
      for (const [k, v] of new URLSearchParams(queryPart)) {
        parsedQuery[k] = v;
      }
    }

    const req = new http.IncomingMessage();
    req.method = method.toUpperCase();
    req.url = url;
    req.originalUrl = url;
    req.headers = {
      'content-type': 'application/json',
      'x-request-id': 'req_finding_routes_test',
      ...headers
    };
    req.body = body;
    req.query = { ...parsedQuery, ...query };

    const res = new http.ServerResponse(req);
    let rawBody = '';

    res.write = (chunk) => {
      if (chunk) rawBody += chunk;
      return true;
    };

    res.end = (chunk) => {
      if (chunk) rawBody += chunk;
      let parsed = null;
      try {
        parsed = rawBody ? JSON.parse(rawBody) : null;
      } catch (_) {
        parsed = rawBody;
      }

      resolve({
        statusCode: res.statusCode,
        headers: res.getHeaders(),
        body: parsed
      });
    };

    app.handle(req, res);
  });
}

function createSampleFinding(overrides = {}) {
  return {
    id: `finding_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    scanId: 'scan_fixture_001',
    scanner: 'semgrep',
    ruleId: 'javascript.express.security.audit.sqli',
    title: 'SQL Injection in User Lookup',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    status: 'DETECTED',
    filePath: 'src/controllers/user.controller.js',
    startLine: 42,
    endLine: 42,
    message: 'Direct string interpolation in SQL query permits arbitrary SQL injection.',
    evidence: 'const query = `SELECT * FROM users WHERE username = \'${req.query.username}\'`;',
    createdAt: new Date().toISOString(),
    ...overrides
  };
}

describe('Finding Routes & Investigation API (Task 28)', () => {
  beforeEach(() => {
    scanOrchestrator.clearStores();
    investigationService.clearStore();
  });

  describe('POST /api/findings/:id/investigate', () => {
    it('should successfully investigate a finding and return canonical investigation entity', async () => {
      const sample = createSampleFinding();
      scanOrchestrator.addFinding(sample);

      const res = await dispatch('POST', `/api/findings/${sample.id}/investigate`, {
        body: { codeContext: 'const query = `SELECT * FROM users WHERE username = \'${req.query.username}\'`;' }
      });

      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.body.success, true);
      assert.ok(res.body.requestId);

      const inv = res.body.data;
      assert.ok(inv.id);
      assert.strictEqual(inv.findingId, sample.id);
      assert.ok(['LIKELY_TRUE', 'UNCERTAIN', 'LIKELY_FALSE'].includes(inv.assessment));
      assert.ok(inv.explanation);
      assert.ok(inv.impact);
      assert.ok(inv.recommendation);
      assert.ok(['LOW', 'MEDIUM', 'HIGH'].includes(inv.confidence) || typeof inv.confidence === 'number');
      assert.ok(Array.isArray(inv.evidence));
      assert.ok(Array.isArray(inv.preconditions));
      assert.ok(Array.isArray(inv.limitations));
      assert.ok(inv.createdAt);

      // Validate provenance metadata
      assert.ok(inv.provenance);
      assert.strictEqual(inv.provenance.scanner, sample.scanner);
      assert.strictEqual(inv.provenance.ruleId, sample.ruleId);
      assert.strictEqual(inv.provenance.filePath, sample.filePath);
      assert.ok(inv.provenance.model);
      assert.ok(inv.provenance.promptVersion);
      assert.ok(inv.provenance.investigatedAt);

      // Verify schema compliance
      const validation = validateInvestigation(inv);
      assert.strictEqual(validation.success, true);
    });

    it('should transition finding state machine from DETECTED to TRIAGED', async () => {
      const sample = createSampleFinding({ status: 'DETECTED' });
      scanOrchestrator.addFinding(sample);

      const res = await dispatch('POST', `/api/findings/${sample.id}/investigate`);
      assert.strictEqual(res.statusCode, 200);

      const updatedFinding = scanOrchestrator.getFindingById(sample.id);
      assert.strictEqual(updatedFinding.status, 'TRIAGED');
      assert.ok(updatedFinding.investigationId);
      assert.strictEqual(updatedFinding.aiAssessment, res.body.data.assessment);
      assert.strictEqual(updatedFinding.aiConfidence, res.body.data.confidence);
      assert.ok(updatedFinding.triagedAt);
    });

    it('should return 404 with FINDING_NOT_FOUND for non-existent finding ID', async () => {
      const res = await dispatch('POST', '/api/findings/nonexistent_finding_id/investigate');
      assert.strictEqual(res.statusCode, 404);
      assert.strictEqual(res.body.success, false);
      assert.strictEqual(res.body.error.code, 'FINDING_NOT_FOUND');
    });
  });

  describe('GET /api/findings/:id/investigation', () => {
    it('should return 404 INVESTIGATION_NOT_FOUND when finding has not yet been investigated', async () => {
      const sample = createSampleFinding();
      scanOrchestrator.addFinding(sample);

      const res = await dispatch('GET', `/api/findings/${sample.id}/investigation`);
      assert.strictEqual(res.statusCode, 404);
      assert.strictEqual(res.body.success, false);
      assert.strictEqual(res.body.error.code, 'INVESTIGATION_NOT_FOUND');
    });

    it('should retrieve persisted investigation entity after investigation has run', async () => {
      const sample = createSampleFinding();
      scanOrchestrator.addFinding(sample);

      // Trigger investigation
      const postRes = await dispatch('POST', `/api/findings/${sample.id}/investigate`);
      assert.strictEqual(postRes.statusCode, 200);

      // Fetch persisted investigation
      const getRes = await dispatch('GET', `/api/findings/${sample.id}/investigation`);
      assert.strictEqual(getRes.statusCode, 200);
      assert.strictEqual(getRes.body.success, true);
      assert.strictEqual(getRes.body.data.id, postRes.body.data.id);
      assert.strictEqual(getRes.body.data.findingId, sample.id);
      assert.strictEqual(getRes.body.data.assessment, postRes.body.data.assessment);
    });

    it('should return 404 FINDING_NOT_FOUND for non-existent finding ID', async () => {
      const res = await dispatch('GET', '/api/findings/nonexistent_id/investigation');
      assert.strictEqual(res.statusCode, 404);
      assert.strictEqual(res.body.success, false);
      assert.strictEqual(res.body.error.code, 'FINDING_NOT_FOUND');
    });
  });

  describe('GET /api/findings/:id', () => {
    it('should retrieve uninvestigated finding without attached investigation', async () => {
      const sample = createSampleFinding({ status: 'DETECTED' });
      scanOrchestrator.addFinding(sample);

      const res = await dispatch('GET', `/api/findings/${sample.id}`);
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.body.success, true);
      assert.strictEqual(res.body.data.id, sample.id);
      assert.strictEqual(res.body.data.status, 'DETECTED');
      assert.strictEqual(res.body.data.investigation, undefined);
    });

    it('should retrieve investigated finding enriched with investigation details and status TRIAGED', async () => {
      const sample = createSampleFinding();
      scanOrchestrator.addFinding(sample);

      await dispatch('POST', `/api/findings/${sample.id}/investigate`);

      const res = await dispatch('GET', `/api/findings/${sample.id}`);
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.body.success, true);
      assert.strictEqual(res.body.data.id, sample.id);
      assert.strictEqual(res.body.data.status, 'TRIAGED');
      assert.ok(res.body.data.investigationId);
      assert.ok(res.body.data.aiAssessment);
      assert.ok(res.body.data.investigation);
      assert.strictEqual(res.body.data.investigation.findingId, sample.id);
    });

    it('should return 404 FINDING_NOT_FOUND for non-existent finding ID', async () => {
      const res = await dispatch('GET', '/api/findings/nonexistent_id');
      assert.strictEqual(res.statusCode, 404);
      assert.strictEqual(res.body.success, false);
      assert.strictEqual(res.body.error.code, 'FINDING_NOT_FOUND');
    });
  });

  describe('GET /api/findings', () => {
    it('should list findings with query filters', async () => {
      const finding1 = createSampleFinding({ id: 'f_crit_1', severity: 'CRITICAL', category: 'SQL_INJECTION' });
      const finding2 = createSampleFinding({ id: 'f_low_1', severity: 'LOW', category: 'INFO_DISCLOSURE' });

      scanOrchestrator.addFinding(finding1);
      scanOrchestrator.addFinding(finding2);

      // Filter by severity CRITICAL
      const resCrit = await dispatch('GET', '/api/findings?severity=CRITICAL');
      assert.strictEqual(resCrit.statusCode, 200);
      assert.strictEqual(resCrit.body.data.length, 1);
      assert.strictEqual(resCrit.body.data[0].id, 'f_crit_1');

      // Filter by category INFO_DISCLOSURE
      const resCat = await dispatch('GET', '/api/findings?category=INFO_DISCLOSURE');
      assert.strictEqual(resCat.statusCode, 200);
      assert.strictEqual(resCat.body.data.length, 1);
      assert.strictEqual(resCat.body.data[0].id, 'f_low_1');
    });

    it('should enrich findings in list with investigation metadata if investigated', async () => {
      const finding1 = createSampleFinding({ id: 'f_list_1' });
      scanOrchestrator.addFinding(finding1);

      await dispatch('POST', '/api/findings/f_list_1/investigate');

      const res = await dispatch('GET', '/api/findings');
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.body.data.length, 1);
      assert.strictEqual(res.body.data[0].status, 'TRIAGED');
      assert.ok(res.body.data[0].investigation);
      assert.strictEqual(res.body.data[0].investigation.findingId, 'f_list_1');
    });
  });

  describe('POST /api/findings/:id/analyze (Backward compatibility)', () => {
    it('should alias to investigate and return investigation entity', async () => {
      const sample = createSampleFinding();
      scanOrchestrator.addFinding(sample);

      const res = await dispatch('POST', `/api/findings/${sample.id}/analyze`);
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.body.success, true);
      assert.strictEqual(res.body.data.findingId, sample.id);
      assert.ok(res.body.data.assessment);
    });

    it('should return 404 for non-existent finding ID', async () => {
      const res = await dispatch('POST', '/api/findings/nonexistent_alias_id/analyze');
      assert.strictEqual(res.statusCode, 404);
      assert.strictEqual(res.body.error.code, 'FINDING_NOT_FOUND');
    });
  });

  describe('InvestigationService direct persistence tests', () => {
    it('should save, retrieve by ID, retrieve by finding ID, and list investigations', () => {
      const saved = investigationService.saveInvestigation({
        findingId: 'f_direct_001',
        assessment: 'LIKELY_TRUE',
        explanation: 'Direct explanation',
        impact: 'Direct impact',
        recommendation: 'Direct fix',
        confidence: 'HIGH',
        evidence: ['line 42'],
        preconditions: ['unauthenticated access'],
        limitations: ['none'],
        provenance: { scanner: 'semgrep', ruleId: 'rule.sqli' }
      });

      assert.ok(saved.id);
      assert.strictEqual(saved.findingId, 'f_direct_001');

      const byId = investigationService.getInvestigationById(saved.id);
      assert.deepStrictEqual(byId, saved);

      const byFinding = investigationService.getInvestigationByFindingId('f_direct_001');
      assert.deepStrictEqual(byFinding, saved);

      const list = investigationService.listInvestigations({ assessment: 'LIKELY_TRUE' });
      assert.strictEqual(list.length, 1);
      assert.strictEqual(list[0].id, saved.id);
    });
  });
});
