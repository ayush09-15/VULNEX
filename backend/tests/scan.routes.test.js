const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const app = require('../src/app');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const repositoryService = require('../src/services/repository.service');

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
      'x-request-id': 'req_scan_routes_test',
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

describe('Scan Status and Event Timeline API (Task 19)', () => {
  let tempWorkspace;
  let registeredRepo;

  before(() => {
    scanOrchestrator.clearStores();
    repositoryService._resetStore();

    // Create temporary workspace with vulnerable fixtures
    tempWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex-scan-routes-'));
    fs.mkdirSync(path.join(tempWorkspace, 'src'), { recursive: true });

    fs.writeFileSync(
      path.join(tempWorkspace, 'src', 'app.js'),
      'db.query(`SELECT * FROM items WHERE id = ${req.query.id}`);\nconst apiKey = "AKIA1234567890ABCDEF";\n'
    );

    fs.writeFileSync(
      path.join(tempWorkspace, 'package.json'),
      JSON.stringify({ name: 'fixture-app', version: '1.0.0' }, null, 2)
    );

    // Register repository in repository service
    registeredRepo = repositoryService.registerRepository({
      sourceType: 'GITHUB',
      displayName: 'Fixture Test Repository',
      sourceUrl: 'https://github.com/vulnex/fixture-test-repo',
      defaultRef: 'main'
    });
  });

  after(() => {
    if (tempWorkspace && fs.existsSync(tempWorkspace)) {
      fs.rmSync(tempWorkspace, { recursive: true, force: true });
    }
  });

  // --------------------------------------------------------------------------
  // 1. GET /api/scans
  // --------------------------------------------------------------------------
  describe('GET /api/scans', () => {
    it('should return empty list initially enclosed in canonical envelope', async () => {
      const response = await dispatch('GET', '/api/scans');

      assert.strictEqual(response.statusCode, 200);
      assert.strictEqual(response.body.success, true);
      assert.ok(Array.isArray(response.body.data));
      assert.ok(response.body.requestId);
    });
  });

  // --------------------------------------------------------------------------
  // 2. POST /api/scans
  // --------------------------------------------------------------------------
  describe('POST /api/scans', () => {
    it('should reject scan initiation without repositoryId (400 INVALID_INPUT)', async () => {
      const response = await dispatch('POST', '/api/scans', {
        body: {}
      });

      assert.strictEqual(response.statusCode, 400);
      assert.strictEqual(response.body.success, false);
      assert.strictEqual(response.body.error.code, 'INVALID_INPUT');
      assert.ok(response.body.error.message.includes('repositoryId'));
      assert.ok(response.body.requestId);
    });

    it('should successfully initiate scan and return real scan record (201)', async () => {
      const response = await dispatch('POST', '/api/scans', {
        body: {
          repositoryId: registeredRepo.id,
          repositoryPath: tempWorkspace,
          ref: 'main',
          scanners: ['patterns']
        }
      });

      assert.strictEqual(response.statusCode, 201);
      assert.strictEqual(response.body.success, true);

      const scan = response.body.data;
      assert.ok(scan.id.startsWith('scan_'));
      assert.strictEqual(scan.repositoryId, registeredRepo.id);
      assert.strictEqual(scan.ref, 'main');
      assert.strictEqual(scan.status, 'COMPLETED');
      assert.strictEqual(scan.stage, 'COMPLETED');
      assert.ok(scan.startedAt);
      assert.ok(scan.completedAt);
      assert.ok(Array.isArray(scan.events));
      assert.ok(scan.events.length >= 4);
      assert.ok(scan.summary.totalFindings > 0);
    });
  });

  // --------------------------------------------------------------------------
  // 3. GET /api/scans/:id
  // --------------------------------------------------------------------------
  describe('GET /api/scans/:id', () => {
    it('should return 404 RESOURCE_NOT_FOUND for non-existent scan ID', async () => {
      const response = await dispatch('GET', '/api/scans/scan_nonexistent_999');

      assert.strictEqual(response.statusCode, 404);
      assert.strictEqual(response.body.success, false);
      assert.strictEqual(response.body.error.code, 'RESOURCE_NOT_FOUND');
      assert.ok(response.body.requestId);
    });

    it('should return full scan metadata, real stage, and summary for valid ID', async () => {
      const createRes = await dispatch('POST', '/api/scans', {
        body: {
          repositoryId: registeredRepo.id,
          repositoryPath: tempWorkspace,
          scanners: ['patterns']
        }
      });

      const scanId = createRes.body.data.id;
      const getRes = await dispatch('GET', `/api/scans/${scanId}`);

      assert.strictEqual(getRes.statusCode, 200);
      assert.strictEqual(getRes.body.success, true);

      const scan = getRes.body.data;
      assert.strictEqual(scan.id, scanId);
      assert.strictEqual(scan.status, 'COMPLETED');
      assert.strictEqual(scan.stage, 'COMPLETED');
      assert.ok(scan.summary.totalFindings > 0);
      assert.ok(scan.summary.bySeverity.CRITICAL > 0 || scan.summary.bySeverity.HIGH > 0);
    });
  });

  // --------------------------------------------------------------------------
  // 4. GET /api/scans/:id/events (Task 19 Acceptance Gate)
  // --------------------------------------------------------------------------
  describe('GET /api/scans/:id/events (Real Stage Event Timeline API)', () => {
    it('should return 404 RESOURCE_NOT_FOUND when requesting events for missing scan', async () => {
      const response = await dispatch('GET', '/api/scans/scan_unknown_event/events');

      assert.strictEqual(response.statusCode, 404);
      assert.strictEqual(response.body.success, false);
      assert.strictEqual(response.body.error.code, 'RESOURCE_NOT_FOUND');
    });

    it('should return chronological stage events for a completed scan', async () => {
      const createRes = await dispatch('POST', '/api/scans', {
        body: {
          repositoryId: registeredRepo.id,
          repositoryPath: tempWorkspace,
          scanners: ['patterns']
        }
      });

      const scanId = createRes.body.data.id;
      const eventsRes = await dispatch('GET', `/api/scans/${scanId}/events`);

      assert.strictEqual(eventsRes.statusCode, 200);
      assert.strictEqual(eventsRes.body.success, true);
      assert.ok(Array.isArray(eventsRes.body.data));

      const events = eventsRes.body.data;
      assert.ok(events.length >= 4, 'Must have at least 4 stage events in timeline');

      // Verify chronological stages
      const stages = events.map((e) => e.stage);
      assert.ok(stages.includes('QUEUED'));
      assert.ok(stages.includes('PREPARING'));
      assert.ok(stages.includes('SCANNING'));
      assert.ok(stages.includes('NORMALIZING'));

      // Validate event object attributes
      for (const event of events) {
        assert.ok(event.stage, 'Event must have stage');
        assert.ok(['IN_PROGRESS', 'SUCCESS', 'FAILED', 'SKIPPED'].includes(event.status), 'Event must have valid status');
        assert.ok(event.timestamp, 'Event must have ISO timestamp');
        assert.ok(event.message, 'Event must have descriptive message');
      }
    });
  });

  // --------------------------------------------------------------------------
  // 5. GET /api/scans/:id/findings
  // --------------------------------------------------------------------------
  describe('GET /api/scans/:id/findings', () => {
    it('should return 404 for missing scan', async () => {
      const response = await dispatch('GET', '/api/scans/scan_ghost_123/findings');
      assert.strictEqual(response.statusCode, 404);
      assert.strictEqual(response.body.success, false);
    });

    it('should return all normalized findings for scan', async () => {
      const createRes = await dispatch('POST', '/api/scans', {
        body: {
          repositoryId: registeredRepo.id,
          repositoryPath: tempWorkspace,
          scanners: ['patterns']
        }
      });

      const scanId = createRes.body.data.id;
      const findingsRes = await dispatch('GET', `/api/scans/${scanId}/findings`);

      assert.strictEqual(findingsRes.statusCode, 200);
      assert.strictEqual(findingsRes.body.success, true);
      assert.ok(Array.isArray(findingsRes.body.data));
      assert.ok(findingsRes.body.data.length >= 2);

      const first = findingsRes.body.data[0];
      assert.ok(first.id.startsWith('find_'));
      assert.strictEqual(first.scanId, scanId);
      assert.strictEqual(first.status, 'DETECTED');
      assert.ok(first.fingerprint && first.fingerprint.length === 64);
    });

    it('should filter findings by severity query parameter', async () => {
      const createRes = await dispatch('POST', '/api/scans', {
        body: {
          repositoryId: registeredRepo.id,
          repositoryPath: tempWorkspace,
          scanners: ['patterns']
        }
      });

      const scanId = createRes.body.data.id;
      const filteredRes = await dispatch('GET', `/api/scans/${scanId}/findings?severity=CRITICAL`);

      assert.strictEqual(filteredRes.statusCode, 200);
      const findings = filteredRes.body.data;
      assert.ok(findings.length > 0);
      for (const f of findings) {
        assert.strictEqual(f.severity, 'CRITICAL');
      }
    });
  });

  // --------------------------------------------------------------------------
  // 6. POST /api/scans/:id/cancel & DELETE /api/scans/:id
  // --------------------------------------------------------------------------
  describe('Cancel & Delete Scan Endpoints', () => {
    it('should reject cancelling an already terminal scan with 409 INVALID_STATE_TRANSITION', async () => {
      const createRes = await dispatch('POST', '/api/scans', {
        body: {
          repositoryId: registeredRepo.id,
          repositoryPath: tempWorkspace,
          scanners: ['patterns']
        }
      });

      const scanId = createRes.body.data.id;
      const cancelRes = await dispatch('POST', `/api/scans/${scanId}/cancel`, {
        body: { reason: 'Test abort' }
      });

      assert.strictEqual(cancelRes.statusCode, 409);
      assert.strictEqual(cancelRes.body.success, false);
      assert.strictEqual(cancelRes.body.error.code, 'INVALID_STATE_TRANSITION');
    });

    it('should delete an existing scan (200) and return 404 afterwards', async () => {
      const createRes = await dispatch('POST', '/api/scans', {
        body: {
          repositoryId: registeredRepo.id,
          repositoryPath: tempWorkspace,
          scanners: ['patterns']
        }
      });

      const scanId = createRes.body.data.id;
      const delRes = await dispatch('DELETE', `/api/scans/${scanId}`);

      assert.strictEqual(delRes.statusCode, 200);
      assert.strictEqual(delRes.body.success, true);
      assert.strictEqual(delRes.body.data.deleted, true);

      const checkRes = await dispatch('GET', `/api/scans/${scanId}`);
      assert.strictEqual(checkRes.statusCode, 404);
    });
  });
});
