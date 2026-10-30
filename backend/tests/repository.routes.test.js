const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const router = require('../src/routes/repository.routes');
const { _resetStore } = require('../src/services/repository.service');

// Helper to simulate Express route handler invocation
function mockRoute(method, path, { body = {}, query = {}, params = {}, headers = {} } = {}) {
  return new Promise((resolve) => {
    const req = {
      method,
      url: path,
      originalUrl: path,
      body,
      query,
      params,
      headers: { 'x-request-id': 'req_mock_test_123', ...headers }
    };

    let statusCode = 200;
    const res = {
      status(code) {
        statusCode = code;
        return this;
      },
      json(payload) {
        resolve({ statusCode, body: payload });
      }
    };

    // Find the matching layer in the router stack
    const matchingLayer = router.stack.find((layer) => {
      if (!layer.route) return false;
      const layerMethod = Object.keys(layer.route.methods)[0].toUpperCase();
      return layerMethod === method.toUpperCase() && layer.route.path === path;
    });

    if (matchingLayer) {
      matchingLayer.handle(req, res);
    } else {
      resolve({ statusCode: 404, body: { error: 'Route not found in test harness' } });
    }
  });
}

describe('Repository HTTP Routes (Commit 07 Controller Integration)', () => {
  beforeEach(() => {
    _resetStore();
  });

  it('POST /api/repositories rejects invalid scheme with 400 and canonical error envelope', async () => {
    const res = await mockRoute('POST', '/', {
      body: {
        sourceType: 'GITHUB',
        sourceUrl: 'http://github.com/org/repo'
      }
    });

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.success, false);
    assert.equal(res.body.error.code, 'INVALID_URL');
  });

  it('POST /api/repositories rejects SSRF private IP target with 400', async () => {
    const res = await mockRoute('POST', '/', {
      body: {
        sourceType: 'GITHUB',
        sourceUrl: 'https://169.254.169.254/secret/repo'
      }
    });

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.success, false);
    assert.equal(res.body.error.code, 'INVALID_URL');
  });

  it('POST /api/repositories registers valid repository with 201', async () => {
    const res = await mockRoute('POST', '/', {
      body: {
        sourceType: 'GITHUB',
        sourceUrl: 'https://github.com/juice-shop/juice-shop',
        displayName: 'Juice Shop'
      }
    });

    assert.equal(res.statusCode, 201);
    assert.equal(res.body.success, true);
    assert.ok(res.body.data.id.startsWith('repo_'));
    assert.equal(res.body.data.sanitizedSourceUrl, 'https://github.com/juice-shop/juice-shop');
    assert.equal(res.body.data.displayName, 'Juice Shop');
  });

  it('GET /api/repositories returns repository array in envelope', async () => {
    const res = await mockRoute('GET', '/');
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.success, true);
    assert.ok(Array.isArray(res.body.data));
    assert.ok(res.body.data.length >= 1);
  });

  it('GET /api/repositories/:id returns 404 for nonexistent id', async () => {
    const res = await mockRoute('GET', '/:id', { params: { id: 'nonexistent_123' } });
    assert.equal(res.statusCode, 404);
    assert.equal(res.body.success, false);
    assert.equal(res.body.error.code, 'RESOURCE_NOT_FOUND');
  });
});
