const { describe, it } = require('node:test');
const assert = require('node:assert');
const http = require('http');
const app = require('../src/app');
const errorHandler = require('../src/middleware/errorHandler');

/**
 * Helper to dispatch HTTP requests directly to the Express application
 * without opening network socket ports.
 */
function makeRequest(url, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve) => {
    const req = new http.IncomingMessage();
    req.method = method;
    req.url = url;
    req.originalUrl = url;
    req.headers = { ...headers };

    const res = new http.ServerResponse(req);
    let rawBody = '';

    res.write = (chunk) => {
      if (chunk) rawBody += chunk;
      return true;
    };

    res.end = (chunk) => {
      if (chunk) rawBody += chunk;
      let parsedBody = null;
      try {
        parsedBody = rawBody ? JSON.parse(rawBody) : null;
      } catch (_) {
        parsedBody = rawBody;
      }

      resolve({
        statusCode: res.statusCode,
        headers: res.getHeaders(),
        body: parsedBody
      });
    };

    app.handle(req, res);
  });
}

describe('VULNEX Express Backend Scaffold & Health Route', () => {
  it('1. GET /api/health returns HTTP 200', async () => {
    const response = await makeRequest('/api/health');
    assert.strictEqual(response.statusCode, 200);
  });

  it('2. Response has success: true', async () => {
    const response = await makeRequest('/api/health');
    assert.ok(response.body);
    assert.strictEqual(response.body.success, true);
  });

  it('3. Response contains data.status = healthy', async () => {
    const response = await makeRequest('/api/health');
    assert.ok(response.body?.data);
    assert.strictEqual(response.body.data.status, 'healthy');
  });

  it('4. Response contains data.service = vulnex-api', async () => {
    const response = await makeRequest('/api/health');
    assert.ok(response.body?.data);
    assert.strictEqual(response.body.data.service, 'vulnex-api');
  });

  it('5. Response contains requestId in envelope and X-Request-ID header', async () => {
    const response = await makeRequest('/api/health');
    assert.ok(response.body?.requestId, 'Envelope should include requestId');
    assert.ok(response.body.requestId.startsWith('req_'), 'requestId must start with req_');

    const headerRequestId = response.headers['x-request-id'];
    assert.ok(headerRequestId, 'X-Request-ID header must be present');
    assert.strictEqual(response.body.requestId, headerRequestId);

    // Propagation of client-supplied X-Request-ID
    const customTraceId = 'req_custom_trace_987654321';
    const customResponse = await makeRequest('/api/health', {
      headers: { 'x-request-id': customTraceId }
    });
    assert.strictEqual(customResponse.body.requestId, customTraceId);
    assert.strictEqual(customResponse.headers['x-request-id'], customTraceId);
  });

  it('6. Unknown routes return the documented 404 error envelope', async () => {
    const response = await makeRequest('/api/unknown-nonexistent-endpoint');
    assert.strictEqual(response.statusCode, 404);
    assert.strictEqual(response.body.success, false);
    assert.ok(response.body.error);
    assert.strictEqual(response.body.error.code, 'RESOURCE_NOT_FOUND');
    assert.ok(response.body.error.message.includes('/api/unknown-nonexistent-endpoint'));
    assert.ok(response.body.requestId);
  });

  it('7. Unexpected errors return a safe error envelope', async () => {
    // Dispatch error directly through centralized errorHandler middleware
    const mockReq = new http.IncomingMessage();
    mockReq.method = 'GET';
    mockReq.url = '/api/simulated-error';
    mockReq.id = 'req_test_error_123';

    const mockRes = new http.ServerResponse(mockReq);
    let capturedBody = null;

    mockRes.status = (code) => {
      mockRes.statusCode = code;
      return mockRes;
    };
    mockRes.json = (data) => {
      capturedBody = data;
      return mockRes;
    };

    const simulatedError = new Error('Database server connection timeout at 10.0.0.5:5432');
    simulatedError.stack = 'Error: Database connection timeout\n    at query (/app/src/db.js:55:12)\n    at Object.<anonymous>';

    errorHandler(simulatedError, mockReq, mockRes, () => {});

    assert.strictEqual(mockRes.statusCode, 500);
    assert.ok(capturedBody);
    assert.strictEqual(capturedBody.success, false);
    assert.strictEqual(capturedBody.error.code, 'INTERNAL_SERVER_ERROR');
    assert.strictEqual(capturedBody.error.message, 'An unexpected internal server error occurred.');
    assert.strictEqual(capturedBody.requestId, 'req_test_error_123');
  });

  it('8. Stack traces are not exposed to clients', async () => {
    const mockReq = new http.IncomingMessage();
    mockReq.method = 'POST';
    mockReq.url = '/api/crash';
    mockReq.id = 'req_stack_test';

    const mockRes = new http.ServerResponse(mockReq);
    let capturedBody = null;

    mockRes.status = (code) => {
      mockRes.statusCode = code;
      return mockRes;
    };
    mockRes.json = (data) => {
      capturedBody = data;
      return mockRes;
    };

    const internalCrash = new Error('Critical core dump in /Users/internal/secret/key.pem');
    internalCrash.stack = 'Error: Critical core dump\n    at eval (eval at <anonymous>)\n    at NativeMethod';

    errorHandler(internalCrash, mockReq, mockRes, () => {});

    const serialized = JSON.stringify(capturedBody);
    assert.strictEqual(capturedBody.error.stack, undefined, 'Stack trace must not exist on error payload');
    assert.ok(!serialized.includes('/Users/internal/secret/key.pem'), 'Internal paths must not leak');
    assert.ok(!serialized.includes('at eval'), 'Stack frames must not leak into response');
  });
});
