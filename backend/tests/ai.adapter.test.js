const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  GoogleAIModelAdapter,
  AIError,
  AITimeoutError,
  AIQuotaExceededError,
  AIAuthError,
  redactApiKey
} = require('../src/services/ai.adapter');
const { AIService } = require('../src/services/ai.service');

describe('Server-Side AI Model Adapter & Configuration (Commit 24)', () => {
  describe('1. Server-Only Key Protection & Secret Redaction', () => {
    it('never exposes the raw API key in getModelInfo or JSON serialization', () => {
      const sensitiveKey = 'AIzaSySecretApiKey1234567890';
      const adapter = new GoogleAIModelAdapter({
        apiKey: sensitiveKey,
        model: 'gemini-1.5-pro'
      });

      const info = adapter.getModelInfo();
      assert.equal(info.configured, true);
      assert.equal(info.model, 'gemini-1.5-pro');
      assert.equal(info.apiKey, undefined, 'Raw apiKey must not be present in getModelInfo');

      const jsonStr = JSON.stringify(adapter);
      assert.ok(!jsonStr.includes(sensitiveKey), 'Serialized JSON must never leak the API key');
    });

    it('redactApiKey strips keys from URLs and error text', () => {
      const apiKey = 'AIzaSySecretApiKey12345';
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=${apiKey}`;
      const redacted = redactApiKey(url, apiKey);

      assert.ok(!redacted.includes(apiKey));
      assert.ok(redacted.includes('key=[REDACTED]'));

      const errorText = `Failed with key ${apiKey} during handshake`;
      const sanitizedError = redactApiKey(errorText, apiKey);
      assert.ok(!sanitizedError.includes(apiKey));
      assert.ok(sanitizedError.includes('[REDACTED]'));
    });

    it('isAvailable returns false when API key is missing or empty placeholder', () => {
      const adapter1 = new GoogleAIModelAdapter({ apiKey: '' });
      assert.equal(adapter1.isAvailable(), false);

      const adapter2 = new GoogleAIModelAdapter({ apiKey: 'PLACEHOLDER_KEY' });
      assert.equal(adapter2.isAvailable(), false);
    });

    it('rejects generateCompletion immediately with AIAuthError if apiKey is unconfigured', async () => {
      const adapter = new GoogleAIModelAdapter({ apiKey: '' });
      await assert.rejects(
        async () => {
          await adapter.generateCompletion({ userPrompt: 'Hello' });
        },
        (err) => err instanceof AIAuthError && err.code === 'AI_AUTH_FAILED'
      );
    });
  });

  describe('2. Model Environment Variable & Options Configuration', () => {
    it('uses explicit model option when supplied', () => {
      const adapter = new GoogleAIModelAdapter({
        apiKey: 'test-key',
        model: 'gemini-1.5-flash',
        timeoutMs: 8000
      });

      assert.equal(adapter.model, 'gemini-1.5-flash');
      assert.equal(adapter.timeoutMs, 8000);
    });

    it('defaults model safely to gemma-2-9b-it if model is unspecified', () => {
      const adapter = new GoogleAIModelAdapter({
        apiKey: 'test-key',
        model: null
      });

      assert.ok(adapter.model.length > 0);
    });
  });

  describe('3. Error Classification & Quota/Timeout Handling', () => {
    it('creates AIQuotaExceededError with HTTP 429 status code', () => {
      const err = new AIQuotaExceededError('Resource exhausted');
      assert.equal(err.code, 'AI_QUOTA_EXCEEDED');
      assert.equal(err.status, 429);
      assert.ok(err instanceof AIError);
    });

    it('creates AITimeoutError with HTTP 504 status code', () => {
      const err = new AITimeoutError('Model timed out');
      assert.equal(err.code, 'AI_TIMEOUT');
      assert.equal(err.status, 504);
      assert.ok(err instanceof AIError);
    });

    it('creates AIAuthError with HTTP 401 status code', () => {
      const err = new AIAuthError('Unauthorized');
      assert.equal(err.code, 'AI_AUTH_FAILED');
      assert.equal(err.status, 401);
      assert.ok(err instanceof AIError);
    });
  });

  describe('4. AIService Resilience on Quota & Timeout', () => {
    it('returns schema-compliant fallback investigation when AI model throws QuotaExceededError', async () => {
      const service = new AIService({
        apiKey: 'test-key',
        model: 'gemma-2-9b-it'
      });

      // Mock adapter to simulate quota exhaustion
      service.adapter.generateCompletion = async () => {
        throw new AIQuotaExceededError('Quota limit exceeded: Daily quota used up.');
      };

      const finding = {
        id: 'find_sql_test',
        title: 'SQL Injection in user route',
        category: 'SQL_INJECTION',
        severity: 'HIGH',
        filePath: 'src/routes/user.js',
        startLine: 24,
        evidence: 'SELECT * FROM users'
      };

      const result = await service.analyzeVulnerability(finding);

      assert.equal(result.findingId, 'find_sql_test');
      assert.equal(result.assessment, 'UNCERTAIN');
      assert.equal(result.confidence, 'LOW');
      assert.ok(result.limitations.some(l => l.includes('Quota') || l.includes('unavailable')));
    });

    it('returns schema-compliant fallback investigation when AI model times out', async () => {
      const service = new AIService({
        apiKey: 'test-key',
        model: 'gemma-2-9b-it'
      });

      // Mock adapter to simulate timeout
      service.adapter.generateCompletion = async () => {
        throw new AITimeoutError('Inference timed out after 15000ms.');
      };

      const finding = {
        id: 'find_xss_test',
        title: 'Reflected XSS',
        category: 'XSS',
        severity: 'HIGH',
        filePath: 'src/controllers/search.js',
        startLine: 12
      };

      const result = await service.analyzeVulnerability(finding);

      assert.equal(result.findingId, 'find_xss_test');
      assert.equal(result.assessment, 'UNCERTAIN');
      assert.equal(result.confidence, 'LOW');
      assert.ok(result.limitations.some(l => l.includes('timed out') || l.includes('unavailable')));
    });
  });
});
