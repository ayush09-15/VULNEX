/**
 * VULNEX Secret Redaction Regression Test Suite
 *
 * Verifies centralized secret redaction across:
 * 1. Sensitive values: API keys, tokens, auth headers, passwords, connection strings, private keys.
 * 2. Nested objects, arrays, and Error instances (redactDeep).
 * 3. Environment sanitization (sanitizeEnvironment, getSafeEnvSummary).
 * 4. Backend logs (safeLogger, console interception).
 * 5. API responses and error handlers (apiResponse, errorHandler).
 * 6. AI prompt and request context (buildInvestigationPrompt, buildPatchProposalPrompt, getFileExcerpt).
 * 7. Source file integrity (in-memory only, no disk mutation).
 */

const { describe, it, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');

const {
  redactString,
  redactSecrets,
  redactDeep,
  sanitizeEnvironment,
  getSafeEnvSummary,
  safeLogger
} = require('../src/utils/secretRedactor');

const apiResponse = require('../src/utils/apiResponse');
const errorHandler = require('../src/middleware/errorHandler');
const { buildInvestigationPrompt, buildPatchProposalPrompt } = require('../src/services/ai.prompt');
const { getFileExcerpt } = require('../src/services/inventory.service');

// ----------------------------------------------------------------------------
// Synthetic Test Secrets (strictly fake and non-functional)
// Broken into dynamic components to prevent false positives in static secret scanners
// ----------------------------------------------------------------------------
const FAKE_AWS_KEY = ['AKIA', 'IOSFODNN7FAKEKEY'].join('');
const FAKE_GITHUB_TOKEN = 'ghp_fakePersonalAccessToken1234567890abcdefgh';
const FAKE_GOOGLE_KEY = 'AIzaSyFakeGoogleApiKey1234567890abcdef';
const FAKE_SLACK_TOKEN = 'xoxb-fake-1234567890-abcdefghijklmnopqrstuvwx';
const FAKE_STRIPE_KEY = ['sk_live', 'fakeStripeKey1234567890abcdef'].join('_');
const FAKE_AWS_SECRET = ['wJalrXUtnFEMI', 'K7MDENG/bPxRfiCYFAKEKEY123'].join('/');
const FAKE_BEARER_TOKEN = 'Bearer fakeBearerTokenPayload1234567890abcdefgh';
const FAKE_JWT = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fakeSignatureValue12345';
const FAKE_BASIC_AUTH = 'Basic dXNlcjpzdXBlcnNlY3JldHBhc3M=';
const FAKE_PASSWORD = 'SuperFakeSecretPassword123!';
const FAKE_MONGO_URI = 'mongodb://fakeAdmin:fakeSecretPassword999@cluster0.fake.mongodb.net/vulnex';
const FAKE_POSTGRES_URI = 'postgres://db_user:fakePostgresPassword888@localhost:5432/vulnex_db';
const FAKE_REDIS_URI = 'redis://:fakeRedisPassword777@localhost:6379';

const FAKE_RSA_KEY = [
  '-----BEGIN RSA PRIVATE KEY-----',
  'MIIEowIBAAKCAQEA0fakeKeyData1234567890abcdefghijklmnopqrstuvwxyz',
  'fakeKeyPayloadLine2abcdefghijklmnopqrstuvwxyz1234567890==',
  '-----END RSA PRIVATE KEY-----'
].join('\n');

const FAKE_OPENSSH_KEY = [
  '-----BEGIN OPENSSH PRIVATE KEY-----',
  'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn',
  'fakeOpenSshPayloadData1234567890abcdefghijklmnopqrstuvwxyz==',
  '-----END OPENSSH PRIVATE KEY-----'
].join('\n');

const FAKE_PGP_KEY = [
  '-----BEGIN PGP PRIVATE KEY BLOCK-----',
  'lQHYBFfakeKeyDataLine1abcdefghijklmnopqrstuvwxyz1234567890==',
  '-----END PGP PRIVATE KEY BLOCK-----'
].join('\n');

describe('Secret Redaction & Log Sanitization (Security Hardening)', () => {

  // --------------------------------------------------------------------------
  // 1. String Redaction Patterns
  // --------------------------------------------------------------------------
  describe('1. Pattern Detection & Redaction in Strings', () => {
    it('redacts AWS Access Key IDs', () => {
      const input = `Deploying with AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY} to us-east-1`;
      const result = redactString(input);
      assert.equal(result.includes(FAKE_AWS_KEY), false);
      assert.ok(result.includes('[REDACTED_AWS_KEY]'));
    });

    it('redacts GitHub Personal Access Tokens and Fine-Grained Tokens', () => {
      const input = `Clone repo with token: ${FAKE_GITHUB_TOKEN} from github.com`;
      const result = redactString(input);
      assert.equal(result.includes(FAKE_GITHUB_TOKEN), false);
      assert.ok(result.includes('[REDACTED_GITHUB_TOKEN]'));

      const fineGrained = 'github_pat_11AAAAAAA0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      const resultFg = redactString(fineGrained);
      assert.equal(resultFg.includes('github_pat_'), false);
      assert.ok(resultFg.includes('[REDACTED_GITHUB_TOKEN]'));
    });

    it('redacts Google / Gemini AI API keys', () => {
      const input = `Using Gemini with key=${FAKE_GOOGLE_KEY} for reasoning`;
      const result = redactString(input);
      assert.equal(result.includes(FAKE_GOOGLE_KEY), false);
      assert.ok(result.includes('[REDACTED_API_KEY]'));
    });

    it('redacts Slack and Stripe API keys', () => {
      const input = `Slack bot: ${FAKE_SLACK_TOKEN} and Stripe: ${FAKE_STRIPE_KEY}`;
      const result = redactString(input);
      assert.equal(result.includes(FAKE_SLACK_TOKEN), false);
      assert.equal(result.includes(FAKE_STRIPE_KEY), false);
      assert.ok(result.includes('[REDACTED_SLACK_TOKEN]'));
      assert.ok(result.includes('[REDACTED_STRIPE_KEY]'));
    });

    it('redacts Bearer tokens and Authorization headers', () => {
      const bearerInput = `Authorization: ${FAKE_BEARER_TOKEN}`;
      const resBearer = redactString(bearerInput);
      assert.equal(resBearer.includes('fakeBearerTokenPayload'), false);
      assert.ok(resBearer.includes('Bearer [REDACTED_BEARER_TOKEN]'));

      const jwtInput = `Header: ${FAKE_JWT}`;
      const resJwt = redactString(jwtInput);
      assert.equal(resJwt.includes('fakeSignatureValue'), false);
      assert.ok(resJwt.includes('Bearer [REDACTED_BEARER_TOKEN]'));

      const basicInput = `Header: ${FAKE_BASIC_AUTH}`;
      const resBasic = redactString(basicInput);
      assert.equal(resBasic.includes('dXNlcjpzdXBlcnNlY3JldHBhc3M='), false);
      assert.ok(resBasic.includes('Basic [REDACTED_BASIC_AUTH]'));
    });

    it('redacts database connection URIs preserving host and scheme', () => {
      const mongoResult = redactString(FAKE_MONGO_URI);
      assert.equal(mongoResult.includes('fakeSecretPassword999'), false);
      assert.ok(mongoResult.includes('mongodb://fakeAdmin:[REDACTED_PASSWORD]@cluster0.fake.mongodb.net/vulnex'));

      const pgResult = redactString(FAKE_POSTGRES_URI);
      assert.equal(pgResult.includes('fakePostgresPassword888'), false);
      assert.ok(pgResult.includes('postgres://db_user:[REDACTED_PASSWORD]@localhost:5432/vulnex_db'));

      const redisResult = redactString(FAKE_REDIS_URI);
      assert.equal(redisResult.includes('fakeRedisPassword777'), false);
      assert.ok(redisResult.includes('redis://:[REDACTED_PASSWORD]@localhost:6379'));
    });

    it('redacts multiline private key blocks (RSA, OpenSSH, PGP)', () => {
      const rsaResult = redactString(FAKE_RSA_KEY);
      assert.equal(rsaResult.includes('0fakeKeyData1234567890'), false);
      assert.ok(rsaResult.includes('[REDACTED_PRIVATE_KEY]'));

      const sshResult = redactString(FAKE_OPENSSH_KEY);
      assert.equal(sshResult.includes('fakeOpenSshPayloadData'), false);
      assert.ok(sshResult.includes('[REDACTED_PRIVATE_KEY]'));

      const pgpResult = redactString(FAKE_PGP_KEY);
      assert.equal(pgpResult.includes('fakeKeyDataLine1'), false);
      assert.ok(pgpResult.includes('[REDACTED_PRIVATE_KEY]') || pgpResult.includes('[REDACTED_PGP_PRIVATE_KEY]'));
    });

    it('redacts code assignments for password, secret, and apikey', () => {
      const assignments = [
        `const password = "${FAKE_PASSWORD}";`,
        `const db_pass = '${FAKE_PASSWORD}';`,
        `api_key: "${FAKE_GOOGLE_KEY}",`,
        `client_secret = "${FAKE_PASSWORD}";`
      ];

      for (const line of assignments) {
        const result = redactString(line);
        assert.equal(result.includes(FAKE_PASSWORD), false);
        assert.equal(result.includes(FAKE_GOOGLE_KEY), false);
        assert.ok(result.includes('[REDACTED_SECRET]') || result.includes('[REDACTED_API_KEY]'));
      }
    });

    it('redacts credentials passed in URL query parameters', () => {
      const url = `https://api.example.com/v1/resource?key=${FAKE_GOOGLE_KEY}&token=${FAKE_GITHUB_TOKEN}&format=json`;
      const result = redactString(url);
      assert.equal(result.includes(FAKE_GOOGLE_KEY), false);
      assert.equal(result.includes(FAKE_GITHUB_TOKEN), false);
      assert.ok(result.includes('key=[REDACTED]'));
      assert.ok(result.includes('token=[REDACTED]'));
      assert.ok(result.includes('format=json'));
    });

    it('does not re-mask or corrupt existing redaction markers', () => {
      const marker = 'const auth = "[REDACTED_SECRET]";\nconst key = "[REDACTED_AWS_KEY]";';
      const result = redactString(marker);
      assert.equal(result, marker);
    });

    it('redacts user-supplied caller secrets via knownSecrets option', () => {
      const customSecret = 'my-custom-super-secret-nonce-987654';
      const text = `Operation failed while accessing service with ${customSecret}.`;
      const result = redactString(text, { knownSecrets: [customSecret] });
      assert.equal(result.includes(customSecret), false);
      assert.ok(result.includes('[REDACTED]'));
    });
  });

  // --------------------------------------------------------------------------
  // 2. Deep Recursive Redaction (Objects, Arrays, Errors)
  // --------------------------------------------------------------------------
  describe('2. Deep Recursive Redaction (redactDeep)', () => {
    it('redacts sensitive fields and values in deeply nested objects', () => {
      const payload = {
        scanId: 'scan_001',
        config: {
          database: {
            url: FAKE_POSTGRES_URI,
            password: FAKE_PASSWORD
          },
          auth: {
            apiKey: FAKE_GOOGLE_KEY,
            tokens: [FAKE_GITHUB_TOKEN, 'safe-public-identifier']
          }
        },
        metadata: {
          note: `Contacted ${FAKE_MONGO_URI}`
        }
      };

      const result = redactDeep(payload);

      // Verify no secrets exist in result
      const serialized = JSON.stringify(result);
      assert.equal(serialized.includes(FAKE_POSTGRES_URI), false);
      assert.equal(serialized.includes(FAKE_PASSWORD), false);
      assert.equal(serialized.includes(FAKE_GOOGLE_KEY), false);
      assert.equal(serialized.includes(FAKE_GITHUB_TOKEN), false);
      assert.equal(serialized.includes(FAKE_MONGO_URI), false);

      // Verify structure is preserved
      assert.equal(result.scanId, 'scan_001');
      assert.equal(result.config.auth.tokens[1], 'safe-public-identifier');
      assert.ok(result.config.database.password.includes('[REDACTED'));

      // Verify input object was not mutated
      assert.equal(payload.config.database.password, FAKE_PASSWORD);
      assert.equal(payload.config.auth.apiKey, FAKE_GOOGLE_KEY);
    });

    it('handles Error instances redacting message and details', () => {
      const originalErr = new Error(`Connection to ${FAKE_MONGO_URI} failed with password: ${FAKE_PASSWORD}`);
      originalErr.code = 'CONNECTION_FAILED';
      originalErr.statusCode = 500;
      originalErr.details = { rawQuery: `SELECT * FROM users WHERE token = '${FAKE_GITHUB_TOKEN}'` };

      const sanitizedErr = redactDeep(originalErr);

      assert.ok(sanitizedErr instanceof Error);
      assert.equal(sanitizedErr.code, 'CONNECTION_FAILED');
      assert.equal(sanitizedErr.statusCode, 500);
      assert.equal(sanitizedErr.message.includes(FAKE_PASSWORD), false);
      assert.equal(sanitizedErr.message.includes('fakeSecretPassword999'), false);
      assert.equal(sanitizedErr.details.rawQuery.includes(FAKE_GITHUB_TOKEN), false);
    });

    it('safely handles circular references without throwing', () => {
      const circularObj = {
        name: 'parent',
        secret: FAKE_PASSWORD
      };
      circularObj.child = {
        parentRef: circularObj
      };

      const result = redactDeep(circularObj);
      assert.equal(result.secret.includes('[REDACTED'), true);
      assert.equal(result.child.parentRef, '[Circular]');
    });

    it('handles DAG aliasing without false-positive [Circular]', () => {
      const sharedNode = { tool: 'semgrep', version: '1.98.0' };
      const dag = {
        branchA: sharedNode,
        branchB: sharedNode
      };

      const result = redactDeep(dag);
      assert.equal(result.branchA.tool, 'semgrep');
      assert.equal(result.branchB.tool, 'semgrep');
      assert.notEqual(result.branchB, '[Circular]');
    });
  });

  // --------------------------------------------------------------------------
  // 3. Environment Sanitization
  // --------------------------------------------------------------------------
  describe('3. Safe Environment Sanitization', () => {
    it('sanitizes sensitive environment variables', () => {
      const mockEnv = {
        NODE_ENV: 'test',
        PORT: '5001',
        AWS_SECRET_ACCESS_KEY: FAKE_AWS_SECRET,
        GEMINI_API_KEY: FAKE_GOOGLE_KEY,
        DATABASE_URL: FAKE_POSTGRES_URI,
        GITHUB_TOKEN: FAKE_GITHUB_TOKEN,
        APP_NAME: 'vulnex-backend'
      };

      const sanitized = sanitizeEnvironment(mockEnv);

      assert.equal(sanitized.NODE_ENV, 'test');
      assert.equal(sanitized.PORT, '5001');
      assert.equal(sanitized.APP_NAME, 'vulnex-backend');
      assert.equal(sanitized.AWS_SECRET_ACCESS_KEY, '[REDACTED]');
      assert.equal(sanitized.GEMINI_API_KEY, '[REDACTED]');
      assert.equal(sanitized.DATABASE_URL, '[REDACTED]');
      assert.equal(sanitized.GITHUB_TOKEN, '[REDACTED]');

      // Verify no secrets appear in serialized string
      const json = JSON.stringify(sanitized);
      assert.equal(json.includes(FAKE_GOOGLE_KEY), false);
      assert.equal(json.includes(FAKE_POSTGRES_URI), false);
      assert.equal(json.includes(FAKE_GITHUB_TOKEN), false);
    });

    it('provides bounded, safe environment summary without dumping full process.env', () => {
      const summary = getSafeEnvSummary();
      assert.ok(summary.nodeEnv);
      assert.ok(summary.port);
      assert.ok(summary.platform);
      assert.ok(summary.nodeVersion);

      // Verify no credential keys exist in summary
      assert.equal('GEMINI_API_KEY' in summary, false);
      assert.equal('DATABASE_URL' in summary, false);
      assert.equal('AWS_SECRET_ACCESS_KEY' in summary, false);
    });
  });

  // --------------------------------------------------------------------------
  // 4. Backend Logging Boundary
  // --------------------------------------------------------------------------
  describe('4. Backend Log Sanitization Boundary', () => {
    let capturedLogs;
    let originalConsole;

    beforeEach(() => {
      capturedLogs = [];
      originalConsole = {
        log: console.log,
        info: console.info,
        warn: console.warn,
        error: console.error
      };

      const capture = (level) => (...args) => {
        capturedLogs.push({
          level,
          text: args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ')
        });
      };

      console.log = capture('log');
      console.info = capture('info');
      console.warn = capture('warn');
      console.error = capture('error');
    });

    afterEach(() => {
      console.log = originalConsole.log;
      console.info = originalConsole.info;
      console.warn = originalConsole.warn;
      console.error = originalConsole.error;
    });

    it('safeLogger scrubs secrets before writing to stdout/stderr', () => {
      safeLogger.info(`Worker connected to ${FAKE_MONGO_URI}`);
      safeLogger.warn(`API call failed with authorization: ${FAKE_BEARER_TOKEN}`);
      safeLogger.error(`Database failure with password: ${FAKE_PASSWORD}`);

      assert.equal(capturedLogs.length, 3);
      for (const log of capturedLogs) {
        assert.equal(log.text.includes(FAKE_MONGO_URI), false);
        assert.equal(log.text.includes(FAKE_BEARER_TOKEN), false);
        assert.equal(log.text.includes(FAKE_PASSWORD), false);
        assert.ok(log.text.includes('[REDACTED'));
      }
    });

    it('safeLogger scrubs secrets embedded inside logged object parameters', () => {
      safeLogger.error('Diagnostic error dump:', {
        service: 'scanner-engine',
        credentials: {
          key: FAKE_AWS_KEY,
          secret: FAKE_PASSWORD
        }
      });

      assert.equal(capturedLogs.length, 1);
      const text = capturedLogs[0].text;
      assert.equal(text.includes(FAKE_AWS_KEY), false);
      assert.equal(text.includes(FAKE_PASSWORD), false);
      assert.ok(text.includes('[REDACTED'));
    });
  });

  // --------------------------------------------------------------------------
  // 5. API Response & Error Handling Boundaries
  // --------------------------------------------------------------------------
  describe('5. API Response & Error Handling Boundaries', () => {
    let capturedLogs;
    let originalConsole;

    beforeEach(() => {
      capturedLogs = [];
      originalConsole = { error: console.error };
      console.error = (...args) => {
        capturedLogs.push(args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' '));
      };
    });

    afterEach(() => {
      console.error = originalConsole.error;
    });

    it('apiResponse.success scrubs secrets from response payloads', () => {
      let sentPayload = null;
      let sentStatus = null;
      const res = {
        req: { id: 'req_test_01' },
        status(code) {
          sentStatus = code;
          return this;
        },
        json(data) {
          sentPayload = data;
          return this;
        }
      };

      apiResponse.success(res, {
        repository: 'vulnex-core',
        dbConnection: FAKE_POSTGRES_URI,
        auth: { token: FAKE_GITHUB_TOKEN }
      });

      assert.equal(sentStatus, 200);
      assert.equal(sentPayload.success, true);
      const json = JSON.stringify(sentPayload);
      assert.equal(json.includes('fakePostgresPassword888'), false);
      assert.equal(json.includes(FAKE_GITHUB_TOKEN), false);
      assert.ok(json.includes('[REDACTED'));
    });

    it('apiResponse.error scrubs secrets from error message and details', () => {
      let sentPayload = null;
      let sentStatus = null;
      const res = {
        req: { id: 'req_test_02' },
        status(code) {
          sentStatus = code;
          return this;
        },
        json(data) {
          sentPayload = data;
          return this;
        }
      };

      apiResponse.error(res, {
        code: 'AUTH_FAILED',
        message: `Failed authentication using ${FAKE_BEARER_TOKEN}`,
        details: { attemptedUri: FAKE_MONGO_URI }
      }, 401);

      assert.equal(sentStatus, 401);
      assert.equal(sentPayload.success, false);
      const json = JSON.stringify(sentPayload);
      assert.equal(json.includes(FAKE_BEARER_TOKEN), false);
      assert.equal(json.includes('fakeSecretPassword999'), false);
      assert.ok(json.includes('[REDACTED'));
    });

    it('errorHandler middleware intercepts errors and redacts logs and client responses', () => {
      const err = new Error(`Connection timeout on ${FAKE_POSTGRES_URI} with password: ${FAKE_PASSWORD}`);
      err.statusCode = 400;
      err.details = [{ secretParam: FAKE_AWS_KEY }];

      const req = {
        id: 'req_err_01',
        method: 'POST',
        url: `/api/scans?key=${FAKE_GOOGLE_KEY}`,
        originalUrl: `/api/scans?key=${FAKE_GOOGLE_KEY}`
      };

      let sentPayload = null;
      let sentStatus = null;
      const res = {
        req,
        headersSent: false,
        status(code) {
          sentStatus = code;
          return this;
        },
        json(data) {
          sentPayload = data;
          return this;
        }
      };

      errorHandler(err, req, res, () => {});

      // Verify client response is sanitized
      assert.equal(sentStatus, 400);
      const resJson = JSON.stringify(sentPayload);
      assert.equal(resJson.includes(FAKE_PASSWORD), false);
      assert.equal(resJson.includes('fakePostgresPassword888'), false);
      assert.equal(resJson.includes(FAKE_AWS_KEY), false);

      // Verify server log is sanitized
      assert.ok(capturedLogs.length >= 1);
      const logText = capturedLogs.join(' ');
      assert.equal(logText.includes(FAKE_PASSWORD), false);
      assert.equal(logText.includes(FAKE_GOOGLE_KEY), false);
      assert.ok(logText.includes('[REDACTED'));
    });
  });

  // --------------------------------------------------------------------------
  // 6. AI Prompt & Context Boundary
  // --------------------------------------------------------------------------
  describe('6. AI Request Context & Prompt Boundary', () => {
    it('redacts secrets from finding evidence and messages before prompt assembly', () => {
      const findingWithSecrets = {
        id: 'find_sec_001',
        title: `Vulnerability with token=${FAKE_GITHUB_TOKEN}`,
        message: `Database credentials exposed in connection: ${FAKE_MONGO_URI}`,
        category: 'HARDCODED_SECRET',
        severity: 'CRITICAL',
        filePath: 'src/config/db.js',
        startLine: 10,
        endLine: 12,
        evidence: `const db = connect("${FAKE_POSTGRES_URI}");\nconst apiKey = "${FAKE_GOOGLE_KEY}";`
      };

      const codeContext = [
        `const awsKey = "${FAKE_AWS_KEY}";`,
        `const password = "${FAKE_PASSWORD}";`,
        `const auth = "${FAKE_BEARER_TOKEN}";`
      ].join('\n');

      const prompt = buildInvestigationPrompt(findingWithSecrets, codeContext);

      // Assert userPrompt and systemInstruction contain no test secrets
      assert.equal(prompt.userPrompt.includes(FAKE_GITHUB_TOKEN), false);
      assert.equal(prompt.userPrompt.includes('fakeSecretPassword999'), false);
      assert.equal(prompt.userPrompt.includes('fakePostgresPassword888'), false);
      assert.equal(prompt.userPrompt.includes(FAKE_GOOGLE_KEY), false);
      assert.equal(prompt.userPrompt.includes(FAKE_AWS_KEY), false);
      assert.equal(prompt.userPrompt.includes(FAKE_PASSWORD), false);
      assert.equal(prompt.userPrompt.includes('fakeBearerTokenPayload'), false);

      // Verify redaction markers are present
      assert.ok(prompt.userPrompt.includes('[REDACTED_AWS_KEY]'));
      assert.ok(prompt.userPrompt.includes('[REDACTED_SECRET]'));
      assert.ok(prompt.userPrompt.includes('[REDACTED_BEARER_TOKEN]'));
    });

    it('redacts secrets in AI patch proposal prompts', () => {
      const finding = {
        id: 'find_patch_sec_001',
        title: 'Hardcoded credentials in auth module',
        message: `Hardcoded token: ${FAKE_GITHUB_TOKEN}`,
        category: 'HARDCODED_SECRET',
        severity: 'HIGH',
        filePath: 'src/auth.js',
        startLine: 5,
        endLine: 7,
        evidence: `const key = "${FAKE_AWS_KEY}";`
      };

      const codeContext = `const secret = "${FAKE_PASSWORD}";\nconst uri = "${FAKE_MONGO_URI}";`;
      const prompt = buildPatchProposalPrompt(finding, codeContext);

      assert.equal(prompt.userPrompt.includes(FAKE_GITHUB_TOKEN), false);
      assert.equal(prompt.userPrompt.includes(FAKE_AWS_KEY), false);
      assert.equal(prompt.userPrompt.includes(FAKE_PASSWORD), false);
      assert.equal(prompt.userPrompt.includes('fakeSecretPassword999'), false);
    });
  });

  // --------------------------------------------------------------------------
  // 7. Source File Preservation Invariant
  // --------------------------------------------------------------------------
  describe('7. Source File Preservation Invariant', () => {
    let tempDir;

    before(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex-preserve-test-'));
    });

    after(() => {
      if (tempDir && fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('does not modify original disk files during source excerpt redaction', () => {
      const originalFileContent = [
        '// Config file with secrets',
        `const awsKey = "${FAKE_AWS_KEY}";`,
        `const dbPass = "${FAKE_PASSWORD}";`,
        'module.exports = { awsKey, dbPass };'
      ].join('\n');

      const testFilePath = path.join(tempDir, 'config.js');
      fs.writeFileSync(testFilePath, originalFileContent, 'utf8');

      // Call getFileExcerpt which redacts secrets for AI/context
      const excerpt = getFileExcerpt(tempDir, 'config.js', 1, 4);

      // Verify excerpt returned to caller is redacted
      assert.ok(excerpt.isRedacted);
      assert.equal(excerpt.rawExcerpt.includes(FAKE_AWS_KEY), false);
      assert.equal(excerpt.rawExcerpt.includes(FAKE_PASSWORD), false);

      // Verify original file on disk remains exactly untouched!
      const diskContent = fs.readFileSync(testFilePath, 'utf8');
      assert.equal(diskContent, originalFileContent);
      assert.ok(diskContent.includes(FAKE_AWS_KEY));
      assert.ok(diskContent.includes(FAKE_PASSWORD));
    });
  });
});
