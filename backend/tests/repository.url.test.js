const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const app = require('../src/app');
const { validateGitHubUrl, registerRepository, _resetStore } = require('../src/services/repository.service');

// Helper for testing Express app endpoints without external deps
function makeRequest(server, { method = 'GET', path = '/', body = null, headers = {} }) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const reqHeaders = { ...headers };
    if (payload) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = http.request(
      {
        path,
        method,
        headers: reqHeaders,
        socketPath: undefined,
        createConnection: (options) => {
          return server.listen ? null : undefined;
        }
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(data);
          } catch {
            json = data;
          }
          resolve({ status: res.statusCode, headers: res.headers, body: json });
        });
      }
    );

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

test('GitHub Repository URL Validation & SSRF Guard (Commit 07)', async (t) => {
  t.beforeEach(() => {
    _resetStore();
  });

  await t.test('accepts valid canonical public GitHub repository URLs', () => {
    const validCases = [
      'https://github.com/juice-shop/juice-shop',
      'https://github.com/facebook/react',
      'https://github.com/expressjs/express.git',
      'https://www.github.com/owner-name/repo_name.js',
      'https://github.com/user.name/project-123'
    ];

    for (const url of validCases) {
      const result = validateGitHubUrl(url);
      assert.equal(result.isValid, true);
      assert.ok(result.sanitizedUrl.startsWith('https://github.com/'));
      assert.ok(!result.sanitizedUrl.endsWith('.git'), 'Must strip trailing .git');
    }
  });

  await t.test('rejects non-HTTPS protocols (http, ssh, git, file, ftp)', () => {
    const invalidProtocols = [
      'http://github.com/org/repo',
      'git@github.com:org/repo.git',
      'ssh://git@github.com/org/repo',
      'file:///etc/passwd',
      'ftp://github.com/org/repo'
    ];

    for (const url of invalidProtocols) {
      assert.throws(
        () => validateGitHubUrl(url),
        (err) => err.code === 'INVALID_URL'
      );
    }
  });

  await t.test('rejects embedded user credentials or tokens', () => {
    const credCases = [
      'https://token@github.com/org/repo',
      'https://user:password@github.com/org/repo',
      'https://ghp_secrettoken@github.com/org/repo'
    ];

    for (const url of credCases) {
      assert.throws(
        () => validateGitHubUrl(url),
        (err) => err.code === 'INVALID_URL' && err.message.includes('credentials')
      );
    }
  });

  await t.test('rejects non-standard ports to prevent port-scanning or redirect smuggling', () => {
    const portCases = [
      'https://github.com:8443/org/repo',
      'https://github.com:8080/org/repo',
      'https://github.com:22/org/repo'
    ];

    for (const url of portCases) {
      assert.throws(
        () => validateGitHubUrl(url),
        (err) => err.code === 'INVALID_URL' && err.message.includes('Non-standard port')
      );
    }
  });

  await t.test('rejects non-GitHub domains and subdomain spoofing attempts', () => {
    const invalidHosts = [
      'https://gitlab.com/org/repo',
      'https://bitbucket.org/org/repo',
      'https://evil-github.com/org/repo',
      'https://github.com.attacker.com/org/repo',
      'https://attacker.com/github.com/org/repo'
    ];

    for (const url of invalidHosts) {
      assert.throws(
        () => validateGitHubUrl(url),
        (err) => err.code === 'INVALID_URL' && err.message.includes('not a supported Git host')
      );
    }
  });

  await t.test('mitigates SSRF by rejecting loopback and private IP addresses', () => {
    const privateTargets = [
      'https://localhost/org/repo',
      'https://127.0.0.1/org/repo',
      'https://0.0.0.0/org/repo',
      'https://10.0.0.1/org/repo',
      'https://192.168.1.1/org/repo',
      'https://172.16.0.1/org/repo',
      'https://169.254.169.254/latest/meta-data'
    ];

    for (const url of privateTargets) {
      assert.throws(
        () => validateGitHubUrl(url),
        (err) => err.code === 'INVALID_URL'
      );
    }
  });

  await t.test('rejects directory traversal and malformed path structures', () => {
    const badPaths = [
      'https://github.com/',
      'https://github.com/only-owner',
      'https://github.com/org/repo/extra/path',
      'https://github.com/../repo',
      'https://github.com/org/..',
      'https://github.com/./repo'
    ];

    for (const url of badPaths) {
      assert.throws(
        () => validateGitHubUrl(url),
        (err) => err.code === 'INVALID_URL'
      );
    }
  });

  await t.test('registerRepository creates canonical entity for valid GitHub URL', () => {
    const record = registerRepository({
      sourceType: 'GITHUB',
      sourceUrl: 'https://github.com/juice-shop/juice-shop.git',
      defaultRef: 'main'
    });

    assert.ok(record.id.startsWith('repo_'));
    assert.equal(record.sourceType, 'GITHUB');
    assert.equal(record.displayName, 'juice-shop');
    assert.equal(record.sanitizedSourceUrl, 'https://github.com/juice-shop/juice-shop');
    assert.equal(record.defaultRef, 'main');
    assert.ok(record.createdAt);
  });
});
