const crypto = require('crypto');
const path = require('path');
const { URL } = require('url');
const config = require('../config/env');
const { validateZipArchive, extractZipArchive } = require('./zip.service');

/**
 * In-memory repository persistence store
 * In production, this sits behind a repository interface (SQLite/MongoDB)
 */
const repositoriesStore = new Map();

// Initialize default controlled fixture repository
const defaultFixtureId = 'repo_fixture_01';
repositoriesStore.set(defaultFixtureId, {
  id: defaultFixtureId,
  sourceType: 'LOCAL_FIXTURE',
  displayName: 'intentionally-vulnerable-node-app',
  sanitizedSourceUrl: null,
  defaultRef: 'main',
  workspacePath: path.resolve(__dirname, '../../../fixtures/intentionally-vulnerable-node-app'),
  createdAt: '2026-10-31T03:00:00.000Z',
  ownerId: null
});

/**
 * Validates and sanitizes a GitHub repository URL
 * Mitigates SSRF, credential leakage, open redirects, and protocol hijacking.
 * 
 * @param {string} rawUrl - Untrusted input URL
 * @returns {{ isValid: boolean, sanitizedUrl: string, owner: string, repo: string }}
 * @throws {Error} Machine-readable error code on failure
 */
function validateGitHubUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    const err = new Error('Repository URL is required and must be a string.');
    err.code = 'INVALID_URL';
    throw err;
  }

  const trimmed = rawUrl.trim();

  // 1. Enforce strict HTTPS scheme
  let parsedUrl;
  try {
    parsedUrl = new URL(trimmed);
  } catch {
    const err = new Error('Malformed URL format.');
    err.code = 'INVALID_URL';
    throw err;
  }

  if (parsedUrl.protocol !== 'https:') {
    const err = new Error(`Protocol "${parsedUrl.protocol}" is not supported. Only secure HTTPS URLs are permitted.`);
    err.code = 'INVALID_URL';
    throw err;
  }

  // 2. Reject embedded user credentials (e.g., https://user:pass@github.com)
  if (parsedUrl.username || parsedUrl.password) {
    const err = new Error('Embedding user credentials or authentication tokens in repository URLs is prohibited.');
    err.code = 'INVALID_URL';
    throw err;
  }

  // 3. Port check (only standard HTTPS port 443 allowed)
  if (parsedUrl.port && parsedUrl.port !== '443') {
    const err = new Error(`Non-standard port "${parsedUrl.port}" is not permitted for GitHub repository URLs.`);
    err.code = 'INVALID_URL';
    throw err;
  }

  // 4. Host verification & SSRF protection
  const hostname = parsedUrl.hostname.toLowerCase();

  // Prohibit local / loopback / private IP ranges
  const privateIpPatterns = [
    /^localhost$/i,
    /^127\./,
    /^0\./,
    /^::1$/,
    /^10\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^169\.254\./ // AWS / Cloud metadata address
  ];

  for (const pattern of privateIpPatterns) {
    if (pattern.test(hostname)) {
      const err = new Error('Prohibited IP or private host address detected. Access blocked by SSRF policy.');
      err.code = 'INVALID_URL';
      throw err;
    }
  }

  // Strictly allow only verified GitHub host domains
  const allowedHosts = ['github.com', 'www.github.com'];
  if (!allowedHosts.includes(hostname)) {
    const err = new Error(`Host "${hostname}" is not a supported Git host. Only github.com is currently allowed.`);
    err.code = 'INVALID_URL';
    throw err;
  }

  // 5. Path extraction and validation: /:owner/:repo
  const pathParts = parsedUrl.pathname.split('/').filter(Boolean);

  if (pathParts.length !== 2) {
    const err = new Error('URL must follow the canonical path format "https://github.com/:owner/:repo".');
    err.code = 'INVALID_URL';
    throw err;
  }

  const [rawOwner, rawRepo] = pathParts;

  // GitHub username and repo naming rules
  const gitIdentifierRegex = /^[a-zA-Z0-9_.-]{1,100}$/;

  if (!gitIdentifierRegex.test(rawOwner) || rawOwner === '.' || rawOwner === '..') {
    const err = new Error(`Invalid GitHub organization/user identifier: "${rawOwner}".`);
    err.code = 'INVALID_URL';
    throw err;
  }

  if (!gitIdentifierRegex.test(rawRepo) || rawRepo === '.' || rawRepo === '..') {
    const err = new Error(`Invalid GitHub repository identifier: "${rawRepo}".`);
    err.code = 'INVALID_URL';
    throw err;
  }

  // Strip trailing .git suffix if present
  const cleanRepo = rawRepo.endsWith('.git') ? rawRepo.slice(0, -4) : rawRepo;

  if (!cleanRepo || cleanRepo === '.' || cleanRepo === '..') {
    const err = new Error('Invalid repository identifier after stripping .git suffix.');
    err.code = 'INVALID_URL';
    throw err;
  }

  const sanitizedUrl = `https://github.com/${rawOwner}/${cleanRepo}`;

  return {
    isValid: true,
    sanitizedUrl,
    owner: rawOwner,
    repo: cleanRepo
  };
}

/**
 * Register a new repository intake (URL or metadata)
 * 
 * @param {Object} params
 * @param {string} params.sourceType - 'GITHUB' | 'ZIP_UPLOAD'
 * @param {string} [params.displayName]
 * @param {string} [params.sourceUrl]
 * @param {string} [params.defaultRef='main']
 * @param {string} [params.ownerId=null]
 * @param {string} [params.workspacePath=null]
 * @returns {Object} Canonical Repository entity
 */
function registerRepository({ sourceType, displayName, sourceUrl, defaultRef = 'main', ownerId = null, workspacePath = null }) {
  if (!sourceType || !['GITHUB', 'ZIP_UPLOAD', 'LOCAL_FIXTURE'].includes(sourceType)) {
    const err = new Error('Invalid sourceType. Must be GITHUB or ZIP_UPLOAD.');
    err.code = 'INVALID_INPUT';
    throw err;
  }

  let sanitizedSourceUrl = null;
  let finalDisplayName = displayName?.trim() || null;

  if (sourceType === 'GITHUB') {
    if (!sourceUrl) {
      const err = new Error('sourceUrl is required when sourceType is GITHUB.');
      err.code = 'INVALID_INPUT';
      throw err;
    }

    const validated = validateGitHubUrl(sourceUrl);
    sanitizedSourceUrl = validated.sanitizedUrl;
    if (!finalDisplayName) {
      finalDisplayName = validated.repo;
    }
  } else if (sourceType === 'ZIP_UPLOAD') {
    if (!finalDisplayName) {
      finalDisplayName = `upload-${Date.now()}`;
    }
  }

  finalDisplayName = finalDisplayName.replace(/[/\\~]/g, '').trim() || 'unnamed-repo';

  const id = `repo_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const record = {
    id,
    sourceType,
    displayName: finalDisplayName,
    sanitizedSourceUrl,
    defaultRef: defaultRef || 'main',
    workspacePath: workspacePath || null,
    createdAt: new Date().toISOString(),
    ownerId: ownerId || null
  };

  repositoriesStore.set(id, record);
  return record;
}

/**
 * Ingest and extract a ZIP archive into an isolated scan workspace
 * 
 * @param {Buffer} zipBuffer - Binary zip payload
 * @param {Object} [params]
 * @param {string} [params.displayName]
 * @param {string} [params.defaultRef='main']
 * @returns {Object} Canonical Repository record with isolated workspace
 */
function ingestZipArchive(zipBuffer, { displayName, defaultRef = 'main' } = {}) {
  // Validate archive buffer safety
  validateZipArchive(zipBuffer);

  const workspaceId = `ws_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const workspacePath = path.resolve(config.workspaceRoot, workspaceId);

  // Safely extract into bounded disposable workspace
  extractZipArchive(zipBuffer, workspacePath);

  return registerRepository({
    sourceType: 'ZIP_UPLOAD',
    displayName: displayName || `archive-${workspaceId}`,
    defaultRef,
    workspacePath
  });
}

/**
 * Retrieve repository by ID
 * @param {string} id
 * @returns {Object|null}
 */
function getRepositoryById(id) {
  return repositoriesStore.get(id) || null;
}

/**
 * List repositories with optional pagination
 * @param {Object} options
 * @param {number} [options.page=1]
 * @param {number} [options.limit=20]
 * @returns {{ items: Array, total: number, page: number, limit: number }}
 */
function listRepositories({ page = 1, limit = 20 } = {}) {
  const p = Math.max(1, parseInt(page, 10) || 1);
  const l = Math.max(1, Math.min(100, parseInt(limit, 10) || 20));

  const all = Array.from(repositoriesStore.values());
  const startIndex = (p - 1) * l;
  const items = all.slice(startIndex, startIndex + l);

  return {
    items,
    total: all.length,
    page: p,
    limit: l
  };
}

/**
 * Clear repositories (used in testing environments)
 */
function _resetStore() {
  repositoriesStore.clear();
  repositoriesStore.set(defaultFixtureId, {
    id: defaultFixtureId,
    sourceType: 'LOCAL_FIXTURE',
    displayName: 'intentionally-vulnerable-node-app',
    sanitizedSourceUrl: null,
    defaultRef: 'main',
    workspacePath: path.resolve(__dirname, '../../../fixtures/intentionally-vulnerable-node-app'),
    createdAt: '2026-10-31T03:00:00.000Z',
    ownerId: null
  });
}

module.exports = {
  validateGitHubUrl,
  registerRepository,
  ingestZipArchive,
  getRepositoryById,
  listRepositories,
  _resetStore
};
