const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { URL } = require('url');
const { isPrivateOrBlockedHost } = require('../utils/ssrfGuard');
const inventoryService = require('./inventory.service');
const zipService = require('./zip.service');
const processRunner = require('../utils/processRunner');
const config = require('../config/env');

/**
 * ============================================================================
 * VULNEX Repository Service
 * Coordinates repository intake records, GitHub URL validation, ZIP archives,
 * and bounded inventory scanning.
 * ============================================================================
 */

// In-memory repository persistence store
const repositoriesStore = new Map();

// Default fixture repository
const defaultFixtureId = 'repo_fixture_01';
const defaultFixturePath = path.resolve(__dirname, '../../../fixtures');
repositoriesStore.set(defaultFixtureId, {
  id: defaultFixtureId,
  sourceType: 'LOCAL_FIXTURE',
  displayName: 'intentionally-vulnerable-node-app',
  sanitizedSourceUrl: 'fixtures/intentionally-vulnerable-node-app',
  defaultRef: 'main',
  createdAt: '2026-10-31T03:00:00.000Z',
  ownerId: null,
  workspacePath: fs.existsSync(defaultFixturePath) ? defaultFixturePath : './fixtures'
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
    err.statusCode = 400;
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
    err.statusCode = 400;
    throw err;
  }

  if (parsedUrl.protocol !== 'https:') {
    const err = new Error(`Protocol "${parsedUrl.protocol}" is not supported. Only secure HTTPS URLs are permitted.`);
    err.code = 'INVALID_URL';
    err.statusCode = 400;
    throw err;
  }

  // 2. Reject embedded user credentials (e.g., https://user:pass@github.com)
  if (parsedUrl.username || parsedUrl.password) {
    const err = new Error('Embedding user credentials or authentication tokens in repository URLs is prohibited.');
    err.code = 'INVALID_URL';
    err.statusCode = 400;
    throw err;
  }

  // 3. Port check (only standard HTTPS port 443 allowed)
  if (parsedUrl.port && parsedUrl.port !== '443') {
    const err = new Error(`Non-standard port "${parsedUrl.port}" is not permitted for GitHub repository URLs.`);
    err.code = 'INVALID_URL';
    err.statusCode = 400;
    throw err;
  }

  // 4. Host verification & SSRF protection
  const hostname = parsedUrl.hostname.toLowerCase();

  // Prohibit local / loopback / private IP ranges or metadata endpoints
  if (isPrivateOrBlockedHost(hostname)) {
    const err = new Error('Prohibited IP or private host address detected. Access blocked by SSRF policy.');
    err.code = 'INVALID_URL';
    err.statusCode = 400;
    throw err;
  }

  // Strictly allow only verified GitHub host domains
  const allowedHosts = ['github.com', 'www.github.com'];
  if (!allowedHosts.includes(hostname)) {
    const err = new Error(`Host "${hostname}" is not a supported Git host. Only github.com is currently allowed.`);
    err.code = 'INVALID_URL';
    err.statusCode = 400;
    throw err;
  }

  // 5. Path extraction and validation: /:owner/:repo
  const pathParts = parsedUrl.pathname.split('/').filter(Boolean);

  if (pathParts.length !== 2) {
    const err = new Error('URL must follow the canonical path format "https://github.com/:owner/:repo".');
    err.code = 'INVALID_URL';
    err.statusCode = 400;
    throw err;
  }

  const [rawOwner, rawRepo] = pathParts;
  const gitIdentifierRegex = /^[a-zA-Z0-9_.-]{1,100}$/;

  if (!gitIdentifierRegex.test(rawOwner) || rawOwner === '.' || rawOwner === '..') {
    const err = new Error(`Invalid GitHub organization/user identifier: "${rawOwner}".`);
    err.code = 'INVALID_URL';
    err.statusCode = 400;
    throw err;
  }

  if (!gitIdentifierRegex.test(rawRepo) || rawRepo === '.' || rawRepo === '..') {
    const err = new Error(`Invalid GitHub repository identifier: "${rawRepo}".`);
    err.code = 'INVALID_URL';
    err.statusCode = 400;
    throw err;
  }

  // Strip trailing .git suffix if present
  const cleanRepo = rawRepo.endsWith('.git') ? rawRepo.slice(0, -4) : rawRepo;

  if (!cleanRepo || cleanRepo === '.' || cleanRepo === '..') {
    const err = new Error('Invalid repository identifier after stripping .git suffix.');
    err.code = 'INVALID_URL';
    err.statusCode = 400;
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
 * Register a new repository
 * 
 * @param {Object} params
 * @param {string} params.sourceType - 'GITHUB' | 'ZIP_UPLOAD'
 * @param {string} [params.displayName]
 * @param {string} [params.sourceUrl]
 * @param {string} [params.defaultRef='main']
 * @param {string} [params.ownerId=null]
 * @returns {Object} Canonical Repository entity
 */
function registerRepository({ sourceType, displayName, sourceUrl, defaultRef = 'main', ownerId = null }) {
  if (!sourceType || !['GITHUB', 'ZIP_UPLOAD'].includes(sourceType)) {
    const err = new Error('Invalid sourceType. Must be either GITHUB or ZIP_UPLOAD.');
    err.code = 'INVALID_INPUT';
    err.statusCode = 400;
    throw err;
  }

  let sanitizedSourceUrl = null;
  let finalDisplayName = displayName?.trim() || null;

  if (sourceType === 'GITHUB') {
    if (!sourceUrl) {
      const err = new Error('sourceUrl is required when sourceType is GITHUB.');
      err.code = 'INVALID_INPUT';
      err.statusCode = 400;
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

  finalDisplayName = finalDisplayName ? finalDisplayName.replace(/[/\\~]/g, '').trim() : 'unnamed-repo';

  const id = `repo_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const record = {
    id,
    sourceType,
    displayName: finalDisplayName,
    sanitizedSourceUrl,
    defaultRef: defaultRef || 'main',
    createdAt: new Date().toISOString(),
    ownerId: ownerId || null
  };

  repositoriesStore.set(id, record);
  return record;
}

/**
 * Ingest and validate a ZIP archive into an isolated workspace directory
 * @param {Buffer} zipBuffer
 * @param {Object} options
 * @returns {Object}
 */
function ingestZipArchive(zipBuffer, options = {}) {
  const repoId = `repo_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const targetWorkspace = path.resolve(config.workspaceRoot || path.resolve(__dirname, '../../../.workspaces'), repoId);
  fs.mkdirSync(targetWorkspace, { recursive: true });

  zipService.extractZipArchive(zipBuffer, targetWorkspace, options);

  const displayName = (options.displayName || `upload-${Date.now()}`).replace(/[/\\~]/g, '').trim() || 'unnamed-repo';
  const record = {
    id: repoId,
    sourceType: 'ZIP_UPLOAD',
    displayName,
    sanitizedSourceUrl: null,
    defaultRef: options.defaultRef || 'main',
    createdAt: new Date().toISOString(),
    ownerId: options.ownerId || null,
    workspacePath: targetWorkspace
  };

  repositoriesStore.set(repoId, record);
  return record;
}

/**
 * Prepares an isolated filesystem workspace for a repository
 * - LOCAL_FIXTURE: Points to verified fixture directory
 * - ZIP_UPLOAD: Points to extracted workspace
 * - GITHUB: Clones via git CLI into .workspaces/<repositoryId>
 * 
 * @param {string} repositoryId
 * @param {Object} [options={}]
 * @param {string} [options.ref]
 * @returns {Promise<string>} Absolute path to workspace directory
 */
async function prepareWorkspace(repositoryId, options = {}) {
  let repo = getRepositoryById(repositoryId);

  // If repo is the default fixture or not found but matches default fixture ID
  if (!repo && repositoryId === defaultFixtureId) {
    repo = {
      id: defaultFixtureId,
      sourceType: 'LOCAL_FIXTURE',
      displayName: 'intentionally-vulnerable-node-app',
      sanitizedSourceUrl: 'fixtures/intentionally-vulnerable-node-app',
      defaultRef: 'main',
      createdAt: '2026-10-31T03:00:00.000Z',
      ownerId: null,
      workspacePath: fs.existsSync(defaultFixturePath) ? defaultFixturePath : './fixtures'
    };
    repositoriesStore.set(defaultFixtureId, repo);
  }

  if (!repo) {
    const err = new Error(`Repository with ID "${repositoryId}" not found.`);
    err.code = 'RESOURCE_NOT_FOUND';
    err.statusCode = 404;
    throw err;
  }

  // Handle LOCAL_FIXTURE
  if (repo.sourceType === 'LOCAL_FIXTURE') {
    const fixturePath = repo.workspacePath && fs.existsSync(repo.workspacePath)
      ? repo.workspacePath
      : (fs.existsSync(defaultFixturePath) ? defaultFixturePath : path.resolve(__dirname, '../../../fixtures'));
    
    if (!fs.existsSync(fixturePath)) {
      const err = new Error(`Fixture directory not found at: ${fixturePath}`);
      err.code = 'WORKSPACE_ERROR';
      throw err;
    }
    repo.workspacePath = fixturePath;
    return fixturePath;
  }

  // Handle ZIP_UPLOAD
  if (repo.sourceType === 'ZIP_UPLOAD') {
    if (repo.workspacePath && fs.existsSync(repo.workspacePath)) {
      return repo.workspacePath;
    }
    const err = new Error(`Workspace for uploaded archive "${repo.displayName}" does not exist on disk.`);
    err.code = 'WORKSPACE_ERROR';
    throw err;
  }

  // Handle GITHUB
  if (repo.sourceType === 'GITHUB') {
    // If workspace already exists and has files, reuse it
    if (repo.workspacePath && fs.existsSync(repo.workspacePath)) {
      try {
        const entries = fs.readdirSync(repo.workspacePath);
        if (entries.length > 0) {
          return repo.workspacePath;
        }
      } catch (_) {}
    }

    const workspacesBase = config.workspaceRoot || path.resolve(__dirname, '../../../.workspaces');
    const targetWorkspace = path.resolve(workspacesBase, repo.id);
    fs.mkdirSync(path.dirname(targetWorkspace), { recursive: true });

    // If directory exists and is non-empty, use it
    if (fs.existsSync(targetWorkspace)) {
      try {
        const entries = fs.readdirSync(targetWorkspace);
        if (entries.length > 0) {
          repo.workspacePath = targetWorkspace;
          repositoriesStore.set(repo.id, repo);
          return targetWorkspace;
        }
      } catch (_) {}
    }

    const targetRef = options.ref || repo.defaultRef || 'main';

    // 1. Attempt shallow clone with specific ref
    let cloneResult = await processRunner.run('git', [
      'clone',
      '--depth', '1',
      '--single-branch',
      '--branch', targetRef,
      repo.sanitizedSourceUrl,
      targetWorkspace
    ], { timeoutMs: 60000 });

    // 2. If branch-specific clone failed (e.g. default branch is master, not main), clone default branch
    if (cloneResult.exitCode !== 0) {
      cloneResult = await processRunner.run('git', [
        'clone',
        '--depth', '1',
        repo.sanitizedSourceUrl,
        targetWorkspace
      ], { timeoutMs: 60000 });
    }

    if (cloneResult.exitCode !== 0) {
      if (fs.existsSync(targetWorkspace)) {
        try { fs.rmSync(targetWorkspace, { recursive: true, force: true }); } catch (_) {}
      }
      const rawError = (cloneResult.stderr || cloneResult.stdout || 'git clone process exited with non-zero code').trim();
      const err = new Error(`Failed to clone remote repository from "${repo.sanitizedSourceUrl}": ${rawError}`);
      err.code = 'WORKSPACE_ERROR';
      throw err;
    }

    repo.workspacePath = targetWorkspace;
    repositoriesStore.set(repo.id, repo);
    return targetWorkspace;
  }

  const err = new Error(`Unsupported repository sourceType: "${repo.sourceType}"`);
  err.code = 'WORKSPACE_ERROR';
  throw err;
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
 * Supports both listRepositories() and listRepositories({ page, limit })
 * @param {Object} [options={}]
 * @returns {{ items: Array, total: number, page: number, limit: number, some: Function }}
 */
function listRepositories(options = {}) {
  const p = Math.max(1, parseInt(options.page, 10) || 1);
  const l = Math.max(1, Math.min(100, parseInt(options.limit, 10) || (options.limit === undefined ? 20 : 20)));

  const all = Array.from(repositoriesStore.values());
  const startIndex = (p - 1) * l;
  const items = all.slice(startIndex, startIndex + l);

  const result = {
    items,
    total: all.length,
    page: p,
    limit: l,
    [Symbol.iterator]: function* () { yield* items; },
    some: (fn) => items.some(fn),
    filter: (fn) => items.filter(fn),
    map: (fn) => items.map(fn),
    forEach: (fn) => items.forEach(fn),
    length: items.length
  };

  return result;
}

/**
 * Remove a registered repository
 * @param {string} id
 * @returns {boolean}
 */
function deleteRepository(id) {
  return repositoriesStore.delete(id);
}

/**
 * Reset store (testing helper)
 */
function _resetStore() {
  repositoriesStore.clear();
  repositoriesStore.set(defaultFixtureId, {
    id: defaultFixtureId,
    sourceType: 'LOCAL_FIXTURE',
    displayName: 'intentionally-vulnerable-node-app',
    sanitizedSourceUrl: null,
    defaultRef: 'main',
    createdAt: '2026-10-31T03:00:00.000Z',
    ownerId: null,
    workspacePath: fs.existsSync(defaultFixturePath) ? defaultFixturePath : './fixtures'
  });
}

const clearRepositories = _resetStore;

module.exports = {
  validateGitHubUrl,
  registerRepository,
  ingestZipArchive,
  prepareWorkspace,
  getRepositoryById,
  listRepositories,
  deleteRepository,
  _resetStore,
  clearRepositories,
  scanWorkspace: inventoryService.scanWorkspace,
  getFileExcerpt: inventoryService.getFileExcerpt
};
