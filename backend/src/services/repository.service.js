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

// Default fixture repository & sample repository
const defaultFixtureId = 'repo_fixture_01';
const sampleJuiceShopId = 'repo_01JAZZ80001';
const defaultFixturePath = path.resolve(__dirname, '../../../fixtures');
const resolvedFixtureWorkspace = fs.existsSync(defaultFixturePath) ? defaultFixturePath : './fixtures';

function seedDefaultRepositories() {

  repositoriesStore.set(defaultFixtureId, {
      id: defaultFixtureId,
      sourceType: 'LOCAL_FIXTURE',
      displayName: 'intentionally-vulnerable-node-app',
      sanitizedSourceUrl: 'fixtures/intentionally-vulnerable-node-app',
      defaultRef: 'main',
      createdAt: '2026-10-31T03:00:00.000Z',
      ownerId: null,
      workspacePath: resolvedFixtureWorkspace
    });

  repositoriesStore.set(sampleJuiceShopId, {
      id: sampleJuiceShopId,
      sourceType: 'GITHUB',
      displayName: 'juice-shop-sample',
      sanitizedSourceUrl: 'https://github.com/juice-shop/juice-shop',
      defaultRef: 'main',
      createdAt: '2026-10-31T03:00:00.000Z',
      ownerId: null,
      workspacePath: resolvedFixtureWorkspace
    });
  }

seedDefaultRepositories();

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
function registerRepository({ sourceType, displayName, sourceUrl, defaultRef = 'main', ownerId = null, workspacePath = null }) {
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
    ownerId: ownerId || null,
    workspacePath: workspacePath || null
  };

  repositoriesStore.set(id, record);
  return record;
}

/**
 * Ingest and validate a ZIP archive
 * @param {Buffer} zipBuffer
 * @param {Object} options
 * @returns {Object}
 */
function ingestZipArchive(zipBuffer, options = {}) {
  const result = zipService.ingestZipArchive(zipBuffer, options);
  repositoriesStore.set(result.repository.id, result.repository);
  return result.repository;
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
  seedDefaultRepositories();
}

const clearRepositories = _resetStore;


/**
 * Ensures a valid bounded workspace exists for the repository.
 * If the repository is GITHUB and not yet cloned, clones it into a bounded workspace.
 *
 * @param {string} repositoryId
 * @param {string} [ref]
 * @returns {Promise<string>} Resolved workspace directory path
 */
async function ensureWorkspace(repositoryId, ref) {
  const repo = getRepositoryById(repositoryId);
  if (!repo) {
    const err = new Error(`Repository with ID "${repositoryId}" not found.`);
    err.code = 'RESOURCE_NOT_FOUND';
    err.statusCode = 404;
    throw err;
  }

  // 1. If workspacePath already exists on disk, reuse it
  if (repo.workspacePath && fs.existsSync(repo.workspacePath)) {
    return repo.workspacePath;
  }

  // 2. If it's a GITHUB source, clone into a dedicated bounded workspace directory
  if (repo.sourceType === 'GITHUB' && repo.sanitizedSourceUrl) {
    const workspaceRoot = config.workspaceRoot || path.resolve(__dirname, '../../../.workspaces');
    const targetDir = path.resolve(workspaceRoot, `ws_git_${repo.id}`);

    // If targetDir already exists and contains files
    if (fs.existsSync(targetDir)) {
      try {
        const files = fs.readdirSync(targetDir);
        if (files.length > 0) {
          repo.workspacePath = targetDir;
        repositoriesStore.set(repo.id, repo);
          return targetDir;
        }
      } catch (_) {}
      try {
        fs.rmSync(targetDir, { recursive: true, force: true });
      } catch (_) {}
    }

    fs.mkdirSync(path.dirname(targetDir), { recursive: true });

    const targetRef = ref || repo.defaultRef || 'main';
    let cloneSuccess = false;
    let lastError = null;

    try {
      const res = await processRunner.run('git', [
        'clone',
        '--depth', '1',
        '--single-branch',
        '--branch', targetRef,
        repo.sanitizedSourceUrl,
        targetDir
      ], { timeoutMs: 60000 });

      if (res.exitCode === 0) {
        cloneSuccess = true;
      } else {
        lastError = res.stderr || res.stdout;
      }
    } catch (e) {
      lastError = e.message;
    }

    // Fallback: If branch-specific clone failed, try default branch
    if (!cloneSuccess) {
      if (fs.existsSync(targetDir)) {
        try {
          fs.rmSync(targetDir, { recursive: true, force: true });
        } catch (_) {}
      }
      try {
        const fallbackRes = await processRunner.run('git', [
          'clone',
          '--depth', '1',
          repo.sanitizedSourceUrl,
          targetDir
        ], { timeoutMs: 60000 });

        if (fallbackRes.exitCode === 0) {
          cloneSuccess = true;
        } else {
          lastError = fallbackRes.stderr || fallbackRes.stdout;
        }
      } catch (e) {
        lastError = e.message;
      }
    }

    if (!cloneSuccess || !fs.existsSync(targetDir)) {
      const err = new Error(
        `Failed to clone GitHub repository from ${repo.sanitizedSourceUrl}. Please verify the repository URL is public and accessible.`
      );
      err.code = 'GIT_CLONE_FAILED';
      err.details = lastError;
      err.statusCode = 422;
      throw err;
    }

    repo.workspacePath = targetDir;
  repositoriesStore.set(repo.id, repo);
    return targetDir;
  }

  // 3. Fallback check for fixture
  if (repo.id === defaultFixtureId && fs.existsSync(resolvedFixtureWorkspace)) {
    repo.workspacePath = resolvedFixtureWorkspace;
  repositoriesStore.set(repo.id, repo);
    return resolvedFixtureWorkspace;
  }

  const err = new Error(`Cannot locate or provision workspace for repository "${repositoryId}".`);
  err.code = 'WORKSPACE_NOT_FOUND';
  err.statusCode = 404;
  throw err;
}

module.exports = {
  ensureWorkspace,
  validateGitHubUrl,
  registerRepository,
  ingestZipArchive,
  getRepositoryById,
  listRepositories,
  deleteRepository,
  _resetStore,
  clearRepositories,
  scanWorkspace: inventoryService.scanWorkspace,
  getFileExcerpt: inventoryService.getFileExcerpt
};


