const crypto = require('crypto');
const inventoryService = require('./inventory.service');
const { validateRegisterRepository } = require('../validators/canonical.schema');

/**
 * ============================================================================
 * VULNEX Repository Service
 * Coordinates repository intake records, metadata, and bounded inventory scanning.
 * ============================================================================
 */

// Repository memory store (isolated behind service interface)
const repositoriesStore = new Map();

// Initialize default sample repository if store empty
const defaultRepoId = 'repo_default_vulnex';
repositoriesStore.set(defaultRepoId, {
  id: defaultRepoId,
  sourceType: 'GITHUB',
  displayName: 'VULNEX Sample Repository',
  sanitizedSourceUrl: 'https://github.com/vulnex/sample-repo',
  defaultRef: 'main',
  createdAt: new Date().toISOString()
});

/**
 * List all registered repositories
 * @returns {Array<Object>}
 */
function listRepositories() {
  return Array.from(repositoriesStore.values());
}

/**
 * Get repository by ID
 * @param {string} id
 * @returns {Object|null}
 */
function getRepositoryById(id) {
  return repositoriesStore.get(id) || null;
}

/**
 * Register a new repository intake
 * @param {Object} input
 * @returns {Object}
 */
function registerRepository(input) {
  const validation = validateRegisterRepository(input);
  if (!validation.success) {
    const err = new Error(validation.error.issues[0]?.message || 'Invalid repository registration input');
    err.code = 'INVALID_INPUT';
    err.statusCode = 400;
    err.details = validation.error.issues;
    throw err;
  }

  const validData = validation.data;
  const id = `repo_${crypto.randomBytes(6).toString('hex')}`;

  const repository = {
    id,
    sourceType: validData.sourceType,
    displayName: validData.displayName,
    sanitizedSourceUrl: validData.sourceUrl || null,
    defaultRef: validData.defaultRef || 'main',
    createdAt: new Date().toISOString()
  };

  repositoriesStore.set(id, repository);
  return repository;
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
 * Clear repositories (testing helper)
 */
function clearRepositories() {
  repositoriesStore.clear();
}

module.exports = {
  listRepositories,
  getRepositoryById,
  registerRepository,
  deleteRepository,
  clearRepositories,
  // Delegate bounded source inventory methods
  scanWorkspace: inventoryService.scanWorkspace,
  getFileExcerpt: inventoryService.getFileExcerpt
};
