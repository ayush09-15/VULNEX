const express = require('express');
const router = express.Router();
const apiResponse = require('../utils/apiResponse');
const repositoryService = require('../services/repository.service');

/**
 * GET /api/repositories
 * Lists all registered repositories with optional pagination
 */
router.get('/', (req, res) => {
  try {
    const { page, limit } = req.query;
    const result = repositoryService.listRepositories({ page, limit });
    return apiResponse.success(res, result.items, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: err.code || 'INTERNAL_SERVER_ERROR',
      message: err.message
    }, 500);
  }
});

/**
 * POST /api/repositories
 * Registers a new repository intake (GitHub URL or ZIP upload)
 */
router.post('/', (req, res) => {
  try {
    const { sourceType, displayName, sourceUrl, defaultRef, zipBase64 } = req.body;

    if (!sourceType) {
      return apiResponse.error(res, {
        code: 'INVALID_INPUT',
        message: 'Missing required field: "sourceType" (GITHUB | ZIP_UPLOAD).'
      }, 400);
    }

    if (sourceType === 'ZIP_UPLOAD' && zipBase64) {
      const zipBuffer = Buffer.from(zipBase64, 'base64');
      const repo = repositoryService.ingestZipArchive(zipBuffer, {
        displayName,
        defaultRef
      });
      return apiResponse.success(res, repo, 201);
    }

    const repo = repositoryService.registerRepository({
      sourceType,
      displayName,
      sourceUrl,
      defaultRef
    });

    return apiResponse.success(res, repo, 201);
  } catch (err) {
    const clientErrorCodes = [
      'INVALID_URL',
      'INVALID_INPUT',
      'UNSUPPORTED_ARCHIVE',
      'FILE_TOO_LARGE',
      'RESOURCE_LIMIT_EXCEEDED'
    ];
    const statusCode = clientErrorCodes.includes(err.code) ? 400 : 500;
    return apiResponse.error(res, {
      code: err.code || 'BAD_REQUEST',
      message: err.message
    }, statusCode);
  }
});

/**
 * GET /api/repositories/:id
 * Retrieves repository metadata and default ref by ID
 */
router.get('/:id', (req, res) => {
  try {
    const repo = repositoryService.getRepositoryById(req.params.id);
    if (!repo) {
      return apiResponse.error(res, {
        code: 'RESOURCE_NOT_FOUND',
        message: `Repository with ID "${req.params.id}" not found.`
      }, 404);
    }

    return apiResponse.success(res, repo, 200);
  } catch (err) {
    return apiResponse.error(res, {
      code: err.code || 'INTERNAL_SERVER_ERROR',
      message: err.message
    }, 500);
  }
});

module.exports = router;
