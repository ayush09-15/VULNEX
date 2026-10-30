const express = require('express');
const router = express.Router();
const crypto = require('crypto');

// In-memory repositories store
const repositoriesStore = new Map();

// Sample initial repository
const defaultRepoId = 'repo-default';
repositoriesStore.set(defaultRepoId, {
  id: defaultRepoId,
  name: 'VULNEX Sample Repository',
  url: 'https://github.com/vulnex/sample-repo',
  path: './',
  branch: 'main',
  status: 'ACTIVE',
  createdAt: new Date().toISOString()
});

// GET /api/repositories - List all repositories
router.get('/', (req, res) => {
  const repositories = Array.from(repositoriesStore.values());
  res.json({ success: true, data: repositories });
});

// POST /api/repositories - Register a repository
router.post('/', (req, res) => {
  const { name, url, path, branch = 'main' } = req.body;

  if (!name && !url && !path) {
    return res.status(400).json({
      success: false,
      error: 'Repository name, url, or path is required.'
    });
  }

  const id = `repo-${crypto.randomBytes(4).toString('hex')}`;
  const newRepo = {
    id,
    name: name || (url ? url.split('/').pop().replace('.git', '') : 'Local Repository'),
    url: url || null,
    path: path || './',
    branch,
    status: 'ACTIVE',
    createdAt: new Date().toISOString()
  };

  repositoriesStore.set(id, newRepo);
  res.status(201).json({ success: true, data: newRepo });
});

// GET /api/repositories/:id - Get repository details
router.get('/:id', (req, res) => {
  const repo = repositoriesStore.get(req.params.id);
  if (!repo) {
    return res.status(404).json({ success: false, error: 'Repository not found.' });
  }
  res.json({ success: true, data: repo });
});

// DELETE /api/repositories/:id - Remove repository
router.delete('/:id', (req, res) => {
  const exists = repositoriesStore.has(req.params.id);
  if (!exists) {
    return res.status(404).json({ success: false, error: 'Repository not found.' });
  }
  repositoriesStore.delete(req.params.id);
  res.json({ success: true, message: 'Repository removed successfully.' });
});

module.exports = router;

