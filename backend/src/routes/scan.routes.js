const express = require('express');
const router = express.Router();
const scannerService = require('../services/scanner.service');

// GET /api/scans - List all scans
router.get('/', (req, res) => {
  const scans = scannerService.listScans();
  res.json({ success: true, data: scans });
});

// POST /api/scans - Initiate a scan
router.post('/', async (req, res) => {
  try {
    const { repositoryId, repositoryPath, name } = req.body;
    const scan = await scannerService.createScan({ repositoryId, repositoryPath, name });
    res.status(201).json({ success: true, data: scan });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/scans/:id - Get specific scan details
router.get('/:id', (req, res) => {
  const scan = scannerService.getScan(req.params.id);
  if (!scan) {
    return res.status(404).json({ success: false, error: 'Scan not found.' });
  }
  res.json({ success: true, data: scan });
});

// GET /api/scans/:id/findings - Get findings for specific scan
router.get('/:id/findings', (req, res) => {
  const scan = scannerService.getScan(req.params.id);
  if (!scan) {
    return res.status(404).json({ success: false, error: 'Scan not found.' });
  }
  const findings = scannerService.getFindings(req.params.id);
  res.json({ success: true, data: findings });
});

// DELETE /api/scans/:id - Delete a scan
router.delete('/:id', (req, res) => {
  const deleted = scannerService.deleteScan(req.params.id);
  if (!deleted) {
    return res.status(404).json({ success: false, error: 'Scan not found.' });
  }
  res.json({ success: true, message: 'Scan deleted successfully.' });
});

module.exports = router;

