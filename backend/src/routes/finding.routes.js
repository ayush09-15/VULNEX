const express = require('express');
const router = express.Router();
const scannerService = require('../services/scanner.service');
const aiService = require('../services/ai.service');
const patchService = require('../services/patch.service');
const verificationService = require('../services/verification.service');

// GET /api/findings - List findings with optional filters
router.get('/', (req, res) => {
  const { scanId, severity, status } = req.query;
  let findings = scannerService.getAllFindings();

  if (scanId) {
    findings = findings.filter(f => f.scanId === scanId);
  }
  if (severity) {
    findings = findings.filter(f => f.severity.toUpperCase() === severity.toUpperCase());
  }
  if (status) {
    findings = findings.filter(f => f.status.toUpperCase() === status.toUpperCase());
  }

  res.json({ success: true, count: findings.length, data: findings });
});

// GET /api/findings/:id - Get finding by ID
router.get('/:id', (req, res) => {
  const finding = scannerService.getFindingById(req.params.id);
  if (!finding) {
    return res.status(404).json({ success: false, error: 'Finding not found.' });
  }
  res.json({ success: true, data: finding });
});

// POST /api/findings/:id/analyze - Trigger AI root cause analysis
router.post('/:id/analyze', async (req, res) => {
  try {
    const finding = scannerService.getFindingById(req.params.id);
    if (!finding) {
      return res.status(404).json({ success: false, error: 'Finding not found.' });
    }

    const { codeContext } = req.body;
    const analysis = await aiService.analyzeVulnerability(finding, codeContext);

    // Update finding with analysis
    scannerService.updateFinding(req.params.id, { aiAnalysis: analysis });

    res.json({ success: true, data: analysis });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/findings/:id/generate-patch - Generate AI patch
router.post('/:id/generate-patch', async (req, res) => {
  try {
    const finding = scannerService.getFindingById(req.params.id);
    if (!finding) {
      return res.status(404).json({ success: false, error: 'Finding not found.' });
    }

    const { originalCode } = req.body;
    const patchResult = await aiService.generatePatch(finding, originalCode || finding.codeSnippet);

    const diff = patchService.createUnifiedDiff({
      filename: finding.file,
      originalContent: patchResult.originalCode,
      patchedContent: patchResult.patchedCode
    });

    const preview = patchService.previewPatch(patchResult.originalCode, patchResult.patchedCode);

    const responseData = {
      ...patchResult,
      diff,
      preview
    };

    scannerService.updateFinding(req.params.id, { proposedPatch: responseData });

    res.json({ success: true, data: responseData });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/findings/:id/verify-patch - Verify proposed patch
router.post('/:id/verify-patch', async (req, res) => {
  try {
    const finding = scannerService.getFindingById(req.params.id);
    if (!finding) {
      return res.status(404).json({ success: false, error: 'Finding not found.' });
    }

    const { patchedCode, originalCode } = req.body;
    const verificationReport = await verificationService.verifyPatch({
      finding,
      patchedCode: patchedCode || finding.proposedPatch?.patchedCode,
      originalCode: originalCode || finding.codeSnippet,
      filePath: finding.file
    });

    scannerService.updateFinding(req.params.id, {
      verification: verificationReport,
      status: verificationReport.isVerified ? 'VERIFIED' : 'FAILED_VERIFICATION'
    });

    res.json({ success: true, data: verificationReport });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/findings/:id/apply-patch - Apply patch to disk
router.post('/:id/apply-patch', async (req, res) => {
  try {
    const finding = scannerService.getFindingById(req.params.id);
    if (!finding) {
      return res.status(404).json({ success: false, error: 'Finding not found.' });
    }

    const patchedContent = req.body.patchedCode || finding.proposedPatch?.patchedCode;
    if (!patchedContent) {
      return res.status(400).json({ success: false, error: 'No patched code provided or proposed.' });
    }

    const result = await patchService.applyPatch({
      filePath: finding.file,
      patchedContent
    });

    scannerService.updateFinding(req.params.id, { status: 'RESOLVED', resolvedAt: new Date().toISOString() });

    res.json({ success: true, data: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/findings/:id/rollback - Rollback applied patch
router.post('/:id/rollback', async (req, res) => {
  try {
    const finding = scannerService.getFindingById(req.params.id);
    if (!finding) {
      return res.status(404).json({ success: false, error: 'Finding not found.' });
    }

    const result = await patchService.rollbackPatch({ filePath: finding.file });
    scannerService.updateFinding(req.params.id, { status: 'OPEN' });

    res.json({ success: true, data: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;

