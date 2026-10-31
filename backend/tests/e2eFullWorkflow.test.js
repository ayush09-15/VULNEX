const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');

const repositoryService = require('../src/services/repository.service');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const { investigationService } = require('../src/services/investigation.service');
const patchService = require('../src/services/patch.service');
const verificationService = require('../src/services/verification.service');
const reportService = require('../src/services/report.service');
const aiService = require('../src/services/ai.service');

describe('Full End-to-End System Integration Test', () => {
  let createdZipRepoId = null;
  let fixtureScanId = null;
  let testFinding = null;
  let testPatchId = null;

  it('1. Repository Intelligence: seeds default repos and retrieves both without errors', () => {
    const list = repositoryService.listRepositories();
    assert.ok(list.items.length >= 2, 'Must have at least 2 default repositories');

    const fixtureRepo = repositoryService.getRepositoryById('repo_fixture_01');
    assert.ok(fixtureRepo, 'repo_fixture_01 must exist');
    assert.ok(fs.existsSync(fixtureRepo.workspacePath), 'repo_fixture_01 workspacePath must exist');

    const sampleRepo = repositoryService.getRepositoryById('repo_01JAZZ80001');
    assert.ok(sampleRepo, 'repo_01JAZZ80001 must exist');
    assert.ok(fs.existsSync(sampleRepo.workspacePath), 'repo_01JAZZ80001 workspacePath must exist');
  });

  it('2. Repository Intake: registers a valid GitHub repository with SSRF guard', () => {
    const repo = repositoryService.registerRepository({
      sourceType: 'GITHUB',
      sourceUrl: 'https://github.com/OWASP/NodeGoat',
      displayName: 'NodeGoat-Test',
      defaultRef: 'master'
    });

    assert.ok(repo.id.startsWith('repo_'));
    assert.equal(repo.displayName, 'NodeGoat-Test');
    assert.equal(repo.defaultRef, 'master');
  });

  it('3. Repository Intake: safely ingests and extracts a ZIP archive into bounded workspace', () => {
    const zip = new AdmZip();
    zip.addFile('package.json', Buffer.from(JSON.stringify({ name: 'zip-vuln-app', version: '1.0.0' })));
    zip.addFile('server.js', Buffer.from('const q = `SELECT * FROM users WHERE id = ${req.query.id}`;\n'));

    const zipBuffer = zip.toBuffer();
    const repo = repositoryService.ingestZipArchive(zipBuffer, {
      displayName: 'uploaded-zip-test',
      defaultRef: 'main'
    });

    assert.ok(repo.id.startsWith('repo_'));
    assert.equal(repo.sourceType, 'ZIP_UPLOAD');
    assert.ok(fs.existsSync(repo.workspacePath), 'Extracted workspace path must exist');
    assert.ok(fs.existsSync(path.join(repo.workspacePath, 'server.js')));
    createdZipRepoId = repo.id;
  });

  it('4. Scan Orchestration: executes deterministic scan on repo_fixture_01', async () => {
    const fixtureRepo = repositoryService.getRepositoryById('repo_fixture_01');
    const scan = await scanOrchestrator.startScan({
      repositoryId: fixtureRepo.id,
      repositoryPath: fixtureRepo.workspacePath,
      ref: 'main',
      scanners: ['patterns']
    });

    assert.ok(scan.id.startsWith('scan_'));
    assert.equal(scan.status, 'COMPLETED');
    assert.ok(scan.summary.totalFindings > 0, 'Must detect benchmark fixture vulnerabilities');
    fixtureScanId = scan.id;
  });

  it('5. Scan Orchestration: executes deterministic scan on uploaded ZIP repository', async () => {
    const zipRepo = repositoryService.getRepositoryById(createdZipRepoId);
    const scan = await scanOrchestrator.startScan({
      repositoryId: zipRepo.id,
      repositoryPath: zipRepo.workspacePath,
      ref: 'main',
      scanners: ['patterns']
    });

    assert.ok(scan.id.startsWith('scan_'));
    assert.equal(scan.status, 'COMPLETED');
    assert.ok(scan.summary.totalFindings >= 1, 'Must detect SQL injection in uploaded server.js');
  });

  it('6. Findings Discovery: retrieves and filters normalized findings', () => {
    const findings = scanOrchestrator.getScanFindings(fixtureScanId);
    assert.ok(findings.length > 0);
    testFinding = findings[0];

    assert.ok(testFinding.id.startsWith('find_'));
    assert.ok(testFinding.fingerprint);
    assert.ok(testFinding.severity);
    assert.equal(testFinding.status, 'DETECTED');
  });

  it('7. AI Investigation: investigates finding and transitions state to TRIAGED', async () => {
    const result = await investigationService.investigateFinding(testFinding.id, {
      codeContext: testFinding.evidence
    });

    assert.ok(result);
    assert.ok(result.investigation);
    assert.equal(result.investigation.findingId, testFinding.id);
    assert.ok(result.investigation.assessment);

    // Finding must transition to TRIAGED
    const updated = scanOrchestrator.getFindingById(testFinding.id);
    assert.equal(updated.status, 'TRIAGED');
  });

  it('8. Patch Proposal: generates an evidence-linked minimal patch proposal', () => {
    const localProposal = aiService._localPatchProposal(testFinding);
    assert.ok(localProposal.success);
    assert.ok(localProposal.proposal);

    const saved = patchService.savePatch({
      ...localProposal.proposal,
      id: `patch_${Date.now()}_test`,
      findingId: testFinding.id,
      status: 'GENERATED'
    });

    assert.ok(saved.id.startsWith('patch_'));
    assert.equal(saved.reviewState, 'PENDING_REVIEW');
    testPatchId = saved.id;
  });

  it('9. Patch Review Gate: approves patch proposal', () => {
    const approved = patchService.approvePatch(testPatchId, {
      reviewedBy: 'security_lead',
      comments: 'Verified parameterization'
    });

    assert.equal(approved.reviewState, 'APPROVED');
    assert.equal(approved.reviewedBy, 'security_lead');
  });

  it('10. Patch Review Gate: rejects unapproved apply attempts', async () => {
    // A fresh unapproved patch cannot be applied without explicit approval
    const unapproved = patchService.savePatch({
      findingId: 'find_dummy_gate',
      diff: '--- a/dummy.js\n+++ b/dummy.js\n@@ -1,1 +1,1 @@\n-old\n+new',
      changedFiles: ['dummy.js'],
      status: 'GENERATED',
      reviewState: 'PENDING_REVIEW'
    });

    await assert.rejects(
      async () => {
        await patchService.applyPatchToDisposableWorkspace({
          patchId: unapproved.id,
          approved: false,
          confirm: false
        });
      },
      (err) => err.code === 'CONFIRMATION_REQUIRED' || err.code === 'APPROVAL_REQUIRED' || err.statusCode === 400 || err.statusCode === 403
    );
  });

  it('11. Patch Application: applies approved patch to disposable workspace without modifying original', async () => {
    const fixtureRepo = repositoryService.getRepositoryById('repo_fixture_01');
    const originalFile = path.join(fixtureRepo.workspacePath, testFinding.filePath);
    const originalContent = fs.existsSync(originalFile) ? fs.readFileSync(originalFile, 'utf8') : null;

    const result = await patchService.applyPatchToDisposableWorkspace({
      patchId: testPatchId,
      approved: true,
      confirm: true,
      approverComments: 'Approved for disposable verification'
    });

    assert.ok(result);
    assert.equal(result.status, 'APPLIED_TO_TEMP');
    assert.ok(result.disposableWorkspacePath);
    assert.ok(fs.existsSync(result.disposableWorkspacePath));

    // Original repo file must remain 100% untouched
    if (originalContent) {
      const currentOriginal = fs.readFileSync(originalFile, 'utf8');
      assert.equal(currentOriginal, originalContent, 'Original repo file must remain completely untouched');
    }

    // Cleanup disposable workspace
    fs.rmSync(result.disposableWorkspacePath, { recursive: true, force: true });
  });

  it('12. Report & Export: generates JSON, Markdown, and CSV scan reports', () => {
    const jsonReport = reportService.generateScanReport(fixtureScanId);
    assert.equal(jsonReport.scan.id, fixtureScanId);
    assert.ok(jsonReport.summary.totalFindings > 0);

    const mdReport = reportService.generateScanReport(fixtureScanId, { format: 'markdown' });
    assert.ok(typeof mdReport.content === 'string');
    assert.ok(mdReport.content.includes('# VULNEX Security Audit & Verification Report'));

    const csvReport = reportService.generateScanReport(fixtureScanId, { format: 'csv' });
    assert.ok(typeof csvReport.content === 'string');
    assert.ok(csvReport.content.includes('Finding ID,Rule ID,Severity,File Path'));
  });
});
