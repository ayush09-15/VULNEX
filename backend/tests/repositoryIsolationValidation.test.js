const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { scanOrchestrator } = require('../src/orchestrator/scanOrchestrator');
const repositoryService = require('../src/services/repository.service');
const { SCAN_STATES } = require('../src/orchestrator/scanStateMachine');

describe('Repository Isolation & Truthful Multi-Repo Scanning (Phase 4 Validation)', () => {
  let baseTmpDir;
  let repoAPath;
  let repoBPath;
  let repoCPath;
  let repoNoManifestPath;
  let repoNoSourceFilesPath;

  before(() => {
    baseTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex-val-'));

    // ------------------------------------------------------------------------
    // Repo A: Controlled Vulnerable Repo
    // ------------------------------------------------------------------------
    repoAPath = path.join(baseTmpDir, 'repo_a_vulnerable');
    fs.mkdirSync(path.join(repoAPath, 'src'), { recursive: true });
    fs.mkdirSync(path.join(repoAPath, 'config'), { recursive: true });

    fs.writeFileSync(
      path.join(repoAPath, 'package.json'),
      JSON.stringify({ name: 'repo-a-vulnerable', version: '1.0.0' }, null, 2)
    );
    fs.writeFileSync(
      path.join(repoAPath, 'src', 'users.js'),
      '// User service\nconst q = `SELECT * FROM users WHERE id = ${req.query.id}`;\nconsole.log(q);\n'
    );
    fs.writeFileSync(
      path.join(repoAPath, 'src', 'runner.js'),
      '// Runner service\nconst cp = require("child_process");\ncp.execSync(`ping -c 1 ${req.query.host}`);\n'
    );
    fs.writeFileSync(
      path.join(repoAPath, 'config', 'keys.js'),
      '// Config keys\nconst api_key = "secret_key_1234567890abcdef";\nmodule.exports = { api_key };\n'
    );

    // ------------------------------------------------------------------------
    // Repo B: Clean Repo (Zero vulnerabilities)
    // ------------------------------------------------------------------------
    repoBPath = path.join(baseTmpDir, 'repo_b_clean');
    fs.mkdirSync(path.join(repoBPath, 'src'), { recursive: true });

    fs.writeFileSync(
      path.join(repoBPath, 'package.json'),
      JSON.stringify({ name: 'repo-b-clean', version: '2.0.0' }, null, 2)
    );
    fs.writeFileSync(
      path.join(repoBPath, 'src', 'math.js'),
      '// Clean helper\nfunction add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n'
    );
    fs.writeFileSync(
      path.join(repoBPath, 'src', 'string.js'),
      '// String helper\nfunction capitalize(s) {\n  return s.charAt(0).toUpperCase() + s.slice(1);\n}\nmodule.exports = { capitalize };\n'
    );

    // ------------------------------------------------------------------------
    // Repo C: Different Repo (Path traversal & XSS in different directories)
    // ------------------------------------------------------------------------
    repoCPath = path.join(baseTmpDir, 'repo_c_different');
    fs.mkdirSync(path.join(repoCPath, 'lib'), { recursive: true });

    fs.writeFileSync(
      path.join(repoCPath, 'package.json'),
      JSON.stringify({ name: 'repo-c-different', version: '3.0.0' }, null, 2)
    );
    fs.writeFileSync(
      path.join(repoCPath, 'lib', 'reader.js'),
      '// Reader\nconst fs = require("fs");\nconst content = fs.readFileSync(path.join("/var/log", req.params.logfile));\n'
    );
    fs.writeFileSync(
      path.join(repoCPath, 'lib', 'view.js'),
      '// View\nconst html = `<div class="content">${req.body.profile}</div>`;\nelement.innerHTML = req.body.profile;\n'
    );

    // ------------------------------------------------------------------------
    // Repo D: No package.json
    // ------------------------------------------------------------------------
    repoNoManifestPath = path.join(baseTmpDir, 'repo_d_no_manifest');
    fs.mkdirSync(path.join(repoNoManifestPath, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(repoNoManifestPath, 'src', 'script.js'),
      'console.log("No package.json here");\n'
    );

    // ------------------------------------------------------------------------
    // Repo E: No supported source code files
    // ------------------------------------------------------------------------
    repoNoSourceFilesPath = path.join(baseTmpDir, 'repo_e_no_source');
    fs.mkdirSync(repoNoSourceFilesPath, { recursive: true });
    fs.writeFileSync(path.join(repoNoSourceFilesPath, 'README.txt'), 'Plain text file.\n');
    fs.writeFileSync(path.join(repoNoSourceFilesPath, 'notes.md'), '# Just markdown\nNo code here.\n');
  });

  after(() => {
    if (baseTmpDir && fs.existsSync(baseTmpDir)) {
      fs.rmSync(baseTmpDir, { recursive: true, force: true });
    }
  });

  // --------------------------------------------------------------------------
  // Test 1: Repo A (Vulnerable) produces real findings referencing its actual files
  // --------------------------------------------------------------------------
  it('1. Repository A produces findings that reference actual files and line numbers in Repo A', async () => {
    const scanA = await scanOrchestrator.startScan({
      repositoryId: 'repo_val_a',
      repositoryPath: repoAPath,
      ref: 'main',
      scanners: ['patterns', 'npm-audit']
    });

    assert.ok(scanA.id.startsWith('scan_'), 'Must generate a unique scan ID');
    assert.strictEqual(scanA.status, SCAN_STATES.COMPLETED);
    assert.strictEqual(scanA.stage, SCAN_STATES.COMPLETED);

    const findingsA = scanOrchestrator.getScanFindings(scanA.id);
    assert.ok(findingsA.length >= 3, 'Must detect SQLi, command injection, and secret');

    // Verify all findings reference real files in Repo A
    const filePaths = findingsA.map(f => f.filePath);
    assert.ok(filePaths.includes('src/users.js'), 'Must reference src/users.js');
    assert.ok(filePaths.includes('src/runner.js'), 'Must reference src/runner.js');
    assert.ok(filePaths.includes('config/keys.js'), 'Must reference config/keys.js');

    // Verify evidence lines match real source code
    const sqliFinding = findingsA.find(f => f.filePath === 'src/users.js');
    assert.ok(sqliFinding.evidence.includes('SELECT * FROM users WHERE id ='));
    assert.strictEqual(sqliFinding.startLine, 2);

    const cmdFinding = findingsA.find(f => f.filePath === 'src/runner.js');
    assert.ok(cmdFinding.evidence.includes('cp.execSync'));
    assert.strictEqual(cmdFinding.startLine, 3);

    // Verify severity totals match total findings
    const sev = scanA.summary.bySeverity;
    const sumSev = (sev.CRITICAL || 0) + (sev.HIGH || 0) + (sev.MEDIUM || 0) + (sev.LOW || 0) + (sev.INFO || 0);
    assert.strictEqual(sumSev, scanA.summary.totalFindings, 'Severity breakdown must strictly equal totalFindings');
    assert.strictEqual(scanA.summary.totalFindings, findingsA.length);
  });

  // --------------------------------------------------------------------------
  // Test 2: Repo B (Clean) produces 0 findings and status is COMPLETED
  // --------------------------------------------------------------------------
  it('2. Repository B (clean) produces 0 findings without failing or substituting mock findings', async () => {
    const scanB = await scanOrchestrator.startScan({
      repositoryId: 'repo_val_b',
      repositoryPath: repoBPath,
      ref: 'main',
      scanners: ['patterns', 'npm-audit']
    });

    assert.strictEqual(scanB.status, SCAN_STATES.COMPLETED);
    assert.strictEqual(scanB.summary.totalFindings, 0);

    const findingsB = scanOrchestrator.getScanFindings(scanB.id);
    assert.strictEqual(findingsB.length, 0, 'Clean repo must produce exactly 0 findings');

    const sev = scanB.summary.bySeverity;
    assert.strictEqual(sev.CRITICAL, 0);
    assert.strictEqual(sev.HIGH, 0);
    assert.strictEqual(sev.MEDIUM, 0);
    assert.strictEqual(sev.LOW, 0);
    assert.strictEqual(sev.INFO, 0);
  });

  // --------------------------------------------------------------------------
  // Test 3: Repo C produces different findings from Repo A and Repo B
  // --------------------------------------------------------------------------
  it('3. Repository C produces distinct findings corresponding to its specific files', async () => {
    const scanC = await scanOrchestrator.startScan({
      repositoryId: 'repo_val_c',
      repositoryPath: repoCPath,
      ref: 'main',
      scanners: ['patterns', 'npm-audit']
    });

    assert.strictEqual(scanC.status, SCAN_STATES.COMPLETED);
    const findingsC = scanOrchestrator.getScanFindings(scanC.id);
    assert.ok(findingsC.length >= 2, 'Must detect Path Traversal and XSS');

    const filePathsC = findingsC.map(f => f.filePath);
    assert.ok(filePathsC.includes('lib/reader.js'), 'Must reference lib/reader.js');
    assert.ok(filePathsC.includes('lib/view.js'), 'Must reference lib/view.js');

    // Confirm complete segregation from Repo A files
    assert.ok(!filePathsC.includes('src/users.js'), 'Must not contain any Repo A files');
    assert.ok(!filePathsC.includes('src/runner.js'), 'Must not contain any Repo A files');

    const sev = scanC.summary.bySeverity;
    const sumSev = (sev.CRITICAL || 0) + (sev.HIGH || 0) + (sev.MEDIUM || 0) + (sev.LOW || 0) + (sev.INFO || 0);
    assert.strictEqual(sumSev, scanC.summary.totalFindings);
  });

  // --------------------------------------------------------------------------
  // Test 4: Repeated scans of unchanged Repo A produce consistent findings
  // --------------------------------------------------------------------------
  it('4. Repeated scans of unchanged Repo A produce deterministic findings under a new scanId', async () => {
    const scanA1 = await scanOrchestrator.startScan({
      repositoryId: 'repo_val_a',
      repositoryPath: repoAPath,
      ref: 'main',
      scanners: ['patterns']
    });

    const scanA2 = await scanOrchestrator.startScan({
      repositoryId: 'repo_val_a',
      repositoryPath: repoAPath,
      ref: 'main',
      scanners: ['patterns']
    });

    assert.notStrictEqual(scanA1.id, scanA2.id, 'Every scan must receive a unique scan ID');

    const findingsA1 = scanOrchestrator.getScanFindings(scanA1.id);
    const findingsA2 = scanOrchestrator.getScanFindings(scanA2.id);

    assert.strictEqual(findingsA1.length, findingsA2.length, 'Findings count must match across identical runs');

    const fingerprintsA1 = findingsA1.map(f => f.fingerprint).sort();
    const fingerprintsA2 = findingsA2.map(f => f.fingerprint).sort();
    assert.deepStrictEqual(fingerprintsA1, fingerprintsA2, 'Fingerprints must match deterministically');

    // Ensure no finding leaks across scan IDs
    for (const f of findingsA1) {
      assert.strictEqual(f.scanId, scanA1.id);
    }
    for (const f of findingsA2) {
      assert.strictEqual(f.scanId, scanA2.id);
    }
  });

  // --------------------------------------------------------------------------
  // Test 5: Repository with no package.json gracefully skips dependency audit
  // --------------------------------------------------------------------------
  it('5. Repository with no package.json gracefully skips npm-audit without fabricating findings', async () => {
    const scanD = await scanOrchestrator.startScan({
      repositoryId: 'repo_val_d',
      repositoryPath: repoNoManifestPath,
      ref: 'main',
      scanners: ['npm-audit', 'patterns']
    });

    assert.strictEqual(scanD.status, SCAN_STATES.COMPLETED);
    assert.strictEqual(scanD.summary.totalFindings, 0);

    const npmAuditOutcome = scanD.summary.scannerOutcomes['npm-audit'];
    assert.ok(npmAuditOutcome);
    assert.strictEqual(npmAuditOutcome.status, 'COMPLETED');
    assert.strictEqual(npmAuditOutcome.findingsCount, 0);
    assert.ok(npmAuditOutcome.diagnostic.includes('No package manifest'));
  });

  // --------------------------------------------------------------------------
  // Test 6: Repository with no supported source files completes cleanly with 0 findings
  // --------------------------------------------------------------------------
  it('6. Repository with no supported source files completes cleanly with 0 findings', async () => {
    const scanE = await scanOrchestrator.startScan({
      repositoryId: 'repo_val_e',
      repositoryPath: repoNoSourceFilesPath,
      ref: 'main',
      scanners: ['patterns', 'npm-audit']
    });

    assert.strictEqual(scanE.status, SCAN_STATES.COMPLETED);
    assert.strictEqual(scanE.summary.totalFindings, 0);
    const findingsE = scanOrchestrator.getScanFindings(scanE.id);
    assert.strictEqual(findingsE.length, 0);
  });

  // --------------------------------------------------------------------------
  // Test 7: Strict isolation blocks scanning VULNEX application root
  // --------------------------------------------------------------------------
  it('7. Strict workspace isolation prevents scanning the host server application root', async () => {
    const serverRoot = path.resolve(__dirname, '../../');
    const scanRoot = await scanOrchestrator.startScan({
      repositoryId: 'repo_attack_root',
      repositoryPath: serverRoot,
      ref: 'main',
      scanners: ['patterns']
    });

    assert.strictEqual(scanRoot.status, SCAN_STATES.FAILED);
    assert.strictEqual(scanRoot.errorCode, 'WORKSPACE_ERROR');
    assert.strictEqual(scanRoot.summary.totalFindings, 0);

    const failedEvent = scanRoot.events.find(e => e.stage === SCAN_STATES.PREPARING && e.status === 'FAILED');
    assert.ok(failedEvent);
    assert.ok(failedEvent.message.includes('prohibited by repository isolation policy'));
  });

  // --------------------------------------------------------------------------
  // Test 8: ZIP Archive Intake creates isolated workspace and extracts files
  // --------------------------------------------------------------------------
  it('8. ZIP archive intake creates an isolated workspace and runs scan on extracted contents', async () => {
    const AdmZip = require('adm-zip');
    const zip = new AdmZip();
    zip.addFile('src/archive_cmd.js', Buffer.from('const cp = require("child_process"); cp.execSync(`cat ${req.query.file}`);\n'));
    const zipBuffer = zip.toBuffer();

    const repoZip = repositoryService.ingestZipArchive(zipBuffer, {
      displayName: 'test-zip-repo',
      defaultRef: 'main'
    });

    assert.ok(repoZip.id.startsWith('repo_'));
    assert.ok(repoZip.workspacePath);
    assert.ok(fs.existsSync(repoZip.workspacePath));

    const scanZip = await scanOrchestrator.startScan({
      repositoryId: repoZip.id,
      ref: 'main',
      scanners: ['patterns']
    });

    assert.strictEqual(scanZip.status, SCAN_STATES.COMPLETED);
    const findingsZip = scanOrchestrator.getScanFindings(scanZip.id);
    assert.strictEqual(findingsZip.length, 1);
    assert.strictEqual(findingsZip[0].filePath, 'src/archive_cmd.js');
    assert.ok(findingsZip[0].evidence.includes('cp.execSync'));

    // Clean up temporary workspace
    if (fs.existsSync(repoZip.workspacePath)) {
      fs.rmSync(repoZip.workspacePath, { recursive: true, force: true });
    }
  });

  // --------------------------------------------------------------------------
  // Test 9: GitHub repository intake when git clone fails reports WORKSPACE_ERROR
  // --------------------------------------------------------------------------
  it('9. GitHub intake with uncloneable repo fails cleanly with WORKSPACE_ERROR and never scans host', async () => {
    const repoUncloneable = repositoryService.registerRepository({
      sourceType: 'GITHUB',
      sourceUrl: 'https://github.com/vulnex-nonexistent-org/uncloneable-test-repo-999999',
      defaultRef: 'main'
    });

    const scanFail = await scanOrchestrator.startScan({
      repositoryId: repoUncloneable.id,
      ref: 'main',
      scanners: ['patterns']
    });

    assert.strictEqual(scanFail.status, SCAN_STATES.FAILED);
    assert.strictEqual(scanFail.errorCode, 'WORKSPACE_ERROR');
    assert.strictEqual(scanFail.summary.totalFindings, 0);

    const failEvent = scanFail.events.find(e => e.stage === SCAN_STATES.PREPARING && e.status === 'FAILED');
    assert.ok(failEvent);
    assert.ok(failEvent.message.includes('Workspace preparation failed'));
  });

  // --------------------------------------------------------------------------
  // Test 10: scanOrchestrator.getAllFindings({ repositoryId }) strictly partitions findings by repository
  // --------------------------------------------------------------------------
  it('10. scanOrchestrator.getAllFindings({ repositoryId }) strictly partitions findings by repository', async () => {
    const scanA = await scanOrchestrator.startScan({
      repositoryId: 'repo_partition_A',
      repositoryPath: repoAPath,
      scanners: ['patterns']
    });
    const scanB = await scanOrchestrator.startScan({
      repositoryId: 'repo_partition_B',
      repositoryPath: repoBPath,
      scanners: ['patterns']
    });

    const findingsRepoA = scanOrchestrator.getAllFindings({ repositoryId: 'repo_partition_A' });
    const findingsRepoB = scanOrchestrator.getAllFindings({ repositoryId: 'repo_partition_B' });

    assert.ok(findingsRepoA.length >= 2, 'Repo A should have pattern findings');
    assert.strictEqual(findingsRepoB.length, 0, 'Repo B (clean) should have 0 findings');

    // Confirm every finding in Repo A belongs to scanA
    for (const f of findingsRepoA) {
      assert.strictEqual(f.scanId, scanA.id);
    }
  });

  // --------------------------------------------------------------------------
  // Test 11: End-to-end HTTP route GET /api/findings with repositoryId and scanId filters
  // --------------------------------------------------------------------------
  it('11. End-to-end HTTP route GET /api/findings filters by repositoryId and scanId without leakage', async () => {
    const express = require('express');
    const http = require('http');
    const findingRoutes = require('../src/routes/finding.routes');

    const app = express();
    app.use(express.json());
    app.use('/api/findings', findingRoutes);

    const dispatch = (method, url) => {
      return new Promise((resolve) => {
        const [pathPart, queryPart] = url.split('?');
        const parsedQuery = {};
        if (queryPart) {
          for (const [k, v] of new URLSearchParams(queryPart)) {
            parsedQuery[k] = v;
          }
        }
        const req = new http.IncomingMessage();
        req.method = method.toUpperCase();
        req.url = url;
        req.originalUrl = url;
        req.headers = { 'content-type': 'application/json', 'x-request-id': 'req_test' };
        req.body = {};
        req.query = parsedQuery;

        const res = new http.ServerResponse(req);
        let rawBody = '';
        res.write = (chunk) => { if (chunk) rawBody += chunk; return true; };
        res.end = (chunk) => {
          if (chunk) rawBody += chunk;
          let parsed = null;
          try { parsed = JSON.parse(rawBody); } catch (_) { parsed = rawBody; }
          resolve({ statusCode: res.statusCode, body: parsed });
        };
        app.handle(req, res);
      });
    };

    const resA = await dispatch('GET', '/api/findings?repositoryId=repo_partition_A');
    assert.strictEqual(resA.statusCode, 200);
    assert.ok(resA.body.success);
    assert.ok(resA.body.data.length >= 2);

    const resB = await dispatch('GET', '/api/findings?repositoryId=repo_partition_B');
    assert.strictEqual(resB.statusCode, 200);
    assert.ok(resB.body.success);
    assert.strictEqual(resB.body.data.length, 0);
  });
});
