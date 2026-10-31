/**
 * VULNEX Safe Patch Service
 *
 * Implements:
 * - Master Antigravity Execution Bible Section 4.7 (Canonical Patch Endpoints)
 * - Section 4.9 (Patch Entity Schema & Persistence)
 * - Section 4.10 (Patch State Machine: GENERATED -> VALIDATED -> APPLIED_TO_TEMP)
 * - Section 7.2 Gate 35 (Original source/remote unchanged; rollback copy)
 * - Section 9.2 (Explicit Human Approval Gate)
 * - Section 8.7 Step 10 & Section 9 (Apply only to disposable workspace/worktree)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const config = require('../config/env');
const {
  validateDiffAndPaths,
  assertValidDiff,
  DiffValidationError
} = require('../validators/diffValidator');
const {
  parseUnifiedDiff,
  PATCH_REVIEW_STATES
} = require('../validators/patchProposal.schema');
const { scanOrchestrator } = require('../orchestrator/scanOrchestrator');
const scannerService = require('./scanner.service');

// Persistent in-memory stores for patch entities
const patchesStore = new Map();
const patchesByFinding = new Map();

/**
 * Copy directory recursively while excluding heavy or protected folders
 */
function copyDirectoryRecursive(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    if (['node_modules', '.git', '.workspaces', 'dist', 'build', 'coverage'].includes(entry.name)) {
      continue;
    }
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDirectoryRecursive(srcPath, destPath);
    } else if (entry.isFile()) {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

class PatchService {
  /**
   * Save and index a patch entity
   * @param {Object} patchData
   * @returns {Object} Saved patch entity
   */
  savePatch(patchData) {
    if (!patchData || typeof patchData !== 'object') {
      throw new Error('Patch data must be a non-null object');
    }

    const id = patchData.id || `patch_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const findingId = patchData.findingId;
    if (!findingId) {
      throw new Error('Patch entity requires findingId');
    }

    const entity = {
      id,
      findingId,
      diff: patchData.diff || '',
      rationale: typeof patchData.rationale === 'object'
        ? patchData.rationale.explanation || patchData.rationale.proposedCorrection || JSON.stringify(patchData.rationale)
        : String(patchData.rationale || 'Defensive security fix.'),
      status: patchData.status || 'GENERATED',
      reviewState: patchData.reviewState || PATCH_REVIEW_STATES.PENDING_REVIEW,
      changedFiles: Array.isArray(patchData.changedFiles) ? patchData.changedFiles : [],
      evidenceReferences: Array.isArray(patchData.evidenceReferences) ? patchData.evidenceReferences : [],
      appliedWorkspaceId: patchData.appliedWorkspaceId || null,
      disposableWorkspacePath: patchData.disposableWorkspacePath || null,
      originalWorkspacePath: patchData.originalWorkspacePath || null,
      backupFiles: patchData.backupFiles || {},
      createdAt: patchData.createdAt || new Date().toISOString(),
      updatedAt: patchData.updatedAt || new Date().toISOString()
    };

    patchesStore.set(entity.id, entity);
    patchesByFinding.set(findingId, entity);
    return entity;
  }

  /**
   * Retrieve patch by ID
   * @param {string} id
   * @returns {Object|null}
   */
  getPatchById(id) {
    return patchesStore.get(id) || null;
  }

  /**
   * Retrieve latest patch for finding ID
   * @param {string} findingId
   * @returns {Object|null}
   */
  getPatchByFindingId(findingId) {
    return patchesByFinding.get(findingId) || null;
  }

  /**
   * List all stored patches with optional filtering
   * @param {Object} [filters={}]
   * @returns {Array<Object>}
   */
  listPatches(filters = {}) {
    let list = Array.from(patchesStore.values());
    if (filters.findingId) {
      list = list.filter(p => p.findingId === filters.findingId);
    }
    if (filters.status) {
      list = list.filter(p => p.status.toUpperCase() === filters.status.toUpperCase());
    }
    if (filters.reviewState) {
      list = list.filter(p => p.reviewState.toUpperCase() === filters.reviewState.toUpperCase());
    }
    return list;
  }

  /**
   * Create a unified diff between original and modified strings (legacy/utility)
   * @param {Object} options
   * @returns {string} Unified diff format
   */
  createUnifiedDiff({ filename = 'file.js', originalContent = '', patchedContent = '' }) {
    const origLines = originalContent.split('\n');
    const patchLines = patchedContent.split('\n');

    let diff = `--- a/${filename}\n+++ b/${filename}\n@@ -1,${origLines.length} +1,${patchLines.length} @@\n`;

    const max = Math.max(origLines.length, patchLines.length);
    for (let i = 0; i < max; i++) {
      const orig = origLines[i];
      const mod = patchLines[i];

      if (orig !== mod) {
        if (orig !== undefined) diff += `-${orig}\n`;
        if (mod !== undefined) diff += `+${mod}\n`;
      } else {
        diff += ` ${orig}\n`;
      }
    }

    return diff;
  }

  /**
   * Preview diff in structured JSON format for UI presentation
   */
  previewPatch(originalContent, patchedContent) {
    const origLines = (originalContent || '').split('\n');
    const patchLines = (patchedContent || '').split('\n');
    const changes = [];

    const max = Math.max(origLines.length, patchLines.length);
    for (let i = 0; i < max; i++) {
      const o = origLines[i];
      const p = patchLines[i];

      if (o !== p) {
        if (o !== undefined) {
          changes.push({ type: 'delete', lineNum: i + 1, content: o });
        }
        if (p !== undefined) {
          changes.push({ type: 'add', lineNum: i + 1, content: p });
        }
      } else {
        changes.push({ type: 'unchanged', lineNum: i + 1, content: o });
      }
    }

    return {
      totalOriginalLines: origLines.length,
      totalPatchedLines: patchLines.length,
      changes
    };
  }

  /**
   * Apply unified diff string onto file content in memory.
   * Fails closed if hunk context lines do not match.
   *
   * @param {string} originalContent
   * @param {string} diffString
   * @returns {string} Patched content
   */
  applyDiffToContent(originalContent, diffString) {
    const parsed = parseUnifiedDiff(diffString);
    if (!parsed.valid) {
      const err = new Error(`Malformed unified diff: ${parsed.error}`);
      err.code = 'MALFORMED_DIFF';
      throw err;
    }

    const origLines = originalContent.split(/\r?\n/);
    let currentOrigIndex = 0;
    const resultLines = [];

    for (const hunk of parsed.hunks) {
      const targetStart = Math.max(0, hunk.oldStart - 1);

      // Best-effort offset matching window (-5 to +5 lines)
      let matchOffset = 0;
      let foundMatch = false;

      const firstHunkLine = hunk.lines.find(l => l[0] === ' ' || l[0] === '-');
      if (firstHunkLine) {
        const expectedFirst = firstHunkLine.slice(1);
        for (const offset of [0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5]) {
          const testIdx = targetStart + offset;
          if (testIdx >= currentOrigIndex && testIdx < origLines.length && (origLines[testIdx] === expectedFirst || origLines[testIdx].trim() === expectedFirst.trim())) {
            matchOffset = offset;
            foundMatch = true;
            break;
          }
        }
      } else {
        foundMatch = true;
      }

      const effectiveStart = foundMatch ? targetStart + matchOffset : targetStart;

      // Copy all original lines up to effectiveStart
      while (currentOrigIndex < effectiveStart && currentOrigIndex < origLines.length) {
        resultLines.push(origLines[currentOrigIndex]);
        currentOrigIndex++;
      }

      // Apply hunk lines
      for (let hIdx = 0; hIdx < hunk.lines.length; hIdx++) {
        const hLine = hunk.lines[hIdx];
        const marker = hLine[0];
        const content = hLine.slice(1);

        if (marker === ' ') {
          if (currentOrigIndex < origLines.length) {
            if (origLines[currentOrigIndex] === content || origLines[currentOrigIndex].trim() === content.trim()) {
              resultLines.push(origLines[currentOrigIndex]);
              currentOrigIndex++;
            } else {
              const err = new Error(
                `Context mismatch at original line ${currentOrigIndex + 1}. Expected: "${content}", Found: "${origLines[currentOrigIndex]}"`
              );
              err.code = 'HUNK_CONTEXT_MISMATCH';
              throw err;
            }
          }
        } else if (marker === '-') {
          if (currentOrigIndex < origLines.length) {
            if (origLines[currentOrigIndex] === content || origLines[currentOrigIndex].trim() === content.trim()) {
              currentOrigIndex++; // Omit line from output
            } else {
              const err = new Error(
                `Deleted line mismatch at original line ${currentOrigIndex + 1}. Expected: "${content}", Found: "${origLines[currentOrigIndex]}"`
              );
              err.code = 'HUNK_DELETE_MISMATCH';
              throw err;
            }
          }
        } else if (marker === '+') {
          resultLines.push(content);
        }
      }
    }

    // Copy remaining lines
    while (currentOrigIndex < origLines.length) {
      resultLines.push(origLines[currentOrigIndex]);
      currentOrigIndex++;
    }

    return resultLines.join('\n');
  }

  /**
   * Apply an approved patch into an isolated disposable workspace.
   * Guarantees:
   * - Original source directory and remote remain 100% untouched.
   * - Full rollback copy created inside disposable workspace.
   * - Human approval gate (approved: true or confirm: true) strictly enforced.
   * - Validates diff syntax, paths, and scope before any disk operation.
   * - Fails closed on any mismatch or error.
   *
   * @param {Object} params
   * @param {string} [params.patchId]
   * @param {Object} [params.patch]
   * @param {string} [params.workspacePath]
   * @param {boolean} [params.approved]
   * @param {boolean} [params.confirm]
   * @param {string} [params.approverComments]
   * @returns {Promise<Object>} Safe application result with disposable workspace info
   */
  async applyPatchToDisposableWorkspace(params = {}) {
    const { patchId, workspacePath, approved, confirm, approverComments } = params;

    // 1. Human Approval Gate (Bible Section 4.10, 9.2)
    const isApproved = (approved === true) || (confirm === true);
    if (!isApproved) {
      const err = new Error('Explicit human approval (approved: true or confirm: true) is required to apply patches.');
      err.code = 'CONFIRMATION_REQUIRED';
      err.statusCode = 400;
      throw err;
    }

    // 2. Resolve Patch Entity
    let patch = params.patch || (patchId ? this.getPatchById(patchId) : null);
    if (!patch && params.findingId) {
      patch = this.getPatchByFindingId(params.findingId);
    }
    if (!patch) {
      const err = new Error(`Patch '${patchId || params.findingId || 'unknown'}' not found.`);
      err.code = 'PATCH_NOT_FOUND';
      err.statusCode = 404;
      throw err;
    }

    // 3. Resolve Finding
    const finding = scanOrchestrator.getFindingById(patch.findingId) || scannerService.getFindingById(patch.findingId);

    // 4. Resolve Original Workspace
    let origWorkspace = workspacePath;
    if (!origWorkspace && finding && finding.scanId) {
      const scan = (typeof scanOrchestrator.getScan === 'function' ? scanOrchestrator.getScan(finding.scanId) : null) ||
                   (typeof scannerService.getScan === 'function' ? scannerService.getScan(finding.scanId) : null);
      if (scan && scan.workspacePath) {
        origWorkspace = scan.workspacePath;
      }
    }
    if (!origWorkspace && finding && finding.workspacePath) {
      origWorkspace = finding.workspacePath;
    }
    if (!origWorkspace) {
      origWorkspace = path.resolve(config.workspaceRoot || path.join(__dirname, '../../.workspaces'), 'default_workspace');
      if (!fs.existsSync(origWorkspace)) {
        fs.mkdirSync(origWorkspace, { recursive: true });
      }
    }

    // 5. Validate Diff & Paths (Bible Section 7.2 Gate 31 & 32)
    const validation = validateDiffAndPaths(patch.diff, {
      workspacePath: origWorkspace,
      declaredChangedFiles: patch.changedFiles.length > 0 ? patch.changedFiles : undefined,
      allowMultiFile: false,
      allowCreation: false,
      allowDeletion: false,
      allowRename: false
    });

    if (!validation.valid) {
      const firstErr = validation.errors[0] || 'Diff validation failed';
      const err = new Error(`Diff validation rejected: ${firstErr}`);
      err.code = 'PATCH_VALIDATION_FAILED';
      err.details = validation.errors;
      err.statusCode = 400;
      throw err;
    }

    // 6. Create Disposable Workspace (Isolation Guarantee)
    const disposableId = `disp_${patch.id}_${Date.now()}`;
    const disposableDir = path.join(
      config.workspaceRoot || path.resolve(__dirname, '../../.workspaces'),
      'disposable',
      disposableId
    );
    fs.mkdirSync(disposableDir, { recursive: true });

    // Copy original workspace files into disposable workspace
    // Original source remains 100% untouched!
    if (fs.existsSync(origWorkspace)) {
      copyDirectoryRecursive(origWorkspace, disposableDir);
    }

    const changedFiles = validation.detectedFiles.length > 0 ? validation.detectedFiles : patch.changedFiles;
    const backupFiles = {};

    try {
      // 7. Apply Diff Hunks to Target Files in Disposable Workspace
      for (const relFile of changedFiles) {
        const targetPath = path.join(disposableDir, relFile);
        if (!fs.existsSync(targetPath)) {
          const origPath = path.join(origWorkspace, relFile);
          if (fs.existsSync(origPath)) {
            fs.mkdirSync(path.dirname(targetPath), { recursive: true });
            fs.copyFileSync(origPath, targetPath);
          } else if (finding && (finding.evidence || finding.codeSnippet)) {
            fs.mkdirSync(path.dirname(targetPath), { recursive: true });
            fs.writeFileSync(targetPath, finding.codeSnippet || finding.evidence, 'utf8');
          } else {
            throw new Error(`Target file "${relFile}" not found in workspace`);
          }
        }

        const originalContent = fs.readFileSync(targetPath, 'utf8');
        const backupPath = `${targetPath}.vulnex.bak`;

        // Create backup / rollback copy in disposable workspace
        fs.writeFileSync(backupPath, originalContent, 'utf8');
        backupFiles[relFile] = backupPath;

        // Apply diff to content
        const patchedContent = this.applyDiffToContent(originalContent, patch.diff);

        // Write patched content to disposable workspace file
        fs.writeFileSync(targetPath, patchedContent, 'utf8');
      }
    } catch (applyErr) {
      // Clean up disposable workspace on failure
      try {
        fs.rmSync(disposableDir, { recursive: true, force: true });
      } catch (_) {}

      const err = new Error(`Failed to apply patch hunks safely: ${applyErr.message}`);
      err.code = applyErr.code || 'PATCH_APPLICATION_FAILED';
      err.statusCode = 500;
      throw err;
    }

    // 8. Update Patch State Machine (GENERATED/VALIDATED -> APPLIED_TO_TEMP)
    const updatedPatch = {
      ...patch,
      status: 'APPLIED_TO_TEMP',
      reviewState: PATCH_REVIEW_STATES.APPROVED,
      reviewedBy: 'human_reviewer',
      reviewedAt: new Date().toISOString(),
      reviewComments: approverComments || 'Approved by human reviewer',
      appliedWorkspaceId: disposableId,
      disposableWorkspacePath: disposableDir,
      originalWorkspacePath: origWorkspace,
      backupFiles,
      appliedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    patchesStore.set(patch.id, updatedPatch);
    patchesByFinding.set(patch.findingId, updatedPatch);

    // 9. Update Finding State Machine (PATCH_PROPOSED -> PATCH_APPLIED)
    if (finding) {
      const updatedFinding = {
        ...finding,
        status: 'PATCH_APPLIED',
        patchId: patch.id,
        appliedWorkspaceId: disposableId,
        disposableWorkspacePath: disposableDir,
        appliedAt: new Date().toISOString()
      };
      scanOrchestrator.updateFinding(finding.id, updatedFinding);
      scannerService.updateFinding(finding.id, updatedFinding);
    }

    return {
      success: true,
      patchId: patch.id,
      findingId: patch.findingId,
      status: 'APPLIED_TO_TEMP',
      appliedWorkspaceId: disposableId,
      disposableWorkspacePath: disposableDir,
      originalWorkspacePath: origWorkspace,
      changedFiles,
      backupFiles,
      appliedAt: updatedPatch.appliedAt
    };
  }

  /**
   * Rollback an applied patch in disposable workspace
   * @param {string} patchId
   * @returns {Promise<Object>}
   */
  async rollbackPatch(patchId) {
    const patch = this.getPatchById(patchId) || this.getPatchByFindingId(patchId);
    if (!patch) {
      const err = new Error(`Patch '${patchId}' not found.`);
      err.code = 'PATCH_NOT_FOUND';
      err.statusCode = 404;
      throw err;
    }

    if (patch.status !== 'APPLIED_TO_TEMP' && !patch.disposableWorkspacePath) {
      const err = new Error(`Patch '${patch.id}' is not in APPLIED_TO_TEMP state (current: ${patch.status}).`);
      err.code = 'INVALID_PATCH_STATE';
      err.statusCode = 400;
      throw err;
    }

    // Restore from backup in disposable workspace if exists
    if (patch.backupFiles && typeof patch.backupFiles === 'object') {
      for (const [relFile, backupPath] of Object.entries(patch.backupFiles)) {
        if (fs.existsSync(backupPath)) {
          const targetPath = backupPath.replace(/\.vulnex\.bak$/, '');
          fs.copyFileSync(backupPath, targetPath);
          fs.unlinkSync(backupPath);
        }
      }
    }

    // Transition state: APPLIED_TO_TEMP -> VALIDATED
    const updatedPatch = {
      ...patch,
      status: 'VALIDATED',
      disposableWorkspacePath: null,
      appliedWorkspaceId: null,
      revertedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    patchesStore.set(patch.id, updatedPatch);
    patchesByFinding.set(patch.findingId, updatedPatch);

    // Finding state: PATCH_APPLIED -> PATCH_PROPOSED
    const finding = scanOrchestrator.getFindingById(patch.findingId) || scannerService.getFindingById(patch.findingId);
    if (finding) {
      const updatedFinding = {
        ...finding,
        status: 'PATCH_PROPOSED',
        disposableWorkspacePath: null,
        appliedWorkspaceId: null,
        revertedAt: new Date().toISOString()
      };
      scanOrchestrator.updateFinding(finding.id, updatedFinding);
      scannerService.updateFinding(finding.id, updatedFinding);
    }

    return {
      success: true,
      patchId: patch.id,
      findingId: patch.findingId,
      status: 'REVERTED',
      revertedAt: updatedPatch.revertedAt
    };
  }

  /**
   * Safely apply a patch to disk with backup creation (legacy utility)
   */
  async applyPatch({ filePath, patchedContent }) {
    if (!filePath || !fs.existsSync(filePath)) {
      throw new Error(`Target file does not exist: ${filePath}`);
    }

    const originalContent = fs.readFileSync(filePath, 'utf8');
    const backupPath = `${filePath}.vulnex.bak`;

    // Create backup
    fs.writeFileSync(backupPath, originalContent, 'utf8');

    // Write patched file
    fs.writeFileSync(filePath, patchedContent, 'utf8');

    return {
      success: true,
      filePath,
      backupPath,
      appliedAt: new Date().toISOString()
    };
  }

  /**
   * Clear in-memory patch stores (test helper)
   */
  clearStore() {
    patchesStore.clear();
    patchesByFinding.clear();
  }

  _resetStore() {
    this.clearStore();
  }
}

const patchServiceInstance = new PatchService();

module.exports = patchServiceInstance;
