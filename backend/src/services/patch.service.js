const fs = require('fs');
const path = require('path');

class PatchService {
  /**
   * Create a unified diff between original and modified strings
   * @param {Object} options
   * @returns {string} Unified diff format
   */
  createUnifiedDiff({ filename = 'file.js', originalContent = '', patchedContent = '' }) {
    const origLines = originalContent.split('\n');
    const patchLines = patchedContent.split('\n');

    let diff = `--- a/${filename}\n+++ b/${filename}\n@@ -1,${origLines.length} +1,${patchLines.length} @@\n`;

    // Simple line diff generator
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
   * Safely apply a patch to disk with backup creation
   */
  async applyPatch({ filePath, patchedContent }) {
    if (!fs.existsSync(filePath)) {
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
   * Rollback a patch from backup file
   */
  async rollbackPatch({ filePath }) {
    const backupPath = `${filePath}.vulnex.bak`;
    if (!fs.existsSync(backupPath)) {
      throw new Error(`Backup file not found for ${filePath}`);
    }

    const backupContent = fs.readFileSync(backupPath, 'utf8');
    fs.writeFileSync(filePath, backupContent, 'utf8');
    fs.unlinkSync(backupPath);

    return {
      success: true,
      filePath,
      revertedAt: new Date().toISOString()
    };
  }
}

module.exports = new PatchService();

