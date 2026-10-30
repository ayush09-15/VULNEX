const scannerService = require('./scanner.service');

class VerificationService {
  /**
   * Verify whether a proposed patch resolves the vulnerability
   * and introduces no syntax errors or new vulnerabilities.
   *
   * @param {Object} params
   * @param {Object} params.finding Original security finding
   * @param {string} params.patchedCode The code after applying patch
   * @param {string} params.originalCode The code before applying patch
   * @param {string} params.filePath Target file path
   * @returns {Object} Verification report
   */
  async verifyPatch({ finding, patchedCode, originalCode, filePath = 'file.js' }) {
    const checks = {
      syntaxValid: true,
      originalVulnerabilityResolved: false,
      regressionDetected: false,
      newFindings: []
    };

    // 1. Basic JavaScript syntax check if JS file
    if (filePath.endsWith('.js') || filePath.endsWith('.jsx')) {
      try {
        new Function(patchedCode);
        checks.syntaxValid = true;
      } catch (err) {
        // Functions with imports/exports may fail new Function; check for basic unclosed brackets
        const openBraces = (patchedCode.match(/\{/g) || []).length;
        const closeBraces = (patchedCode.match(/\}/g) || []).length;
        checks.syntaxValid = openBraces === closeBraces;
      }
    }

    // 2. Re-scan patched content using scannerService
    const postScanFindings = scannerService.scanContent(patchedCode, filePath);

    // 3. Check if original rule is still detected
    const stillPresent = postScanFindings.some(f => f.ruleId === finding.ruleId || f.cwe === finding.cwe);
    checks.originalVulnerabilityResolved = !stillPresent;

    // 4. Check for regressions (new security findings not present in original)
    const originalFindings = scannerService.scanContent(originalCode || '', filePath);
    const originalRuleIds = new Set(originalFindings.map(f => f.ruleId));

    const newlyIntroduced = postScanFindings.filter(f => !originalRuleIds.has(f.ruleId));
    if (newlyIntroduced.length > 0) {
      checks.regressionDetected = true;
      checks.newFindings = newlyIntroduced;
    }

    const isVerified = checks.syntaxValid && checks.originalVulnerabilityResolved && !checks.regressionDetected;

    return {
      isVerified,
      checks,
      summary: isVerified
        ? 'Patch successfully resolved the vulnerability with no regressions.'
        : 'Patch verification failed. Review checks for details.',
      verifiedAt: new Date().toISOString()
    };
  }
}

module.exports = new VerificationService();

