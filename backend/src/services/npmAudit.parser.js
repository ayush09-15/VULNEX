const fs = require('fs');
const path = require('path');
const findingNormalizer = require('./finding.normalizer');
const { validateCommonFinding } = require('../validators/commonFinding.schema');

/**
 * ============================================================================
 * VULNEX Lockfile-Aware npm Audit JSON Parser
 *
 * Responsibilities:
 * 1. Parse `npm audit --json` output (supporting both npm v7+ auditReportVersion: 2
 *    and legacy npm v6 advisories format).
 * 2. Resolve installed package versions, integrity, and dependency hierarchy
 *    using `package-lock.json` as the authoritative source of truth.
 * 3. Extract comprehensive advisory metadata:
 *    - Package name and vulnerable version range
 *    - Installed version (from lockfile or advisory findings)
 *    - Advisory title, description, and remediation
 *    - Severity (mapped deterministically to VULNEX convention)
 *    - Direct vs transitive dependency relationship
 *    - Affected dependency path (e.g. `mkdirp > minimist`)
 *    - Fix availability, target fix version, and semver major flags
 *    - Advisory URLs and identifiers (CVE, GHSA, CWE, CVSS)
 * 4. Construct canonical findings conforming to CommonFindingSchema with stable
 *    SHA-256 fingerprints.
 * 5. Handle empty audits, missing fields, malformed JSON, and non-zero exit codes.
 * 6. Completely passive: never executes scripts or writes to lockfiles.
 * ============================================================================
 */
class NpmAuditParser {
  /**
   * Parse a package-lock.json input safely without side effects
   *
   * @param {string|Object} [lockfileInput] Raw string or parsed object
   * @param {string} [lockfilePath] Optional path to read from disk
   * @returns {Object|null} Parsed lockfile or null
   */
  parseLockfile(lockfileInput, lockfilePath = null) {
    if (lockfileInput && typeof lockfileInput === 'object') {
      return lockfileInput;
    }

    if (typeof lockfileInput === 'string' && lockfileInput.trim()) {
      try {
        return JSON.parse(lockfileInput);
      } catch {
        return null;
      }
    }

    if (lockfilePath && typeof lockfilePath === 'string') {
      try {
        if (fs.existsSync(lockfilePath)) {
          const content = fs.readFileSync(lockfilePath, 'utf8');
          return JSON.parse(content);
        }
      } catch {
        return null;
      }
    }

    return null;
  }

  /**
   * Resolve installed version and package details from package-lock.json
   * Respects lockfileVersion 1, 2, and 3.
   *
   * @param {Object|null} lockfile Parsed lockfile object
   * @param {string} packageName Target package name
   * @param {Array<string>} [nodePaths=[]] List of node_modules paths (e.g. `["node_modules/mkdirp/node_modules/minimist"]`)
   * @returns {{
   *   installedVersion: string|null,
   *   isDev: boolean,
   *   resolved: string|null,
   *   integrity: string|null,
   *   lockfileVersion: number|null
   * }}
   */
  resolveFromLockfile(lockfile, packageName, nodePaths = []) {
    const result = {
      installedVersion: null,
      isDev: false,
      resolved: null,
      integrity: null,
      lockfileVersion: lockfile?.lockfileVersion || null
    };

    if (!lockfile || typeof lockfile !== 'object') {
      return result;
    }

    // --- Strategy A: Lockfile v2 / v3 (`packages` map) ---
    if (lockfile.packages && typeof lockfile.packages === 'object') {
      // 1. Check exact nodePaths provided by npm audit
      for (const nodePath of nodePaths) {
        if (lockfile.packages[nodePath]) {
          const pkg = lockfile.packages[nodePath];
          result.installedVersion = pkg.version || null;
          result.isDev = Boolean(pkg.dev);
          result.resolved = pkg.resolved || null;
          result.integrity = pkg.integrity || null;
          return result;
        }
      }

      // 2. Check top-level node_modules/packageName
      const topLevelKey = `node_modules/${packageName}`;
      if (lockfile.packages[topLevelKey]) {
        const pkg = lockfile.packages[topLevelKey];
        result.installedVersion = pkg.version || null;
        result.isDev = Boolean(pkg.dev);
        result.resolved = pkg.resolved || null;
        result.integrity = pkg.integrity || null;
        return result;
      }

      // 3. Search packages keys matching /node_modules/packageName$
      const targetSuffix = `/node_modules/${packageName}`;
      for (const [key, pkg] of Object.entries(lockfile.packages)) {
        if (key.endsWith(targetSuffix) && pkg.version) {
          result.installedVersion = pkg.version;
          result.isDev = Boolean(pkg.dev);
          result.resolved = pkg.resolved || null;
          result.integrity = pkg.integrity || null;
          return result;
        }
      }
    }

    // --- Strategy B: Lockfile v1 / v2 fallback (`dependencies` tree) ---
    if (lockfile.dependencies && typeof lockfile.dependencies === 'object') {
      // Check top-level dependency
      if (lockfile.dependencies[packageName]?.version) {
        const dep = lockfile.dependencies[packageName];
        result.installedVersion = dep.version;
        result.isDev = Boolean(dep.dev);
        result.resolved = dep.resolved || null;
        result.integrity = dep.integrity || null;
        return result;
      }

      // If nodePath indicates a nested dependency (e.g. node_modules/A/node_modules/B)
      for (const nodePath of nodePaths) {
        const parts = nodePath
          .replace(/^node_modules\//, '')
          .split('/node_modules/')
          .filter(Boolean);

        let current = lockfile.dependencies;
        let matched = null;

        for (let i = 0; i < parts.length; i++) {
          const part = parts[i];
          if (current && current[part]) {
            matched = current[part];
            current = matched.dependencies;
          } else {
            matched = null;
            break;
          }
        }

        if (matched?.version) {
          result.installedVersion = matched.version;
          result.isDev = Boolean(matched.dev);
          result.resolved = matched.resolved || null;
          result.integrity = matched.integrity || null;
          return result;
        }
      }
    }

    return result;
  }

  /**
   * Format node_modules path into human-readable dependency chain (e.g. `mkdirp > minimist`)
   *
   * @param {string} nodePath e.g. "node_modules/mkdirp/node_modules/minimist"
   * @returns {string} Formatted chain "mkdirp > minimist"
   */
  formatDependencyPath(nodePath) {
    if (!nodePath || typeof nodePath !== 'string') return '';
    const cleaned = nodePath
      .replace(/^node_modules\//, '')
      .split('/node_modules/')
      .filter(Boolean)
      .join(' > ');
    return cleaned || nodePath;
  }

  /**
   * Extract CVE identifiers from text, URLs, or advisory objects
   *
   * @param {string} text
   * @param {Array<string>} [existingCves=[]]
   * @returns {Array<string>} List of CVE IDs
   */
  extractCves(text = '', existingCves = []) {
    const cves = new Set(existingCves || []);
    const matches = String(text || '').match(/\bCVE-\d{4}-\d{4,}\b/gi);
    if (matches) {
      matches.forEach(m => cves.add(m.toUpperCase()));
    }
    return Array.from(cves);
  }

  /**
   * Extract GHSA identifier from text or URL
   *
   * @param {string} text
   * @returns {string|null} GHSA ID or null
   */
  extractGhsa(text = '') {
    const match = String(text || '').match(/\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b/i);
    return match ? match[0].toUpperCase() : null;
  }

  /**
   * Parse npm audit JSON output and return structured VULNEX scanner findings
   *
   * @param {string|Object} rawOutput Raw stdout string from `npm audit --json` or parsed object
   * @param {Object} [options={}] Parser options
   * @param {string|Object} [options.lockfile] Parsed package-lock.json or JSON string
   * @param {string} [options.lockfilePath] Absolute or relative path to package-lock.json
   * @param {string} [options.workspacePath] Workspace root directory
   * @param {number} [options.exitCode] Process exit code from npm audit runner
   * @returns {{
   *   success: boolean,
   *   isValidJson: boolean,
   *   advisoriesCount: number,
   *   advisories: Array<Object>,
   *   findings: Array<Object>,
   *   errors: Array<string>,
   *   metadata: Object|null
   * }}
   */
  parse(rawOutput, options = {}) {
    const errors = [];
    const advisories = [];
    const findings = [];

    // 1. Validate Input Presence
    if (rawOutput === null || rawOutput === undefined || rawOutput === '') {
      return {
        success: false,
        isValidJson: false,
        advisoriesCount: 0,
        advisories: [],
        findings: [],
        errors: ['npm audit output is empty or null'],
        metadata: null
      };
    }

    // 2. Parse JSON
    let auditData;
    if (typeof rawOutput === 'string') {
      try {
        auditData = JSON.parse(rawOutput);
      } catch (err) {
        return {
          success: false,
          isValidJson: false,
          advisoriesCount: 0,
          advisories: [],
          findings: [],
          errors: [`Failed to parse npm audit JSON output: ${err.message}`],
          metadata: null
        };
      }
    } else if (typeof rawOutput === 'object') {
      auditData = rawOutput;
    } else {
      return {
        success: false,
        isValidJson: false,
        advisoriesCount: 0,
        advisories: [],
        findings: [],
        errors: ['Invalid npm audit output type (expected JSON string or object)'],
        metadata: null
      };
    }

    // 3. Resolve Lockfile
    const lockfilePath = options.lockfilePath || (
      options.workspacePath ? path.join(options.workspacePath, 'package-lock.json') : null
    );
    const lockfile = this.parseLockfile(options.lockfile, lockfilePath);
    const lockfileVersion = lockfile?.lockfileVersion || null;

    // Relative lockfile path for finding location
    let relativeLockfilePath = 'package-lock.json';
    if (options.workspacePath && lockfilePath && lockfilePath.startsWith(options.workspacePath)) {
      relativeLockfilePath = path.relative(options.workspacePath, lockfilePath).replace(/\\/g, '/');
    }

    // 4. Extract Advisories based on npm audit format
    const isReportV2 = auditData.auditReportVersion === 2 || (auditData.vulnerabilities && typeof auditData.vulnerabilities === 'object');
    const isReportV1 = auditData.advisories && typeof auditData.advisories === 'object';

    if (isReportV2) {
      this._parseV2Report(auditData, lockfile, relativeLockfilePath, advisories, findings, errors);
    } else if (isReportV1) {
      this._parseV1Report(auditData, lockfile, relativeLockfilePath, advisories, findings, errors);
    } else {
      // Valid JSON but unrecognized structure (could be empty scan or error payload)
      if (auditData.error) {
        errors.push(`npm audit reported error: ${auditData.error.summary || auditData.error.code || JSON.stringify(auditData.error)}`);
      } else {
        errors.push('Unrecognized npm audit report schema (neither v1 advisories nor v2 vulnerabilities detected)');
      }
    }

    // 5. Build summary metadata
    const vulnsSummary = auditData.metadata?.vulnerabilities || {
      total: advisories.length
    };
    const totalDeps = auditData.metadata?.dependencies?.total !== undefined
      ? auditData.metadata.dependencies.total
      : null;

    const metadata = {
      auditReportVersion: auditData.auditReportVersion || (isReportV1 ? 1 : 2),
      lockfileVersion,
      totalDependencies: totalDeps,
      vulnerabilitiesSummary: vulnsSummary,
      scannedPackageCount: Object.keys(auditData.vulnerabilities || auditData.advisories || {}).length
    };

    return {
      success: errors.length === 0,
      isValidJson: true,
      advisoriesCount: advisories.length,
      advisories,
      findings,
      errors,
      metadata
    };
  }

  /**
   * Internal parser for npm v7+ (auditReportVersion: 2) format
   * @private
   */
  _parseV2Report(auditData, lockfile, relativeLockfilePath, advisories, findings, errors) {
    const vulns = auditData.vulnerabilities || {};

    for (const [pkgName, vulnEntry] of Object.entries(vulns)) {
      if (!vulnEntry || typeof vulnEntry !== 'object') continue;

      const packageName = vulnEntry.name || pkgName;
      const isDirect = Boolean(vulnEntry.isDirect);
      const nodes = Array.isArray(vulnEntry.nodes) ? vulnEntry.nodes : [];
      const effects = Array.isArray(vulnEntry.effects) ? vulnEntry.effects : [];
      const vulnerableRange = vulnEntry.range || 'unknown';

      // Fix availability inspection
      const fixAvailableRaw = vulnEntry.fixAvailable;
      const hasFix = Boolean(fixAvailableRaw);
      const fixVersion = (fixAvailableRaw && typeof fixAvailableRaw === 'object') ? fixAvailableRaw.version : null;
      const fixPackage = (fixAvailableRaw && typeof fixAvailableRaw === 'object') ? fixAvailableRaw.name : (hasFix ? packageName : null);
      const isSemVerMajor = (fixAvailableRaw && typeof fixAvailableRaw === 'object') ? Boolean(fixAvailableRaw.isSemVerMajor) : false;

      // Resolve installed version from lockfile
      const lockfileResolution = this.resolveFromLockfile(lockfile, packageName, nodes);
      const installedVersion = lockfileResolution.installedVersion;

      // Primary dependency chain
      const primaryNode = nodes[0] || `node_modules/${packageName}`;
      const dependencyPath = this.formatDependencyPath(primaryNode);

      // Inspect `via` entries (contains advisory objects or parent dependency names)
      const viaList = Array.isArray(vulnEntry.via) ? vulnEntry.via : [];
      const advisoryObjects = viaList.filter(item => item && typeof item === 'object');

      if (advisoryObjects.length > 0) {
        // Direct or transitive source vulnerabilities with full advisory records
        for (const adv of advisoryObjects) {
          const advisoryTitle = adv.title || `Security advisory in ${packageName}`;
          const advisoryUrl = adv.url || null;
          const rawSeverity = adv.severity || vulnEntry.severity || 'moderate';
          const severity = findingNormalizer.mapSeverity(rawSeverity);
          const ghsaId = this.extractGhsa(advisoryUrl) || this.extractGhsa(adv.name);
          const cves = this.extractCves(adv.title || '', adv.cwe);
          const cveId = cves[0] || null;
          const primaryId = ghsaId || cveId || String(adv.source || adv.name || 'advisory');

          const advisoryRecord = {
            packageName,
            title: advisoryTitle,
            vulnerableVersions: adv.range || vulnerableRange,
            installedVersion,
            severity,
            rawSeverity,
            isDirect,
            dependencyPath,
            nodes,
            effects,
            fixAvailable: {
              hasFix,
              fixPackage,
              fixVersion,
              isSemVerMajor
            },
            advisoryUrl,
            ghsaId,
            cveId,
            cves,
            cwe: Array.isArray(adv.cwe) ? adv.cwe : [],
            cvss: adv.cvss || null,
            source: 'npm-audit',
            lockfileVersion: lockfileResolution.lockfileVersion
          };

          advisories.push(advisoryRecord);

          // Build canonical VULNEX Common Finding
          const finding = this._buildCommonFinding({
            advisory: advisoryRecord,
            relativeLockfilePath,
            primaryId
          });

          if (finding) {
            findings.push(finding);
          }
        }
      } else {
        // Transitive cascade without nested advisory object in `via` (e.g. via: ["depName"])
        // Only record if this package itself has a distinct vulnerable range
        const rawSeverity = vulnEntry.severity || 'moderate';
        const severity = findingNormalizer.mapSeverity(rawSeverity);
        const viaNames = viaList.map(String).join(', ');
        const advisoryTitle = `Vulnerable dependency ${packageName} affected via ${viaNames || 'transitive chain'}`;

        const advisoryRecord = {
          packageName,
          title: advisoryTitle,
          vulnerableVersions: vulnerableRange,
          installedVersion,
          severity,
          rawSeverity,
          isDirect,
          dependencyPath,
          nodes,
          effects,
          fixAvailable: {
            hasFix,
            fixPackage,
            fixVersion,
            isSemVerMajor
          },
          advisoryUrl: null,
          ghsaId: null,
          cveId: null,
          cves: [],
          cwe: [],
          cvss: null,
          source: 'npm-audit',
          lockfileVersion: lockfileResolution.lockfileVersion
        };

        advisories.push(advisoryRecord);

        const finding = this._buildCommonFinding({
          advisory: advisoryRecord,
          relativeLockfilePath,
          primaryId: `transitive-${packageName}`
        });

        if (finding) {
          findings.push(finding);
        }
      }
    }
  }

  /**
   * Internal parser for legacy npm v6 (advisories dictionary) format
   * @private
   */
  _parseV1Report(auditData, lockfile, relativeLockfilePath, advisories, findings, errors) {
    const rawAdvisories = auditData.advisories || {};

    for (const [id, adv] of Object.entries(rawAdvisories)) {
      if (!adv || typeof adv !== 'object') continue;

      const packageName = adv.module_name || 'unknown-package';
      const advisoryTitle = adv.title || `Advisory ${id} in ${packageName}`;
      const vulnerableRange = adv.vulnerable_versions || 'unknown';
      const advisoryUrl = adv.url || null;
      const rawSeverity = adv.severity || 'moderate';
      const severity = findingNormalizer.mapSeverity(rawSeverity);
      const ghsaId = this.extractGhsa(advisoryUrl);
      const cves = Array.isArray(adv.cves) ? adv.cves : this.extractCves(adv.overview || '');
      const cveId = cves[0] || null;
      const primaryId = ghsaId || cveId || String(id);

      // Extract path findings from v1 findings array
      const rawFindings = Array.isArray(adv.findings) ? adv.findings : [];
      const firstFinding = rawFindings[0] || {};
      const installedVersionFromFinding = firstFinding.version || null;
      const paths = Array.isArray(firstFinding.paths) ? firstFinding.paths : [];
      const dependencyPath = paths[0] ? paths[0].replace(/>/g, ' > ') : packageName;

      // Lockfile resolution
      const lockfileRes = this.resolveFromLockfile(lockfile, packageName, paths.map(p => `node_modules/${p.replace(/>/g, '/node_modules/')}`));
      const installedVersion = installedVersionFromFinding || lockfileRes.installedVersion;
      const isDirect = paths.length > 0 ? !paths[0].includes('>') : true;

      const hasFix = Boolean(adv.patched_versions && adv.patched_versions !== '<0.0.0');
      const fixVersion = hasFix ? String(adv.patched_versions) : null;

      const advisoryRecord = {
        packageName,
        title: advisoryTitle,
        vulnerableVersions: vulnerableRange,
        installedVersion,
        severity,
        rawSeverity,
        isDirect,
        dependencyPath,
        nodes: paths,
        effects: [],
        fixAvailable: {
          hasFix,
          fixPackage: packageName,
          fixVersion,
          isSemVerMajor: false
        },
        advisoryUrl,
        ghsaId,
        cveId,
        cves,
        cwe: adv.cwe ? [adv.cwe] : [],
        cvss: adv.cvss || null,
        source: 'npm-audit',
        lockfileVersion: lockfileRes.lockfileVersion
      };

      advisories.push(advisoryRecord);

      const finding = this._buildCommonFinding({
        advisory: advisoryRecord,
        relativeLockfilePath,
        primaryId
      });

      if (finding) {
        findings.push(finding);
      }
    }
  }

  /**
   * Build a Common Finding entity adhering to CommonFindingSchema
   * @private
   */
  _buildCommonFinding({ advisory, relativeLockfilePath, primaryId }) {
    const rule = `npm-audit:${advisory.packageName}:${primaryId}`;
    const evidenceStr = `${advisory.packageName}@${advisory.installedVersion || 'unknown'} (${advisory.vulnerableVersions}) via ${advisory.dependencyPath}`;
    const message = `${advisory.title} (${advisory.packageName}@${advisory.installedVersion || advisory.vulnerableVersions})`;

    const references = [];
    if (advisory.advisoryUrl) references.push(advisory.advisoryUrl);
    if (Array.isArray(advisory.cves)) {
      advisory.cves.forEach(cve => {
        references.push(`https://nvd.nist.gov/vuln/detail/${cve}`);
      });
    }

    // Stable deterministic fingerprint
    const fingerprint = findingNormalizer.generateFingerprint({
      rule,
      path: relativeLockfilePath,
      evidence: evidenceStr,
      message,
      metadata: advisory
    });

    const findingCandidate = {
      rule,
      path: relativeLockfilePath,
      startLine: 1,
      endLine: 1,
      message,
      evidence: evidenceStr,
      severity: advisory.severity,
      confidence: 'HIGH', // Official dependency advisory match is high confidence
      fingerprint,
      scanner: 'npm-audit',
      category: 'VULNERABLE_DEPENDENCY',
      title: advisory.title,
      references,
      metadata: advisory
    };

    const validation = validateCommonFinding(findingCandidate);
    if (validation.success) {
      return validation.data;
    }

    return findingCandidate;
  }
}

// Singleton export
const npmAuditParser = new NpmAuditParser();
npmAuditParser.NpmAuditParser = NpmAuditParser;

module.exports = npmAuditParser;
