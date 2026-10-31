const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const npmAuditParser = require('../src/services/npmAudit.parser');
const { validateCommonFinding, validateCommonFindings } = require('../src/validators/commonFinding.schema');

describe('VULNEX npm Audit JSON Parser', () => {
  const fixturesDir = path.join(__dirname, 'fixtures');

  const multipleJson = fs.readFileSync(path.join(fixturesDir, 'npm-audit-multiple.json'), 'utf8');
  const transitiveJson = fs.readFileSync(path.join(fixturesDir, 'npm-audit-transitive.json'), 'utf8');
  const fixAvailableJson = fs.readFileSync(path.join(fixturesDir, 'npm-audit-fix-available.json'), 'utf8');
  const emptyJson = fs.readFileSync(path.join(fixturesDir, 'npm-audit-empty.json'), 'utf8');
  const malformedJson = fs.readFileSync(path.join(fixturesDir, 'npm-audit-malformed.json'), 'utf8');
  const sampleLockfile = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'sample-package-lock.json'), 'utf8'));

  // --------------------------------------------------------------------------
  // 1. Multiple Advisories & Field Extraction
  // --------------------------------------------------------------------------
  describe('1. Multiple Advisories & Complete Field Extraction', () => {
    it('should parse recorded multiple advisories fixture and extract all required metadata', () => {
      const result = npmAuditParser.parse(multipleJson, {
        lockfile: sampleLockfile
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.isValidJson, true);
      assert.strictEqual(result.advisoriesCount, 2);
      assert.strictEqual(result.findings.length, 2);
      assert.strictEqual(result.errors.length, 0);

      // Verify minimist advisory
      const minimistAdv = result.advisories.find(a => a.packageName === 'minimist');
      assert.ok(minimistAdv, 'minimist advisory must be extracted');
      assert.strictEqual(minimistAdv.packageName, 'minimist');
      assert.strictEqual(minimistAdv.vulnerableVersions, '<0.2.1 || >=1.0.0 <1.2.3');
      assert.strictEqual(minimistAdv.installedVersion, '0.0.8', 'Installed version must be resolved from lockfile');
      assert.strictEqual(minimistAdv.severity, 'CRITICAL');
      assert.strictEqual(minimistAdv.isDirect, false);
      assert.strictEqual(minimistAdv.dependencyPath, 'mkdirp > minimist');
      assert.strictEqual(minimistAdv.fixAvailable.hasFix, true);
      assert.strictEqual(minimistAdv.fixAvailable.fixPackage, 'mkdirp');
      assert.strictEqual(minimistAdv.fixAvailable.fixVersion, '1.0.4');
      assert.strictEqual(minimistAdv.fixAvailable.isSemVerMajor, true);
      assert.strictEqual(minimistAdv.ghsaId, 'GHSA-VH95-RMGR-6W4M');
      assert.ok(minimistAdv.advisoryUrl.includes('GHSA-vh95-rmgr-6w4m'));
      assert.deepStrictEqual(minimistAdv.cwe, ['CWE-1321']);
      assert.strictEqual(minimistAdv.cvss.score, 9.8);
      assert.strictEqual(minimistAdv.lockfileVersion, 3);

      // Verify axios advisory
      const axiosAdv = result.advisories.find(a => a.packageName === 'axios');
      assert.ok(axiosAdv, 'axios advisory must be extracted');
      assert.strictEqual(axiosAdv.packageName, 'axios');
      assert.strictEqual(axiosAdv.installedVersion, '0.21.0');
      assert.strictEqual(axiosAdv.severity, 'HIGH');
      assert.strictEqual(axiosAdv.isDirect, true);
      assert.strictEqual(axiosAdv.dependencyPath, 'axios');
      assert.strictEqual(axiosAdv.fixAvailable.hasFix, true);
      assert.strictEqual(axiosAdv.fixAvailable.fixVersion, '0.21.1');
      assert.strictEqual(axiosAdv.fixAvailable.isSemVerMajor, false);
      assert.strictEqual(axiosAdv.ghsaId, 'GHSA-42XW-2XVC-BB8X');

      // Verify Common Finding Schema validation
      result.findings.forEach(f => {
        assert.strictEqual(f.scanner, 'npm-audit');
        assert.strictEqual(f.category, 'VULNERABLE_DEPENDENCY');
        assert.strictEqual(f.confidence, 'HIGH');
        assert.ok(f.path.includes('package-lock.json'));
        assert.strictEqual(f.startLine, 1);
        assert.strictEqual(f.endLine, 1);
        assert.ok(typeof f.fingerprint === 'string' && f.fingerprint.length === 64);

        const val = validateCommonFinding(f);
        assert.strictEqual(val.success, true, `Schema validation failed: ${val.error?.message}`);
      });
    });
  });

  // --------------------------------------------------------------------------
  // 2. Transitive Dependencies
  // --------------------------------------------------------------------------
  describe('2. Transitive Dependency Inspection', () => {
    it('should correctly format deep transitive dependency paths and identify non-direct dependencies', () => {
      const result = npmAuditParser.parse(transitiveJson, {
        lockfile: sampleLockfile
      });

      assert.strictEqual(result.success, true);
      const minimist = result.advisories.find(a => a.packageName === 'minimist');
      assert.ok(minimist);
      assert.strictEqual(minimist.isDirect, false);
      assert.strictEqual(minimist.dependencyPath, 'express > mkdirp > minimist');
      assert.strictEqual(minimist.installedVersion, '0.0.8');
    });
  });

  // --------------------------------------------------------------------------
  // 3. Fix Availability
  // --------------------------------------------------------------------------
  describe('3. Fix Availability & Semver Details', () => {
    it('should extract fix package, version, and semver major flag', () => {
      const result = npmAuditParser.parse(fixAvailableJson, {
        lockfile: sampleLockfile
      });

      assert.strictEqual(result.success, true);
      const semverAdv = result.advisories.find(a => a.packageName === 'semver');
      assert.ok(semverAdv);
      assert.strictEqual(semverAdv.installedVersion, '6.1.0');
      assert.strictEqual(semverAdv.fixAvailable.hasFix, true);
      assert.strictEqual(semverAdv.fixAvailable.fixPackage, 'semver');
      assert.strictEqual(semverAdv.fixAvailable.fixVersion, '7.5.2');
      assert.strictEqual(semverAdv.fixAvailable.isSemVerMajor, false);
      assert.strictEqual(semverAdv.severity, 'MEDIUM'); // moderate mapped to MEDIUM
    });
  });

  // --------------------------------------------------------------------------
  // 4. Empty Results vs Malformed Output
  // --------------------------------------------------------------------------
  describe('4. Empty Results vs Malformed Output', () => {
    it('should distinguish clean zero-vulnerability audit from error states', () => {
      const result = npmAuditParser.parse(emptyJson);

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.isValidJson, true);
      assert.strictEqual(result.advisoriesCount, 0);
      assert.strictEqual(result.findings.length, 0);
      assert.strictEqual(result.errors.length, 0);
      assert.ok(result.metadata);
      assert.strictEqual(result.metadata.vulnerabilitiesSummary.total, 0);
      assert.strictEqual(result.metadata.totalDependencies, 15);
    });

    it('should handle malformed JSON gracefully without throwing unhandled exceptions', () => {
      const result = npmAuditParser.parse(malformedJson);

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.isValidJson, false);
      assert.strictEqual(result.advisoriesCount, 0);
      assert.strictEqual(result.findings.length, 0);
      assert.ok(result.errors.length > 0);
      assert.ok(result.errors[0].includes('Failed to parse npm audit JSON'));
      assert.strictEqual(result.metadata, null);
    });

    it('should handle null, undefined, and empty string safely', () => {
      const nullRes = npmAuditParser.parse(null);
      assert.strictEqual(nullRes.success, false);
      assert.strictEqual(nullRes.isValidJson, false);

      const emptyRes = npmAuditParser.parse('');
      assert.strictEqual(emptyRes.success, false);
      assert.strictEqual(emptyRes.isValidJson, false);
    });
  });

  // --------------------------------------------------------------------------
  // 5. Lockfile Version Compatibility (v1, v2, v3)
  // --------------------------------------------------------------------------
  describe('5. Lockfile Version Compatibility', () => {
    it('should resolve dependencies from lockfileVersion 1 (nested dependencies tree)', () => {
      const lockfileV1 = {
        name: 'v1-project',
        lockfileVersion: 1,
        dependencies: {
          mkdirp: {
            version: '0.5.1',
            dependencies: {
              minimist: {
                version: '0.0.8'
              }
            }
          }
        }
      };

      const res = npmAuditParser.resolveFromLockfile(
        lockfileV1,
        'minimist',
        ['node_modules/mkdirp/node_modules/minimist']
      );

      assert.strictEqual(res.installedVersion, '0.0.8');
      assert.strictEqual(res.lockfileVersion, 1);
    });

    it('should resolve dependencies from lockfileVersion 2 & 3 (packages dictionary)', () => {
      const lockfileV3 = {
        name: 'v3-project',
        lockfileVersion: 3,
        packages: {
          'node_modules/lodash': {
            version: '4.17.20',
            dev: true
          }
        }
      };

      const res = npmAuditParser.resolveFromLockfile(
        lockfileV3,
        'lodash',
        ['node_modules/lodash']
      );

      assert.strictEqual(res.installedVersion, '4.17.20');
      assert.strictEqual(res.isDev, true);
      assert.strictEqual(res.lockfileVersion, 3);
    });

    it('should safely return null when lockfile is omitted or package is unlisted', () => {
      const res = npmAuditParser.resolveFromLockfile(null, 'non-existent');
      assert.strictEqual(res.installedVersion, null);
      assert.strictEqual(res.lockfileVersion, null);
    });
  });

  // --------------------------------------------------------------------------
  // 6. Legacy npm v6 Format Support
  // --------------------------------------------------------------------------
  describe('6. Legacy npm v6 Format Support', () => {
    it('should parse npm v6 advisories dictionary format', () => {
      const v1Report = {
        advisories: {
          '1096464': {
            id: 1096464,
            title: 'Prototype Pollution in minimist',
            module_name: 'minimist',
            overview: 'Prototype pollution in minimist before 0.2.1',
            recommendation: 'Upgrade to version 0.2.1 or later',
            severity: 'critical',
            vulnerable_versions: '<0.2.1 || >=1.0.0 <1.2.3',
            patched_versions: '>=0.2.1 <1.0.0 || >=1.2.3',
            url: 'https://github.com/advisories/GHSA-vh95-rmgr-6w4m',
            cves: ['CVE-2020-7598'],
            cwe: 'CWE-1321',
            findings: [
              {
                version: '0.0.8',
                paths: ['mkdirp>minimist']
              }
            ]
          }
        },
        metadata: {
          vulnerabilities: {
            critical: 1,
            total: 1
          }
        }
      };

      const result = npmAuditParser.parse(v1Report);
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.advisoriesCount, 1);
      assert.strictEqual(result.findings.length, 1);

      const adv = result.advisories[0];
      assert.strictEqual(adv.packageName, 'minimist');
      assert.strictEqual(adv.installedVersion, '0.0.8');
      assert.strictEqual(adv.severity, 'CRITICAL');
      assert.strictEqual(adv.dependencyPath, 'mkdirp > minimist');
      assert.strictEqual(adv.ghsaId, 'GHSA-VH95-RMGR-6W4M');
      assert.deepStrictEqual(adv.cves, ['CVE-2020-7598']);
    });
  });

  // --------------------------------------------------------------------------
  // 7. Non-Zero Exit Code Handling
  // --------------------------------------------------------------------------
  describe('7. Process Exit Code Handling', () => {
    it('should successfully parse valid JSON even when npm audit exits with non-zero exit code', () => {
      // npm audit exits with code 1 when vulnerabilities are detected
      const result = npmAuditParser.parse(multipleJson, {
        exitCode: 1,
        lockfile: sampleLockfile
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.isValidJson, true);
      assert.strictEqual(result.findings.length, 2);
    });
  });

  // --------------------------------------------------------------------------
  // 8. Deterministic Fingerprints & Common Schema Compliance
  // --------------------------------------------------------------------------
  describe('8. Fingerprint Stability & Canonical Contracts', () => {
    it('should generate stable deterministic fingerprints across repeated parse runs', () => {
      const res1 = npmAuditParser.parse(multipleJson, { lockfile: sampleLockfile });
      const res2 = npmAuditParser.parse(multipleJson, { lockfile: sampleLockfile });

      assert.strictEqual(res1.findings.length, 2);
      assert.strictEqual(res2.findings.length, 2);

      assert.strictEqual(
        res1.findings[0].fingerprint,
        res2.findings[0].fingerprint,
        'Fingerprints must match across repeated runs'
      );
      assert.strictEqual(
        res1.findings[1].fingerprint,
        res2.findings[1].fingerprint,
        'Fingerprints must match across repeated runs'
      );
      assert.notStrictEqual(
        res1.findings[0].fingerprint,
        res1.findings[1].fingerprint,
        'Different dependencies must produce distinct fingerprints'
      );
    });

    it('should pass collection validation with validateCommonFindings', () => {
      const result = npmAuditParser.parse(multipleJson, { lockfile: sampleLockfile });
      const val = validateCommonFindings(result.findings);
      assert.strictEqual(val.success, true);
    });
  });

  // --------------------------------------------------------------------------
  // 9. Read-Only Safety Invariant (Requirement 10)
  // --------------------------------------------------------------------------
  describe('9. Read-Only Lockfile Safety', () => {
    it('should not modify lockfile on disk during parsing', () => {
      const lockfilePath = path.join(fixturesDir, 'sample-package-lock.json');
      const originalStat = fs.statSync(lockfilePath);
      const originalContent = fs.readFileSync(lockfilePath, 'utf8');

      const result = npmAuditParser.parse(multipleJson, {
        lockfilePath
      });

      assert.strictEqual(result.success, true);

      const afterStat = fs.statSync(lockfilePath);
      const afterContent = fs.readFileSync(lockfilePath, 'utf8');

      assert.strictEqual(originalContent, afterContent, 'Lockfile content must remain identical');
      assert.strictEqual(originalStat.size, afterStat.size, 'Lockfile size must remain identical');
    });
  });
});
