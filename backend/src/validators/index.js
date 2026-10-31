/**
 * VULNEX Validators Barrel
 * Central access point for all request, entity, and scanner validation schemas.
 */

const canonical = require('./canonical.schema');
const semgrep = require('./semgrep.schema');
const investigation = require('./investigation.schema');
const commonFinding = require('./commonFinding.schema');

module.exports = {
  ...canonical,
  semgrep,
  investigation,
  commonFinding,
  CommonFindingSchema: commonFinding.CommonFindingSchema,
  validateCommonFinding: commonFinding.validateCommonFinding,
  validateCommonFindings: commonFinding.validateCommonFindings,
  // Direct helpers for investigation
  parseAndValidateAIInvestigation: investigation.parseAndValidateAIInvestigation,
  createFallbackInvestigation: investigation.createFallbackInvestigation,
  extractJsonString: investigation.extractJsonString
};
