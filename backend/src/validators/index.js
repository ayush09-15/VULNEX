/**
 * VULNEX Validators Barrel
 * Central access point for all request, entity, and scanner validation schemas.
 */

const canonical = require('./canonical.schema');
const semgrep = require('./semgrep.schema');
const investigation = require('./investigation.schema');

module.exports = {
  ...canonical,
  semgrep,
  investigation,
  // Direct helpers for investigation
  parseAndValidateAIInvestigation: investigation.parseAndValidateAIInvestigation,
  createFallbackInvestigation: investigation.createFallbackInvestigation,
  extractJsonString: investigation.extractJsonString
};
