/**
 * VULNEX Validators Barrel
 * Central access point for all request, entity, and scanner validation schemas.
 */

const canonical = require('./canonical.schema');
const semgrep = require('./semgrep.schema');

module.exports = {
  ...canonical,
  semgrep
};
