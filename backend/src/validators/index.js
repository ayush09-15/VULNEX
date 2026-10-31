/**
 * VULNEX Validators Barrel
 * Central access point for all request, entity, and scanner validation schemas.
 */

const canonical = require('./canonical.schema');
const semgrep = require('./semgrep.schema');
const investigation = require('./investigation.schema');
const commonFinding = require('./commonFinding.schema');
const patchProposal = require('./patchProposal.schema');
const diffValidator = require('./diffValidator');

module.exports = {
  ...canonical,
  semgrep,
  investigation,
  commonFinding,
  patchProposal,
  diffValidator,
  CommonFindingSchema: commonFinding.CommonFindingSchema,
  validateCommonFinding: commonFinding.validateCommonFinding,
  validateCommonFindings: commonFinding.validateCommonFindings,
  // Direct helpers for investigation
  parseAndValidateAIInvestigation: investigation.parseAndValidateAIInvestigation,
  createFallbackInvestigation: investigation.createFallbackInvestigation,
  extractJsonString: investigation.extractJsonString,
  // Direct helpers for patch proposal
  PATCH_REVIEW_STATES: patchProposal.PATCH_REVIEW_STATES,
  PatchReviewStateEnum: patchProposal.PatchReviewStateEnum,
  PatchProposalSchema: patchProposal.PatchProposalSchema,
  CreatePatchProposalSchema: patchProposal.CreatePatchProposalSchema,
  AIPatchRationaleSchema: patchProposal.AIPatchRationaleSchema,
  AIPatchProposalOutputSchema: patchProposal.AIPatchProposalOutputSchema,
  MissingEvidenceLinkError: patchProposal.MissingEvidenceLinkError,
  OutOfScopeProposalError: patchProposal.OutOfScopeProposalError,
  InvalidReviewStateTransitionError: patchProposal.InvalidReviewStateTransitionError,
  validatePatchProposal: patchProposal.validatePatchProposal,
  validateCreatePatchProposal: patchProposal.validateCreatePatchProposal,
  validateProposalScope: patchProposal.validateProposalScope,
  assertProposalScope: patchProposal.assertProposalScope,
  transitionReviewState: patchProposal.transitionReviewState,
  parseUnifiedDiff: patchProposal.parseUnifiedDiff,
  validateUnifiedDiff: patchProposal.validateUnifiedDiff,
  parseAndValidateAIPatchProposal: patchProposal.parseAndValidateAIPatchProposal,
  // Direct helpers for independent diff & path validation
  validateDiffAndPaths: diffValidator.validateDiffAndPaths,
  validateWorkspacePath: diffValidator.validateWorkspacePath,
  assertValidDiff: diffValidator.assertValidDiff,
  DiffValidationError: diffValidator.DiffValidationError,
  WorkspacePathEscapeError: diffValidator.WorkspacePathEscapeError,
  SymlinkEscapeError: diffValidator.SymlinkEscapeError,
  MalformedDiffError: diffValidator.MalformedDiffError,
  InconsistentLineCountError: diffValidator.InconsistentLineCountError,
  DeclaredFilesMismatchError: diffValidator.DeclaredFilesMismatchError,
  OutOfScopeDiffError: diffValidator.OutOfScopeDiffError
};
