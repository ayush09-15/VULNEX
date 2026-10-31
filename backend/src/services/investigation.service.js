/**
 * VULNEX Investigation Service
 *
 * Implements:
 * - Master Antigravity Execution Bible Section 4.7 (Canonical Investigation Endpoints)
 * - Section 4.9 (Investigation Entity Schema & Persistence)
 * - Section 4.10 (Finding State Machine: DETECTED -> TRIAGED)
 * - Section 8.4 & 8.5 (Structured AI Result & Provenance)
 */

const crypto = require('crypto');
const aiService = require('./ai.service');
const { scanOrchestrator } = require('../orchestrator/scanOrchestrator');
const scannerService = require('./scanner.service');
const { getFileExcerpt } = require('./inventory.service');
const {
  validateInvestigation,
  AI_ASSESSMENTS,
  AI_CONFIDENCES
} = require('../validators/investigation.schema');

// In-memory investigation stores (keyed by investigationId and findingId)
const investigationsStore = new Map();
const investigationsByFinding = new Map();

class InvestigationService {
  /**
   * Save and persist an investigation entity
   * @param {Object} investigationData
   * @returns {Object} Validated canonical investigation entity
   */
  saveInvestigation(investigationData) {
    if (!investigationData || typeof investigationData !== 'object') {
      throw new Error('Invalid investigation data: Object required');
    }

    const findingId = investigationData.findingId;
    if (!findingId) {
      throw new Error('Invalid investigation: findingId is required');
    }

    const id = investigationData.id || `inv_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const model = investigationData.model || investigationData.modelUsed || aiService.model || 'gemma-4-26b-a4b-it';
    const promptVersion = investigationData.promptVersion || aiService.promptVersion || '1.0.0';

    const entity = {
      id,
      findingId,
      model,
      promptVersion,
      assessment: investigationData.assessment || AI_ASSESSMENTS.UNCERTAIN,
      explanation: investigationData.explanation || investigationData.summary || 'Investigation completed.',
      impact: investigationData.impact || investigationData.potentialImpact || 'Potential security impact.',
      recommendation: investigationData.recommendation || investigationData.recommendedFix || 'Apply defensive remediation.',
      confidence: investigationData.confidence || AI_CONFIDENCES.LOW,
      evidence: Array.isArray(investigationData.evidence) ? investigationData.evidence : [],
      preconditions: Array.isArray(investigationData.preconditions) ? investigationData.preconditions : [],
      limitations: Array.isArray(investigationData.limitations) ? investigationData.limitations : [],
      createdAt: investigationData.createdAt || new Date().toISOString()
    };

    // Attach provenance metadata if available
    if (investigationData.provenance) {
      entity.provenance = investigationData.provenance;
    }

    // Validate against canonical entity schema
    const validation = validateInvestigation(entity);
    if (!validation.success) {
      const issueMsgs = validation.error.issues?.map(i => `${i.path.join('.')}: ${i.message}`).join(', ');
      throw new Error(`Investigation entity failed validation: ${issueMsgs}`);
    }

    const validated = validation.data;
    if (entity.provenance) {
      validated.provenance = entity.provenance;
    }

    investigationsStore.set(validated.id, validated);
    investigationsByFinding.set(findingId, validated);

    return validated;
  }

  /**
   * Retrieve investigation by investigation ID
   * @param {string} id
   * @returns {Object|null}
   */
  getInvestigationById(id) {
    return investigationsStore.get(id) || null;
  }

  /**
   * Retrieve latest investigation for a specific finding ID
   * @param {string} findingId
   * @returns {Object|null}
   */
  getInvestigationByFindingId(findingId) {
    return investigationsByFinding.get(findingId) || null;
  }

  /**
   * List all stored investigations with optional filtering
   * @param {Object} [filters={}]
   * @returns {Array<Object>}
   */
  listInvestigations(filters = {}) {
    let list = Array.from(investigationsStore.values());

    if (filters.assessment) {
      list = list.filter(i => i.assessment.toUpperCase() === filters.assessment.toUpperCase());
    }
    if (filters.confidence) {
      list = list.filter(i => String(i.confidence).toUpperCase() === String(filters.confidence).toUpperCase());
    }
    if (filters.model) {
      list = list.filter(i => i.model.toLowerCase() === filters.model.toLowerCase());
    }

    return list;
  }

  /**
   * Conduct an evidence-bounded AI investigation on a finding,
   * persist the investigation entity, and transition finding state to TRIAGED.
   *
   * @param {string} findingId
   * @param {Object} [options={}]
   * @param {string} [options.codeContext]
   * @returns {Promise<{ investigation: Object, finding: Object }>}
   */
  async investigateFinding(findingId, options = {}) {
    // 1. Locate finding across stores
    const finding = scanOrchestrator.getFindingById(findingId) || scannerService.getFindingById(findingId);
    if (!finding) {
      return null;
    }

    // 2. Resolve code context (options -> workspace excerpt -> finding evidence)
    let codeContext = options.codeContext || '';

    if (!codeContext && finding.scanId && finding.filePath) {
      const scan = (typeof scanOrchestrator.getScan === 'function' ? scanOrchestrator.getScan(finding.scanId) : null) ||
                   (typeof scannerService.getScan === 'function' ? scannerService.getScan(finding.scanId) : null);
      if (scan && scan.workspacePath) {
        try {
          const excerptResult = getFileExcerpt(
            scan.workspacePath,
            finding.filePath,
            finding.startLine || 1,
            finding.endLine || finding.startLine || 1,
            { contextLines: 5 }
          );
          codeContext = excerptResult?.excerpt || '';
        } catch {
          // If workspace file read fails, smoothly fall back to finding.evidence
        }
      }
    }

    if (!codeContext) {
      codeContext = finding.evidence || finding.codeSnippet || '';
    }

    // 3. Invoke evidence-bounded AI investigation
    const rawAnalysis = await aiService.analyzeVulnerability(finding, codeContext);

    // 4. Assemble canonical Investigation entity with scanner provenance
    const investigationEntity = this.saveInvestigation({
      findingId: finding.id,
      model: rawAnalysis.modelUsed || aiService.model,
      promptVersion: rawAnalysis.promptVersion || aiService.promptVersion,
      assessment: rawAnalysis.assessment,
      explanation: rawAnalysis.summary || rawAnalysis.explanation,
      impact: rawAnalysis.potentialImpact || rawAnalysis.impact,
      recommendation: rawAnalysis.recommendedFix || rawAnalysis.recommendation,
      confidence: rawAnalysis.confidence,
      evidence: rawAnalysis.evidence || (finding.evidence ? [finding.evidence] : []),
      preconditions: rawAnalysis.preconditions || [],
      limitations: rawAnalysis.limitations || [],
      provenance: {
        scanner: finding.scanner || 'semgrep',
        ruleId: finding.ruleId || 'unknown.rule',
        filePath: finding.filePath || finding.file || 'unknown',
        targetLines: [finding.startLine || 1, finding.endLine || 1],
        model: rawAnalysis.modelUsed || aiService.model,
        promptVersion: rawAnalysis.promptVersion || aiService.promptVersion,
        isFallback: Boolean(rawAnalysis.isFallback || rawAnalysis.modelUsed?.includes('fallback') || rawAnalysis.modelUsed?.includes('heuristic')),
        investigatedAt: new Date().toISOString()
      }
    });

    // 5. Transition finding state machine: DETECTED -> TRIAGED
    const updatedFinding = {
      ...finding,
      status: 'TRIAGED',
      investigationId: investigationEntity.id,
      aiAssessment: investigationEntity.assessment,
      aiConfidence: investigationEntity.confidence,
      investigation: investigationEntity,
      triagedAt: new Date().toISOString()
    };

    // Update both orchestrator and scanner stores
    scanOrchestrator.updateFinding(finding.id, updatedFinding);
    scannerService.updateFinding(finding.id, updatedFinding);

    return {
      investigation: investigationEntity,
      finding: updatedFinding
    };
  }

  /**
   * Clear all stored investigations (testing helper)
   */
  clearStore() {
    investigationsStore.clear();
    investigationsByFinding.clear();
  }

  _resetStore() {
    this.clearStore();
  }
}

const investigationService = new InvestigationService();

module.exports = {
  InvestigationService,
  investigationService
};
