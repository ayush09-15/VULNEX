const {
  parseAndValidateAIInvestigation,
  createFallbackInvestigation
} = require('../validators/investigation.schema');
const {
  PROMPT_VERSION,
  redactSecrets,
  buildInvestigationPrompt
} = require('./ai.prompt');
const {
  GoogleAIModelAdapter,
  AIQuotaExceededError,
  AITimeoutError
} = require('./ai.adapter');
const config = require('../config/env');

/**
 * AI Service for VULNEX
 * Handles evidence-bounded AI vulnerability investigation, root-cause diagnosis,
 * and automated security patch generation via configured model adapter.
 */
class AIService {
  constructor(options = {}) {
    this.apiKey = options.apiKey !== undefined ? options.apiKey : config.ai.apiKey;
    this.model = options.model || config.ai.model || 'gemma-2-9b-it';
    this.timeoutMs = options.timeoutMs !== undefined ? options.timeoutMs : config.ai.timeoutMs;
    this.promptVersion = PROMPT_VERSION;

    // Server-side model adapter instance
    this.adapter = new GoogleAIModelAdapter({
      apiKey: this.apiKey,
      model: this.model,
      timeoutMs: this.timeoutMs
    });
  }

  /**
   * Return active model metadata without leaking secrets
   */
  getModelInfo() {
    return this.adapter.getModelInfo();
  }

  /**
   * Constructs an evidence-bounded investigation prompt for a finding.
   *
   * @param {Object} finding
   * @param {string|Object} codeContext
   * @param {Object} [options={}]
   * @returns {Object} Structured prompt payload
   */
  buildInvestigationPrompt(finding, codeContext = '', options = {}) {
    return buildInvestigationPrompt(finding, codeContext, options);
  }

  /**
   * Analyze a vulnerability finding using evidence-bounded AI investigation.
   *
   * @param {Object} finding
   * @param {string|Object} codeContext
   * @returns {Promise<Object>}
   */
  async analyzeVulnerability(finding, codeContext = '') {
    if (this.adapter.isAvailable()) {
      try {
        return await this._callGeminiAnalysis(finding, codeContext);
      } catch (err) {
        console.warn('[AIService] Remote AI model call failed, falling back to local analysis:', err.message);

        // If quota exceeded or timeout occurred, produce structured fallback with explicit limitation
        if (err instanceof AIQuotaExceededError || err instanceof AITimeoutError) {
          return createFallbackInvestigation({
            findingId: finding?.id || 'finding_unknown',
            reason: `AI model unavailable: ${err.message}`,
            model: this.model,
            promptVersion: this.promptVersion,
            finding
          });
        }
      }
    }

    // Heuristic fallback analysis when API key is not configured or remote fails
    const localOutput = this._localAnalysis(finding, codeContext);
    return {
      ...localOutput,
      findingId: finding?.id || 'finding_unknown',
      modelUsed: 'vulnex-heuristic-engine-v1',
      promptVersion: this.promptVersion,
      analyzedAt: new Date().toISOString()
    };
  }

  /**
   * Process and validate an AI investigation response safely.
   * If the model output is malformed or invalid, constructs a schema-compliant fallback.
   * Never throws uncaught exceptions.
   *
   * @param {string|object} rawOutput
   * @param {object} [finding=null]
   * @returns {object} Safe investigation data
   */
  processInvestigationResponse(rawOutput, finding = null) {
    const parseResult = parseAndValidateAIInvestigation(rawOutput);
    if (parseResult.success) {
      return {
        ...parseResult.data,
        findingId: finding?.id || 'finding_unknown',
        modelUsed: this.model,
        promptVersion: this.promptVersion,
        isFallback: false
      };
    }

    return createFallbackInvestigation({
      findingId: finding?.id || 'finding_unknown',
      reason: `AI output validation failed: ${parseResult.error?.message || 'malformed response'}`,
      model: this.model,
      promptVersion: this.promptVersion,
      finding
    });
  }

  /**
   * Generate an automated security patch for a finding
   * @param {Object} finding
   * @param {string} originalCode
   * @returns {Promise<Object>}
   */
  async generatePatch(finding, originalCode = '') {
    if (this.adapter.isAvailable()) {
      try {
        return await this._callGeminiPatch(finding, originalCode);
      } catch (err) {
        console.warn('[AIService] Remote AI call failed, falling back to local patch generator:', err.message);
      }
    }

    return this._localPatchGeneration(finding, originalCode);
  }

  /**
   * Local heuristic analysis engine that produces schema-compliant
   * evidence-bounded investigation output.
   */
  _localAnalysis(finding, codeContext = '') {
    const categoryKey = (finding.category || finding.cwe || '').toUpperCase();

    const analysisMap = {
      'CWE-89': {
        summary: 'Dynamic SQL construction with unsanitized parameters allows attackers to alter query logic.',
        exploitVector: 'Network / Unauthenticated HTTP input',
        impact: 'Complete database compromise, data leakage, and potential data modification.',
        mitigation: 'Convert string interpolation into parameterized statements or use an ORM with prepared bindings.',
        severity: 'HIGH'
      },
      'SQL_INJECTION': {
        summary: 'Dynamic SQL construction with unsanitized parameters allows attackers to alter query logic.',
        exploitVector: 'Network / Unauthenticated HTTP input',
        impact: 'Complete database compromise, data leakage, and potential data modification.',
        mitigation: 'Convert string interpolation into parameterized statements or use an ORM with prepared bindings.',
        severity: 'HIGH'
      },
      'CWE-78': {
        summary: 'Passing untrusted input directly into a system shell via exec() or eval().',
        exploitVector: 'Remote code execution via command separator injection (e.g., ; && |).',
        impact: 'Complete server host takeover and lateral movement.',
        mitigation: 'Use child_process.execFile with an array of arguments, or avoid OS shell calls entirely.',
        severity: 'CRITICAL'
      },
      'COMMAND_INJECTION': {
        summary: 'Passing untrusted input directly into a system shell via exec() or eval().',
        exploitVector: 'Remote code execution via command separator injection (e.g., ; && |).',
        impact: 'Complete server host takeover and lateral movement.',
        mitigation: 'Use child_process.execFile with an array of arguments, or avoid OS shell calls entirely.',
        severity: 'CRITICAL'
      },
      'CWE-798': {
        summary: 'Secret credentials, API tokens, or encryption keys hardcoded in source control.',
        exploitVector: 'Credential harvesting from public or leaked repositories.',
        impact: 'Unauthorized access to downstream cloud services and API abuse.',
        mitigation: 'Move keys to environment variables and utilize secret management systems (e.g. AWS Secrets Manager, Vault).',
        severity: 'HIGH'
      },
      'HARDCODED_SECRET': {
        summary: 'Secret credentials, API tokens, or encryption keys hardcoded in source control.',
        exploitVector: 'Credential harvesting from public or leaked repositories.',
        impact: 'Unauthorized access to downstream cloud services and API abuse.',
        mitigation: 'Move keys to environment variables and utilize secret management systems (e.g. AWS Secrets Manager, Vault).',
        severity: 'HIGH'
      },
      'CWE-22': {
        summary: 'Path traversal via path.join or file operations lacking path confinement.',
        exploitVector: 'Directory traversal using ../ sequences in user input.',
        impact: 'Unauthorized reading or overwriting of sensitive system files.',
        mitigation: 'Sanitize path segments, reject directory separators, and verify that path.resolve stays within allowed base directory.',
        severity: 'HIGH'
      },
      'PATH_TRAVERSAL': {
        summary: 'Path traversal via path.join or file operations lacking path confinement.',
        exploitVector: 'Directory traversal using ../ sequences in user input.',
        impact: 'Unauthorized reading or overwriting of sensitive system files.',
        mitigation: 'Sanitize path segments, reject directory separators, and verify that path.resolve stays within allowed base directory.',
        severity: 'HIGH'
      }
    };

    const details = analysisMap[categoryKey] || analysisMap[finding.cwe] || {
      summary: `Detected pattern matching security rule: ${finding.title || finding.name || 'Security Finding'}`,
      exploitVector: 'Standard web application attack vector',
      impact: finding.description || 'Potential security risk to application confidentiality and integrity.',
      mitigation: finding.remediation || 'Sanitize input and follow secure coding best practices.',
      severity: finding.severity || 'MEDIUM'
    };

    const rawEvidence = finding.evidence || finding.codeSnippet || (typeof codeContext === 'string' ? codeContext.slice(0, 200) : '');
    const cleanEvidence = rawEvidence ? [redactSecrets(rawEvidence)] : ['[Static scanner evidence matching rule]'];

    return {
      assessment: 'LIKELY_TRUE',
      severity: (finding.severity || details.severity || 'HIGH').toUpperCase(),
      summary: details.summary,
      evidence: cleanEvidence,
      preconditions: [details.exploitVector],
      potentialImpact: details.impact,
      recommendedFix: details.mitigation,
      confidence: 'MEDIUM',
      limitations: [
        'Local deterministic analysis generated without live remote LLM inference',
        'Analysis bounded to finding metadata and available code snippet'
      ]
    };
  }

  /**
   * Local heuristic patch generator
   */
  _localPatchGeneration(finding, originalCode) {
    let patchedCode = originalCode;
    let explanation = 'Applied standard secure coding pattern for ' + (finding.cwe || 'vulnerability');

    if (finding.cwe === 'CWE-89' && originalCode.includes('${')) {
      patchedCode = originalCode.replace(/\$\{([^}]+)\}/g, '?');
      explanation = 'Replaced string interpolation with parameterized SQL query placeholders.';
    } else if (finding.cwe === 'CWE-798') {
      patchedCode = originalCode.replace(/['"`][A-Za-z0-9_\-\.]{16,}['"`]/, 'process.env.SECRET_KEY');
      explanation = 'Replaced hardcoded secret literal with process.env.SECRET_KEY.';
    } else if (finding.cwe === 'CWE-328') {
      patchedCode = originalCode.replace(/'md5'|"md5"/g, "'sha256'");
      explanation = 'Upgraded weak MD5 hashing algorithm to secure SHA-256.';
    }

    return {
      findingId: finding.id,
      originalCode,
      patchedCode,
      explanation: 'AI-generated fix via ' + this.model,
      generatedAt: new Date().toISOString()
    };
  }

  async _callGeminiAnalysis(finding, codeContext) {
    const promptPayload = this.buildInvestigationPrompt(finding, codeContext);

    const completion = await this.adapter.generateCompletion({
      systemInstruction: promptPayload.systemInstruction,
      userPrompt: promptPayload.userPrompt,
      jsonMode: true
    });

    const processed = this.processInvestigationResponse(completion.text, finding);
    return {
      ...processed,
      modelUsed: this.model,
      promptVersion: promptPayload.promptVersion,
      contextSupplied: promptPayload.contextSupplied
    };
  }

  async _callGeminiPatch(finding, originalCode) {
    const prompt = `Fix this security vulnerability:
Vulnerability: ${finding.name || finding.title} (${finding.cwe || finding.category})
Code:
${originalCode || finding.codeSnippet}

Provide the patched code and explanation.`;

    const completion = await this.adapter.generateCompletion({
      userPrompt: prompt,
      jsonMode: false
    });

    return {
      findingId: finding.id,
      modelUsed: this.model,
      patchedCode: completion.text,
      explanation: 'AI-generated fix via ' + this.model,
      generatedAt: new Date().toISOString()
    };
  }
}

const aiService = new AIService();
aiService.AIService = AIService;
aiService.buildInvestigationPrompt = buildInvestigationPrompt;

module.exports = aiService;
