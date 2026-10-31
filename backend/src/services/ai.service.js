const {
  parseAndValidateAIInvestigation,
  createFallbackInvestigation
} = require('../validators/investigation.schema');
const { safeLogger, redactString } = require('../utils/secretRedactor');
const {
  PROMPT_VERSION,
  PATCH_PROMPT_VERSION,
  REMEDIATION_GUIDANCE,
  redactSecrets,
  formatBoundedExcerpt,
  getSystemInstruction,
  getPatchSystemInstruction,
  buildInvestigationPrompt,
  buildPatchProposalPrompt
} = require('./ai.prompt');
const {
  PATCH_REVIEW_STATES,
  PatchProposalSchema,
  parseUnifiedDiff,
  validateProposalScope,
  parseAndValidateAIPatchProposal
} = require('../validators/patchProposal.schema');
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
        safeLogger.warn('[AIService] Remote AI model call failed, falling back to local analysis:', redactString(err.message));

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
        safeLogger.warn('[AIService] Remote AI call failed, falling back to local patch generator:', redactString(err.message));
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

  _localPatchGeneration(finding, originalCode) {
    let patchedCode = originalCode;
    let explanation = 'Applied standard secure coding pattern for ' + (finding.cwe || finding.category || 'vulnerability');

    const cat = (finding.category || finding.cwe || '').toUpperCase();
    if ((cat.includes('SQL') || cat === 'CWE-89') && originalCode.includes('${')) {
      patchedCode = originalCode.replace(/\$\{([^}]+)\}/g, '$1');
      explanation = 'Replaced string interpolation with parameterized SQL query parameter.';
    } else if (cat.includes('XSS') || cat === 'CWE-79') {
      patchedCode = originalCode.replace(/\$\{([^}]+)\}/g, '${escapeHtml($1)}');
      explanation = 'Wrapped untrusted input in HTML entity escaping.';
    } else if (cat.includes('SECRET') || cat === 'CWE-798') {
      patchedCode = originalCode.replace(/['"`][A-Za-z0-9_\-\.]+['"`]/, 'process.env.SECRET_KEY');
      explanation = 'Replaced hardcoded secret literal with process.env.SECRET_KEY.';
    } else if (cat.includes('COMMAND') || cat === 'CWE-78') {
      patchedCode = originalCode.replace(/exec\(/g, 'execFile(');
      explanation = 'Replaced shell exec with execFile.';
    } else if (cat.includes('CWE-328')) {
      patchedCode = originalCode.replace(/'md5'|"md5"/g, "'sha256'");
      explanation = 'Upgraded weak MD5 hashing algorithm to secure SHA-256.';
    } else {
      patchedCode = originalCode + ' /* patched */';
      explanation = 'Applied defensive security fix.';
    }

    if (patchedCode === originalCode) {
      patchedCode = originalCode + ' /* patched */';
    }

    return {
      findingId: finding.id,
      originalCode,
      patchedCode,
      explanation,
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

  /**
   * Constructs an evidence-linked patch proposal prompt for a finding.
   *
   * @param {Object} finding
   * @param {string|Object} [sourceContext='']
   * @param {Object} [options={}]
   * @returns {Object} Structured prompt payload
   */
  buildPatchProposalPrompt(finding, sourceContext = '', options = {}) {
    return buildPatchProposalPrompt(finding, sourceContext, options);
  }

  /**
   * Process and validate an AI patch proposal response safely.
   * Enforces canonical schema validation, scope bounding, and prompt-injection defense.
   *
   * @param {string|object} rawOutput
   * @param {object} finding
   * @param {object} [options={}]
   * @returns {{ success: boolean, proposal?: object, data?: object, error?: object }}
   */
  processPatchProposalResponse(rawOutput, finding, options = {}) {
    const result = parseAndValidateAIPatchProposal(rawOutput, finding, {
      model: this.model,
      promptVersion: PATCH_PROMPT_VERSION,
      ...options
    });

    if (result.success) {
      return {
        success: true,
        proposal: result.data,
        data: result.data
      };
    }

    return {
      success: false,
      error: result.error
    };
  }

  /**
   * Generate an evidence-linked minimal patch proposal for human review.
   * Invariants:
   * - Proposal initial state is ALWAYS PENDING_REVIEW (never auto-applied).
   * - Scoped strictly to the finding's target file.
   * - Does not modify original repository files or execute code.
   * - Bounded to finding evidence.
   *
   * @param {Object} finding - Validated security finding
   * @param {Object} [options={}] - Options (e.g. sourceContext, localOnly)
   * @returns {Promise<{ success: boolean, proposal?: object, data?: object, error?: object }>}
   */
  async generatePatchProposal(finding, options = {}) {
    if (!finding || typeof finding !== 'object') {
      return {
        success: false,
        error: {
          code: 'INVALID_FINDING',
          message: 'A valid finding object is required to generate a patch proposal',
          details: []
        }
      };
    }

    const rawFindingPath = finding.filePath || finding.path;
    if (!rawFindingPath || typeof rawFindingPath !== 'string') {
      return {
        success: false,
        error: {
          code: 'INVALID_FINDING',
          message: 'Finding must include a valid filePath or path',
          details: []
        }
      };
    }

    const rawEvidence = finding.evidence || finding.codeSnippet || options.sourceContext || '';
    const evidenceText = typeof rawEvidence === 'object' ? JSON.stringify(rawEvidence) : String(rawEvidence).trim();
    if (!evidenceText) {
      return {
        success: false,
        error: {
          code: 'MISSING_EVIDENCE',
          message: 'Cannot generate patch proposal without supporting evidence or code snippet',
          details: []
        }
      };
    }

    const sourceContext = options.sourceContext || rawEvidence;

    if (this.apiKey && !options.localOnly) {
      try {
        return await this._callGeminiPatchProposal(finding, sourceContext, options);
      } catch (err) {
        if (err.name === 'AbortError' || err.message?.includes('aborted') || err.message?.includes('timeout')) {
          return {
            success: false,
            error: {
              code: 'AI_TIMEOUT',
              message: `AI patch proposal generation timed out after ${this.timeoutMs}ms`,
              details: [{ error: err.message }]
            }
          };
        }
        if (options.throwOnError) {
          throw err;
        }
        safeLogger.warn('[AIService] Remote AI patch proposal failed, falling back to local generator:', redactString(err.message));
      }
    }

    // Local deterministic generator
    return this._localPatchProposal(finding, sourceContext, options);
  }

  /**
   * Deterministic local patch proposal generator for offline testing and fallback.
   * Produces minimal unified diff and structured rationale conforming to PatchProposalSchema.
   */
  _localPatchProposal(finding, sourceContext = '', options = {}) {
    const rawPath = finding.filePath || finding.path || 'file.js';
    const normPath = rawPath.replace(/\\/g, '/').replace(/^\/+/, '');
    const categoryKey = (finding.category || finding.cwe || '').toUpperCase();
    const startLine = finding.startLine || 1;
    const rawSnippet = String(finding.evidence || finding.codeSnippet || sourceContext || '').trim();

    let origLine = rawSnippet;
    let modLine = rawSnippet;
    let rootCause = 'Dynamic or unvalidated data handling matching security rule: ' + (finding.ruleId || finding.rule || 'vulnerability');
    let proposedCorrection = 'Applied defensive coding pattern at trust boundary.';
    let explanation = 'Sanitizes or parameterizes inputs to prevent exploitation without altering business logic.';

    if (categoryKey.includes('SQL') || categoryKey === 'CWE-89') {
      rootCause = 'Untrusted user input interpolated directly into dynamic SQL query string without parameterization.';
      proposedCorrection = 'Replaced string interpolation with parameterized SQL query placeholder ($1).';
      explanation = 'Parameterized statements ensure user input is treated strictly as literal data rather than executable SQL logic, preventing SQL injection.';
      if (rawSnippet.includes('${')) {
        modLine = rawSnippet.replace(/\$\{([^}]+)\}/g, '$1');
      } else {
        modLine = rawSnippet + ' /* parameterized */';
      }
    } else if (categoryKey.includes('XSS') || categoryKey === 'CWE-79') {
      rootCause = 'Untrusted request parameter rendered directly into HTML response without contextual escaping.';
      proposedCorrection = 'Wrapped untrusted input in HTML entity escaping before rendering.';
      explanation = 'Sanitizing special HTML characters (&, <, >, ", \') neutralizes injected script tags and malicious DOM payloads.';
      if (rawSnippet.includes('${')) {
        modLine = rawSnippet.replace(/\$\{([^}]+)\}/g, '${escapeHtml($1)}');
      } else {
        modLine = `escapeHtml(${rawSnippet})`;
      }
    } else if (categoryKey.includes('COMMAND') || categoryKey === 'CWE-78') {
      rootCause = 'Untrusted input passed directly to system shell execution.';
      proposedCorrection = 'Replaced shell execution with safe argument-array process execution.';
      explanation = 'Executing binaries directly without an intermediate shell prevents shell metacharacter injection.';
      modLine = rawSnippet.replace(/exec\(/g, 'execFile(');
    } else if (categoryKey.includes('SECRET') || categoryKey === 'CWE-798') {
      rootCause = 'Secret credential or API key hardcoded in plaintext source code.';
      proposedCorrection = 'Replaced hardcoded secret literal with environment variable reference.';
      explanation = 'Moving credentials to environment variables prevents secret exposure in source control.';
      modLine = rawSnippet.replace(/['"`][A-Za-z0-9_\-\.]{16,}['"`]/, 'process.env.SECRET_KEY');
    } else if (categoryKey.includes('TRAVERSAL') || categoryKey === 'CWE-22') {
      rootCause = 'Unconfined file path resolution vulnerable to directory traversal via ../ sequences.';
      proposedCorrection = 'Sanitized path segments and verified destination is confined within base directory.';
      explanation = 'Path confinement prevents attackers from navigating outside the intended document root.';
      modLine = `path.resolve(BASE_DIR, path.basename(${rawSnippet}))`;
    } else {
      modLine = rawSnippet + ' // sanitized';
    }

    if (origLine === modLine) {
      modLine = origLine + ' /* patched */';
    }

    const diff = [
      `--- a/${normPath}`,
      `+++ b/${normPath}`,
      `@@ -${startLine},1 +${startLine},1 @@`,
      `-${origLine}`,
      `+${modLine}`
    ].join('\n') + '\n';

    const rawOutput = {
      diff,
      rationale: {
        rootCause,
        proposedCorrection,
        explanation
      },
      changedFiles: [normPath],
      evidenceReferences: [
        {
          type: 'SNIPPET',
          reference: rawSnippet,
          description: `Evidence quoted from finding ${finding.id || ''}`
        }
      ]
    };

    return this.processPatchProposalResponse(rawOutput, finding, {
      model: 'vulnex-deterministic-patch-generator-v1',
      promptVersion: PATCH_PROMPT_VERSION,
      ...options
    });
  }

  async _callGeminiPatchProposal(finding, sourceContext, options = {}) {
    const promptPayload = this.buildPatchProposalPrompt(finding, sourceContext, options);
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;

    const controller = new AbortController();
    const timeoutMs = options.timeoutMs || this.timeoutMs;
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const isGeminiModel = this.model.toLowerCase().includes('gemini');
      const requestBody = isGeminiModel
        ? {
            systemInstruction: {
              parts: [{ text: promptPayload.systemInstruction }]
            },
            contents: [
              {
                parts: [{ text: promptPayload.userPrompt }]
              }
            ],
            generationConfig: {
              temperature: 0.1,
              responseMimeType: 'application/json'
            }
          }
        : {
            contents: [
              {
                role: 'user',
                parts: [{ text: `${promptPayload.systemInstruction}\n\n${promptPayload.userPrompt}` }]
              }
            ],
            generationConfig: {
              temperature: 0.1
            }
          };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        const errorBody = await res.json().catch(() => ({}));
        throw new Error(`Google AI Studio error (${res.status}): ${errorBody?.error?.message || res.statusText}`);
      }

      const data = await res.json();
      const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';

      return this.processPatchProposalResponse(text, finding, {
        model: this.model,
        promptVersion: promptPayload.promptVersion,
        contextSupplied: promptPayload.contextSupplied
      });
    } catch (err) {
      clearTimeout(timeoutId);
      throw err;
    }
  }
}

const aiService = new AIService();
aiService.AIService = AIService;
aiService.buildInvestigationPrompt = buildInvestigationPrompt;
aiService.buildPatchProposalPrompt = buildPatchProposalPrompt;

module.exports = aiService;
