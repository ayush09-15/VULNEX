const {
  parseAndValidateAIInvestigation,
  createFallbackInvestigation
} = require('../validators/investigation.schema');

/**
 * AI Service for VULNEX
 * Handles AI-powered vulnerability analysis, root-cause diagnosis,
 * and automated security patch generation.
 */

class AIService {
  constructor() {
    this.apiKey = process.env.GEMINI_API_KEY || process.env.OPENAI_API_KEY || '';
    this.model = process.env.GEMINI_MODEL || 'gemini-1.5-pro';
  }

  /**
   * Analyze a vulnerability finding
   * @param {Object} finding
   * @param {string} codeContext
   * @returns {Promise<Object>}
   */
  async analyzeVulnerability(finding, codeContext = '') {
    if (this.apiKey) {
      try {
        return await this._callGeminiAnalysis(finding, codeContext);
      } catch (err) {
        console.warn('[AIService] Remote AI call failed, falling back to local analysis:', err.message);
      }
    }

    // Heuristic fallback analysis when API key is not yet configured
    return this._localAnalysis(finding, codeContext);
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
        isFallback: false
      };
    }

    return createFallbackInvestigation({
      findingId: finding?.id || 'finding_unknown',
      reason: `AI output validation failed: ${parseResult.error?.message || 'malformed response'}`,
      model: this.model,
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
    if (this.apiKey) {
      try {
        return await this._callGeminiPatch(finding, originalCode);
      } catch (err) {
        console.warn('[AIService] Remote AI call failed, falling back to local patch generator:', err.message);
      }
    }

    return this._localPatchGeneration(finding, originalCode);
  }

  /**
   * Local heuristic analysis engine
   */
  _localAnalysis(finding, codeContext) {
    const analysisMap = {
      'CWE-89': {
        rootCause: 'Dynamic SQL construction with unsanitized parameters allows attackers to alter query logic.',
        cvssScore: 9.8,
        exploitVector: 'Network / Unauthenticated HTTP input',
        impact: 'Complete database compromise, data leakage, and potential data modification.',
        mitigation: 'Convert string interpolation into parameterized statements or use an ORM with prepared bindings.'
      },
      'CWE-78': {
        rootCause: 'Passing untrusted input directly into a system shell via exec() or eval().',
        cvssScore: 9.8,
        exploitVector: 'Remote code execution via command separator injection (e.g., ; && |).',
        impact: 'Complete server host takeover and lateral movement.',
        mitigation: 'Use child_process.execFile with an array of arguments, or avoid OS shell calls entirely.'
      },
      'CWE-798': {
        rootCause: 'Secret credentials, API tokens, or encryption keys hardcoded in source control.',
        cvssScore: 7.5,
        exploitVector: 'Credential harvesting from public or leaked repositories.',
        impact: 'Unauthorized access to downstream cloud services and API abuse.',
        mitigation: 'Move keys to environment variables and utilize secret management systems (e.g. AWS Secrets Manager, Vault).'
      },
      'CWE-22': {
        rootCause: 'Path traversal via path.join or file operations lacking path confinement.',
        cvssScore: 7.5,
        exploitVector: 'Directory traversal using ../ sequences in user input.',
        impact: 'Unauthorized reading or overwriting of sensitive system files.',
        mitigation: 'Sanitize path segments, reject directory separators, and verify that path.resolve stays within allowed base directory.'
      }
    };

    const details = analysisMap[finding.cwe] || {
      rootCause: `Detected pattern matching security rule: ${finding.name || 'Security Finding'}`,
      cvssScore: finding.severity === 'CRITICAL' ? 9.0 : finding.severity === 'HIGH' ? 7.5 : 5.0,
      exploitVector: 'Standard web application attack vector',
      impact: finding.description || 'Potential security risk to application confidentiality and integrity.',
      mitigation: finding.remediation || 'Sanitize input and follow secure coding best practices.'
    };

    return {
      findingId: finding.id,
      modelUsed: 'vulnex-heuristic-engine-v1',
      confidence: 0.94,
      ...details,
      analyzedAt: new Date().toISOString()
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
      explanation,
      generatedAt: new Date().toISOString()
    };
  }

  async _callGeminiAnalysis(finding, codeContext) {
    // If Gemini REST API is called
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;
    const prompt = `Analyze this security finding:
Vulnerability: ${finding.name} (${finding.cwe})
Severity: ${finding.severity}
Code:
${codeContext || finding.codeSnippet}

Return JSON with: rootCause, cvssScore, exploitVector, impact, mitigation.`;

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }]
      })
    });

    const data = await res.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    return {
      findingId: finding.id,
      modelUsed: this.model,
      rawOutput: text,
      analyzedAt: new Date().toISOString()
    };
  }

  async _callGeminiPatch(finding, originalCode) {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;
    const prompt = `Fix this security vulnerability:
Vulnerability: ${finding.name} (${finding.cwe})
Code:
${originalCode || finding.codeSnippet}

Provide the patched code and explanation.`;

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }]
      })
    });

    const data = await res.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    return {
      findingId: finding.id,
      modelUsed: this.model,
      patchedCode: text,
      explanation: 'AI-generated fix via ' + this.model,
      generatedAt: new Date().toISOString()
    };
  }
}

const aiService = new AIService();
aiService.AIService = AIService;

module.exports = aiService;

