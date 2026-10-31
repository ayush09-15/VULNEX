/**
 * VULNEX Server-Side Model Adapter
 * Manages secure AI model invocation, server-only API keys, timeout handling,
 * quota exhaustion detection, and provider error mapping.
 *
 * Adheres strictly to Master Antigravity Execution Bible Section 4.5, 8.1, and Commit 24 gates.
 */

const config = require('../config/env');

/**
 * Custom Error Classes for AI Provider Responses
 */
class AIError extends Error {
  constructor(message, { code = 'AI_ERROR', status = 500, details = null } = {}) {
    super(message);
    this.name = 'AIError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

class AITimeoutError extends AIError {
  constructor(message = 'AI model inference timed out.') {
    super(message, { code: 'AI_TIMEOUT', status: 504 });
    this.name = 'AITimeoutError';
  }
}

class AIQuotaExceededError extends AIError {
  constructor(message = 'AI provider quota limit reached or rate limit exceeded.') {
    super(message, { code: 'AI_QUOTA_EXCEEDED', status: 429 });
    this.name = 'AIQuotaExceededError';
  }
}

class AIAuthError extends AIError {
  constructor(message = 'Invalid or unauthorized AI provider API key.') {
    super(message, { code: 'AI_AUTH_FAILED', status: 401 });
    this.name = 'AIAuthError';
  }
}

/**
 * Sanitizes URLs and strings to ensure API keys are never leaked in logs or error traces.
 * @param {string} text
 * @param {string} apiKey
 * @returns {string} Redacted string
 */
function redactApiKey(text, apiKey) {
  if (!text || typeof text !== 'string') return '';
  let sanitized = text.replace(/key=[a-zA-Z0-9_\-]+/gi, 'key=[REDACTED]');
  if (apiKey && apiKey.length > 4) {
    sanitized = sanitized.split(apiKey).join('[REDACTED]');
  }
  return sanitized;
}

class GoogleAIModelAdapter {
  /**
   * @param {Object} [options]
   * @param {string} [options.apiKey] - Server-only API key
   * @param {string} [options.model] - Model name from env var
   * @param {number} [options.timeoutMs] - Request timeout in ms
   * @param {number} [options.maxRetries] - Retry count
   */
  constructor(options = {}) {
    this.apiKey = options.apiKey !== undefined ? options.apiKey : config.ai.apiKey;
    this.model = options.model || config.ai.model || 'gemma-2-9b-it';
    this.timeoutMs = options.timeoutMs !== undefined ? options.timeoutMs : config.ai.timeoutMs;
    this.maxRetries = options.maxRetries !== undefined ? options.maxRetries : config.ai.maxRetries;
  }

  /**
   * Check if remote model inference is available and configured
   * @returns {boolean}
   */
  isAvailable() {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0 && !this.apiKey.startsWith('PLACEHOLDER'));
  }

  /**
   * Return non-sensitive metadata for health and reporting (strictly redacts keys)
   * @returns {{ model: string, provider: string, timeoutMs: number, configured: boolean }}
   */
  getModelInfo() {
    return {
      model: this.model,
      provider: 'Google AI Studio',
      timeoutMs: this.timeoutMs,
      configured: this.isAvailable()
    };
  }

  /**
   * Custom serializer to ensure apiKey is NEVER serialized to JSON or exposed
   */
  toJSON() {
    return this.getModelInfo();
  }

  /**
   * Dispatch a completion request to Google AI Studio with timeout and quota guards.
   *
   * @param {Object} params
   * @param {string} [params.systemInstruction]
   * @param {string} params.userPrompt
   * @param {boolean} [params.jsonMode=true]
   * @param {number} [params.temperature=0.1]
   * @returns {Promise<{ text: string, model: string, durationMs: number }>}
   */
  async generateCompletion({ systemInstruction = '', userPrompt = '', jsonMode = true, temperature = 0.1 }) {
    if (!this.isAvailable()) {
      throw new AIAuthError('AI provider API key is not configured on this server.');
    }

    const startTime = Date.now();
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(this.model)}:generateContent?key=${this.apiKey}`;

    const requestBody = {
      generationConfig: {
        temperature,
        maxOutputTokens: 2048,
        ...(jsonMode ? { responseMimeType: 'application/json' } : {})
      },
      contents: [
        {
          parts: [{ text: userPrompt }]
        }
      ]
    };

    if (systemInstruction) {
      requestBody.systemInstruction = {
        parts: [{ text: systemInstruction }]
      };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody),
        signal: controller.signal
      });

      clearTimeout(timer);

      // Handle HTTP Error Responses
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const rawErrMsg = errorData?.error?.message || response.statusText;
        const safeErrMsg = redactApiKey(rawErrMsg, this.apiKey);

        if (response.status === 429) {
          throw new AIQuotaExceededError(`AI quota exceeded (${response.status}): ${safeErrMsg}`);
        }

        if (response.status === 401 || response.status === 403) {
          throw new AIAuthError(`AI authentication error (${response.status}): ${safeErrMsg}`);
        }

        if (response.status >= 500) {
          throw new AIError(`Upstream AI provider unavailable (${response.status}): ${safeErrMsg}`, {
            code: 'AI_SERVICE_UNAVAILABLE',
            status: response.status
          });
        }

        throw new AIError(`AI generation failed with HTTP ${response.status}: ${safeErrMsg}`, {
          code: 'AI_PROVIDER_ERROR',
          status: response.status
        });
      }

      const data = await response.json();
      const parts = data?.candidates?.[0]?.content?.parts || [];
      const nonThoughtParts = parts.filter(p => !p.thought);
      const text = nonThoughtParts.length > 0
        ? nonThoughtParts.map(p => p.text || '').join('')
        : (parts[parts.length - 1]?.text || '');

      return {
        text,
        model: this.model,
        durationMs: Date.now() - startTime
      };
    } catch (err) {
      clearTimeout(timer);

      if (err.name === 'AbortError' || err.code === 'ABORT_ERR' || controller.signal.aborted) {
        throw new AITimeoutError(`AI inference timed out after ${this.timeoutMs}ms.`);
      }

      // Re-throw known AIError types
      if (err instanceof AIError) {
        throw err;
      }

      // Sanitize any unexpected network or parsing error
      const safeMessage = redactApiKey(err.message, this.apiKey);
      throw new AIError(`AI inference network failure: ${safeMessage}`, {
        code: 'AI_NETWORK_ERROR',
        status: 500
      });
    }
  }
}

module.exports = {
  GoogleAIModelAdapter,
  AIError,
  AITimeoutError,
  AIQuotaExceededError,
  AIAuthError,
  redactApiKey
};
