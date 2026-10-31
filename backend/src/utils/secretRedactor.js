/**
 * VULNEX Centralized Secret Redaction & Log Sanitization Utility
 *
 * Implements:
 * 1. Comprehensive pattern detection for:
 *    - API keys and tokens (AWS, GitHub, Google/Gemini, Slack, Stripe, generic)
 *    - Authorization headers, Bearer tokens, JWTs, and Basic auth credentials
 *    - Database connection URIs and credentials (MongoDB, Postgres, MySQL, Redis, AMQP)
 *    - Private keys (RSA, OPENSSH, EC, DSA, PGP)
 *    - Password, secret, and token assignments
 * 2. Deep recursive redaction for nested objects, arrays, and Error structures.
 * 3. Safe environment variable sanitization preventing raw env dumping.
 * 4. Safe logger wrapper ensuring secrets are scrubbed before reaching stdout/stderr.
 * 5. Invariant: Never mutates original source objects or disk files.
 */

const SENSITIVE_KEY_NAMES = new Set([
  'password',
  'passwd',
  'pwd',
  'secret',
  'apikey',
  'api_key',
  'token',
  'auth_token',
  'access_token',
  'authorization',
  'cookie',
  'set-cookie',
  'privatekey',
  'private_key',
  'client_secret',
  'clientsecret',
  'credentials',
  'database_url',
  'db_pass',
  'db_password',
  'jwt'
]);

const SENSITIVE_ENV_REGEX = /(?:KEY|SECRET|PASSWORD|PASS|TOKEN|AUTH|CREDENTIAL|PRIVATE|SIGNING|JWT|DATABASE|URL|MONGO|REDIS|CONNECTION|CERT)/i;

/**
 * Redacts secrets from a string using canonical VULNEX redaction patterns.
 * Preserves already redacted markers ([REDACTED_...]).
 *
 * @param {string} text - Raw input string
 * @param {Object} [options={}]
 * @param {Array<string>} [options.knownSecrets=[]] - Specific exact secrets to redact
 * @returns {string} Sanitized string
 */
function redactString(text, options = {}) {
  if (text === null || text === undefined) return '';
  if (typeof text !== 'string') {
    text = String(text);
  }
  if (!text) return '';

  let sanitized = text;

  // 1. Private keys (multiline blocks: RSA, OPENSSH, EC, DSA, PGP, generic)
  sanitized = sanitized.replace(
    /-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----/g,
    '-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END PRIVATE KEY-----'
  );
  sanitized = sanitized.replace(
    /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    '-----BEGIN PGP PRIVATE KEY BLOCK-----\n[REDACTED_PGP_PRIVATE_KEY]\n-----END PGP PRIVATE KEY BLOCK-----'
  );

  // 2. Database & Service connection URIs with credentials
  // Handles mongodb://user:pass@host, postgres://user:pass@host, mysql://..., redis://:pass@host, amqp://...
  sanitized = sanitized.replace(
    /((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|amqp(?:s)?|mariadb|cockroachdb):\/\/[^:\s\/]+:)([^@\s\/]+)(@)/gi,
    '$1[REDACTED_PASSWORD]$3'
  );
  sanitized = sanitized.replace(
    /((?:redis(?:s)?):\/\/(?:[^:\s\/]+)?:)([^@\s\/]+)(@)/gi,
    '$1[REDACTED_PASSWORD]$3'
  );

  // 3. AWS Credentials
  sanitized = sanitized.replace(/\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{12,24}\b/g, '[REDACTED_AWS_KEY]');
  sanitized = sanitized.replace(
    /((?:aws_secret_access_key|aws_session_token)\s*[:=]\s*['"]?)(?!\[REDACTED_)([A-Za-z0-9/+=]{30,})(['"]?)/gi,
    '$1[REDACTED_SECRET]$3'
  );

  // 4. GitHub Tokens (personal access tokens, fine-grained, OAuth)
  sanitized = sanitized.replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b/g, '[REDACTED_GITHUB_TOKEN]');
  sanitized = sanitized.replace(/\bgithub_pat_[A-Za-z0-9_]{80,255}\b/g, '[REDACTED_GITHUB_TOKEN]');

  // 5. Google / Gemini API Keys
  sanitized = sanitized.replace(/\bAIza[0-9A-Za-z\-_]{30,45}\b/g, '[REDACTED_API_KEY]');

  // 6. Slack & Stripe API Keys
  sanitized = sanitized.replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, '[REDACTED_SLACK_TOKEN]');
  sanitized = sanitized.replace(/\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}\b/g, '[REDACTED_STRIPE_KEY]');

  // 7. Authorization Headers, Bearer Tokens, and Basic Auth
  sanitized = sanitized.replace(
    /\bBearer\s+([a-zA-Z0-9_\-\.]{20,})\b/g,
    'Bearer [REDACTED_BEARER_TOKEN]'
  );
  sanitized = sanitized.replace(
    /\bBasic\s+([A-Za-z0-9+/=]{16,})\b/g,
    'Basic [REDACTED_BASIC_AUTH]'
  );

  // 8. URL query parameter credentials (e.g. ?key=..., &token=..., &apiKey=...)
  sanitized = sanitized.replace(
    /([?&](?:key|api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password)=)[^&\s]+/gi,
    '$1[REDACTED]'
  );

  // 9. Generic password, secret, token assignments in code, JSON, or config
  sanitized = sanitized.replace(
    /((?:password|passwd|pwd|pass|db_pass|dbpass|db_password|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)\s*[:=]\s*(['"`]?))(?!\[REDACTED_)([^\s'"`\r\n]{4,})(\2)/gi,
    '$1[REDACTED_SECRET]$4'
  );

  // 10. Specific caller-supplied known secrets (e.g. active API key in memory)
  if (Array.isArray(options.knownSecrets)) {
    for (const secret of options.knownSecrets) {
      if (typeof secret === 'string' && secret.length >= 6) {
        sanitized = sanitized.split(secret).join('[REDACTED]');
      }
    }
  }

  return sanitized;
}

/**
 * Deep recursive secret redactor.
 * Traverses nested objects, arrays, and Error instances without mutating input structures.
 *
 * @param {any} value - Input value to sanitize
 * @param {Object} [options={}]
 * @param {Set} [activeStack=new Set()] - Circular reference tracking on current stack
 * @returns {any} Sanitized clone
 */
function redactDeep(value, options = {}, activeStack = new Set()) {
  // Primitives and falsy values
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'string') {
    return redactString(value, options);
  }

  if (typeof value !== 'object') {
    return value;
  }

  // Handle special built-in objects
  if (value instanceof Date) {
    return new Date(value.getTime());
  }

  if (value instanceof RegExp) {
    return value;
  }

  if (Buffer.isBuffer(value)) {
    return Buffer.from(value);
  }

  // Circular reference detection (cycle on current active stack)
  if (activeStack.has(value)) {
    return '[Circular]';
  }
  activeStack.add(value);

  try {
    // Error object handling
    if (value instanceof Error) {
      const safeError = new Error(redactString(value.message || '', options));
      safeError.name = value.name;
      if (value.code) safeError.code = value.code;
      if (value.statusCode) safeError.statusCode = value.statusCode;
      if (value.status) safeError.status = value.status;
      if (value.details) {
        safeError.details = redactDeep(value.details, options, activeStack);
      }
      return safeError;
    }

    // Array handling
    if (Array.isArray(value)) {
      return value.map((item) => redactDeep(item, options, activeStack));
    }

    // Plain object handling
    const result = {};
    for (const [key, val] of Object.entries(value)) {
      const normalizedKey = key.toLowerCase().replace(/[_-]/g, '');

      // Check if the key name indicates a sensitive field
      if (SENSITIVE_KEY_NAMES.has(normalizedKey) || /^(?:password|secret|apikey|token|privatekey|credentials)$/.test(normalizedKey)) {
        result[key] = '[REDACTED_SECRET]';
      } else {
        result[key] = redactDeep(val, options, activeStack);
      }
    }

    return result;
  } finally {
    activeStack.delete(value);
  }
}

/**
 * Sanitizes environment variables to prevent accidental credential leakage.
 * Replaces sensitive values with [REDACTED].
 *
 * @param {Object} [env=process.env]
 * @param {Object} [options={}]
 * @returns {Object} Sanitized shallow copy of environment variables
 */
function sanitizeEnvironment(env = process.env, options = {}) {
  if (!env || typeof env !== 'object') return {};

  const sanitized = {};
  for (const [key, val] of Object.entries(env)) {
    if (SENSITIVE_ENV_REGEX.test(key)) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof val === 'string') {
      sanitized[key] = redactString(val, options);
    } else {
      sanitized[key] = val;
    }
  }
  return sanitized;
}

/**
 * Returns a minimal, safe environment summary suitable for diagnostics and health logs.
 * Strictly avoids logging complete process environments.
 *
 * @param {Object} [env=process.env]
 * @returns {Object} Safe diagnostic metadata
 */
function getSafeEnvSummary(env = process.env) {
  return {
    nodeEnv: env.NODE_ENV || 'development',
    port: env.PORT || '5001',
    platform: process.platform,
    nodeVersion: process.version,
    arch: process.arch
  };
}

/**
 * Formats and redacts any argument intended for console logging.
 *
 * @param {any} arg
 * @returns {any}
 */
function formatLogArg(arg) {
  if (typeof arg === 'string') {
    return redactString(arg);
  }
  return redactDeep(arg);
}

/**
 * Centralized safe logger ensuring secrets are redacted before printing.
 */
const safeLogger = {
  log: (...args) => console.log(...args.map(formatLogArg)),
  info: (...args) => console.info(...args.map(formatLogArg)),
  warn: (...args) => console.warn(...args.map(formatLogArg)),
  error: (...args) => console.error(...args.map(formatLogArg)),
  debug: (...args) => (console.debug || console.log)(...args.map(formatLogArg))
};

module.exports = {
  redactString,
  redactSecrets: redactString,
  redactDeep,
  sanitizeEnvironment,
  getSafeEnvSummary,
  safeLogger,
  logger: safeLogger,
  formatLogArg
};
