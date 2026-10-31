const path = require('path');
const dotenv = require('dotenv');

// Load environment variables from backend/.env if available
dotenv.config({ path: path.resolve(__dirname, '../../.env') });
dotenv.config();

const port = parseInt(process.env.PORT || '5001', 10);
const nodeEnv = process.env.NODE_ENV || 'development';
const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';
const maxUploadMb = parseInt(process.env.MAX_UPLOAD_MB || '25', 10);
const workspaceRoot = process.env.WORKSPACE_ROOT || path.resolve(__dirname, '../../.workspaces');

// AI Model Adapter configuration
const geminiApiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || '';
const geminiModel = process.env.GEMINI_MODEL || process.env.GEMMA_MODEL || process.env.AI_MODEL || 'gemma-2-9b-it';
const aiTimeoutMs = parseInt(process.env.AI_TIMEOUT_MS || '45000', 10);
const aiMaxRetries = parseInt(process.env.AI_MAX_RETRIES || '1', 10);

// Validate environment configuration
function validateConfig() {
  if (isNaN(port) || port < 1 || port > 65535) {
    console.warn(`[Config Warning] Invalid PORT "${process.env.PORT}". Falling back to 5001.`);
  }
}

validateConfig();

const config = {
  port: isNaN(port) ? 5001 : port,
  nodeEnv,
  corsOrigin,
  maxUploadMb: isNaN(maxUploadMb) ? 25 : maxUploadMb,
  workspaceRoot,
  isProduction: nodeEnv === 'production',
  isDevelopment: nodeEnv === 'development',
  isTest: nodeEnv === 'test',
  ai: {
    apiKey: geminiApiKey,
    model: geminiModel,
    timeoutMs: isNaN(aiTimeoutMs) ? 45000 : aiTimeoutMs,
    maxRetries: isNaN(aiMaxRetries) ? 1 : aiMaxRetries,
    hasApiKey: Boolean(geminiApiKey && geminiApiKey.trim().length > 0)
  }
};

module.exports = config;
