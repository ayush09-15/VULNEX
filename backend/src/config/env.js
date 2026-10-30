const path = require('path');
const dotenv = require('dotenv');

// Load environment variables from backend/.env if available
dotenv.config({ path: path.resolve(__dirname, '../../.env') });
dotenv.config();

const port = parseInt(process.env.PORT || '5001', 10);
const nodeEnv = process.env.NODE_ENV || 'development';
const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';

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
  isProduction: nodeEnv === 'production',
  isDevelopment: nodeEnv === 'development',
  isTest: nodeEnv === 'test'
};

module.exports = config;

