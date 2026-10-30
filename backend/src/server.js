const app = require('./app');
const config = require('./config/env');

const server = app.listen(config.port, () => {
  console.log(`[VULNEX API] Server running in ${config.nodeEnv} mode on port ${config.port}`);
  console.log(`[VULNEX API] Health check available at http://localhost:${config.port}/api/health`);
});

// Graceful shutdown handling
function gracefulShutdown(signal) {
  console.log(`[VULNEX API] Received ${signal}. Starting graceful shutdown...`);
  server.close(() => {
    console.log('[VULNEX API] HTTP server closed gracefully.');
    process.exit(0);
  });

  // Force close after 10s if connections refuse to terminate
  setTimeout(() => {
    console.error('[VULNEX API] Forced shutdown due to timeout.');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = server;
