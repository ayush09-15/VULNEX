const express = require('express');
const cors = require('cors');
const config = require('./config/env');

// Middlewares
const requestId = require('./middleware/requestId');
const notFound = require('./middleware/notFound');
const errorHandler = require('./middleware/errorHandler');

// Route modules
const healthRoutes = require('./routes/health.routes');
const repositoryRoutes = require('./routes/repository.routes');
const scanRoutes = require('./routes/scan.routes');
const findingRoutes = require('./routes/finding.routes');
const patchRoutes = require('./routes/patch.routes');

const app = express();

// 1. Tracing & Request ID
app.use(requestId);

// 2. CORS configuration
const allowedOrigins = [
  config.corsOrigin,
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    if (!config.isProduction && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
      return callback(null, true);
    }
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID']
}));

// 3. Body parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 4. API Routes
app.use('/api/health', healthRoutes);
app.use('/api/repositories', repositoryRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/findings', findingRoutes);
app.use('/api/patches', patchRoutes);

// 5. 404 Not Found Catch-All
app.use(notFound);

// 6. Centralized Error Handler
app.use(errorHandler);

module.exports = app;
