const path = require("path");
const express = require("express");
const cors = require("cors");
require("dotenv").config({ path: path.resolve(__dirname, "../.env") });
require("dotenv").config();

// Environment configuration validation
const requiredEnvVars = ["PORT", "CORS_ORIGIN"];
const optionalEnvVars = ["GEMINI_API_KEY", "OPENAI_API_KEY", "WORKSPACE_ROOT"];

function validateEnv() {
  console.log("[VULNEX] Validating environment configuration...");
  for (const varName of requiredEnvVars) {
    if (!process.env[varName]) {
      console.warn(`[VULNEX] Warning: Environment variable ${varName} is not set. Using defaults.`);
    }
  }

  if (!process.env.GEMINI_API_KEY && !process.env.OPENAI_API_KEY) {
    console.info("[VULNEX] Info: No AI API keys detected. Operating in local heuristic analysis mode.");
  } else {
    console.info("[VULNEX] Info: AI Provider API key configured.");
  }
}

validateEnv();

const app = express();

// Middlewares
app.use(cors({ origin: process.env.CORS_ORIGIN || "http://localhost:5173" }));
app.use(express.json());

// Routes
const repositoryRoutes = require("./routes/repository.routes");
const scanRoutes = require("./routes/scan.routes");
const findingRoutes = require("./routes/finding.routes");

app.use("/api/repositories", repositoryRoutes);
app.use("/api/scans", scanRoutes);
app.use("/api/findings", findingRoutes);

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({ success: true, message: "VULNEX Backend is running!" });
});

// Fallback 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: "API route not found" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("[VULNEX Error]:", err);
  res.status(500).json({ success: false, error: err.message || "Internal server error" });
});

const PORT = process.env.PORT || 5001;

// Only listen if executed directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;
