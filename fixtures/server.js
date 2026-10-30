/**
 * ==============================================================================
 * WARNING: INTENTIONALLY VULNERABLE — LOCAL SECURITY TESTING ONLY.
 * NEVER DEPLOY OR EXPOSE TO A NETWORK.
 *
 * This fixture is designed specifically as a controlled test subject for the
 * VULNEX automated security scanner and remediation engine.
 * ==============================================================================
 */

const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// In-memory mock database client for safe, non-destructive testing
const db = {
  query: (sql, callback) => {
    // Simulated database query response
    if (typeof callback === 'function') {
      callback(null, [{ id: 1, username: 'admin', email: 'admin@example.local' }]);
    }
  }
};

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok', fixture: 'vulnex-vulnerable-sample' });
});

/**
 * ==============================================================================
 * VULNERABILITY 1: SQL Injection (SQLi)
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command
 *
 * Flaw: Untrusted input from `req.query.username` is directly interpolated into
 * the SQL query string using a template literal without sanitization or parameterization.
 * ==============================================================================
 */
app.get('/users/search', (req, res) => {
  const username = req.query.username || '';

  // VULNERABLE: Direct string interpolation of user input into raw SQL query
  const query = `SELECT id, username, email FROM users WHERE username = '${username}'`;

  db.query(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database query failed' });
    }
    res.json({ results: rows, executedQuery: query });
  });
});

/**
 * ==============================================================================
 * VULNERABILITY 2: Reflected Cross-Site Scripting (XSS)
 * CWE-79: Improper Neutralization of Input During Web Page Generation
 *
 * Flaw: Untrusted input from `req.query.q` is reflected directly into an HTML
 * response sink without encoding or escaping, enabling script injection.
 * ==============================================================================
 */
app.get('/search', (req, res) => {
  const searchTerm = req.query.q || '';

  // VULNERABLE: Raw unsanitized user input embedded directly in HTML response
  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Search Results</title>
      </head>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${searchTerm}</p>
        <div id="results">No matching records found.</div>
      </body>
    </html>
  `;

  res.setHeader('Content-Type', 'text/html');
  res.status(200).send(htmlResponse);
});

// Guard: Only listen when executed standalone, preventing port conflicts during tests
if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`[FIXTURE] Vulnerable test server running on port ${PORT}`);
    console.log(`[FIXTURE] WARNING: Intended solely for local vulnerability scanning.`);
  });
}

module.exports = app;
