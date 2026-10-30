// Controlled Fixture for Semgrep Static Analysis Test
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  // Vulnerable pattern: dynamic SQL construction
  const query = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  res.send(query);
});

module.exports = app;
