# Controlled Vulnerable Node.js Sample Fixture

> **WARNING:**  
> **INTENTIONALLY VULNERABLE — LOCAL SECURITY TESTING ONLY. NEVER DEPLOY OR EXPOSE TO A NETWORK.**

This package is a controlled, isolated test fixture created specifically to benchmark and validate the **VULNEX** detection, analysis, and automated remediation engine.

---

## 1. Overview & Safety Guarantees

- **No Real Credentials:** Does not contain API keys, passwords, private certificates, or secrets.
- **No Destructive Operations:** Employs an in-memory mock database driver; no live database connections or destructive write operations are performed.
- **Isolated Execution:** Designed for local static code analysis and offline subprocess testing.

---

## 2. Documented Vulnerabilities

### Vulnerability 1: SQL Injection (SQLi)
- **Target File:** `fixtures/server.js`
- **Location:** `GET /users/search` (around Line 44)
- **CWE:** [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- **Mechanism:** User input from `req.query.username` is directly interpolated into a raw SQL query string via JavaScript template literals:
  ```javascript
  const query = `SELECT id, username, email FROM users WHERE username = '${username}'`;
  ```
- **Expected Scanner Finding:**
  - Rule Category: `SQL_INJECTION`
  - Severity: `CRITICAL` or `HIGH`
  - Confidence: `HIGH`
  - Remediation Expected: Parameterized SQL statement or prepared query placeholder.

---

### Vulnerability 2: Reflected Cross-Site Scripting (XSS)
- **Target File:** `fixtures/server.js`
- **Location:** `GET /search` (around Line 63)
- **CWE:** [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- **Mechanism:** Untrusted user input from `req.query.q` is rendered unescaped directly into an HTML document returned via `res.send(...)`:
  ```javascript
  <p>You searched for: ${searchTerm}</p>
  ```
- **Expected Scanner Finding:**
  - Rule Category: `XSS`
  - Severity: `HIGH` or `MEDIUM`
  - Confidence: `HIGH` or `MEDIUM`
  - Remediation Expected: Context-aware HTML entity encoding or DOM sanitization.

---

## 3. Running Static Analysis

To scan this fixture with the VULNEX Semgrep detection engine:

```bash
semgrep scan --config auto --json fixtures/
```

