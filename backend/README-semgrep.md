# VULNEX Semgrep Detection Engine

> **Module:** Semgrep Detection Engine  
> **Status:** Production-Ready  
> **Package:** `@vulnex/backend`  
> **Owner:** Anand Maurya  

The VULNEX Semgrep Detection Engine provides static application security testing (SAST) capability for the VULNEX platform. It wraps the Semgrep CLI, parses output deterministically, extracts code evidence, normalizes security findings to the canonical VULNEX Finding schema, and produces immutable scanner provenance records.

---

## 1. Installation Requirements & Setup

### Prerequisites
- Node.js >= 20.0.0 (Tested on Node.js v24)
- Python 3.9+ with `pip`
- macOS (arm64 / x86_64) or Linux

### Semgrep CLI Installation (macOS)

Install Semgrep via Python pip:
```bash
python3 -m pip install --user semgrep
```

Ensure the Python user binary directory is in your `PATH`:
```bash
# Add to ~/.zshrc or ~/.bashrc
export PATH="$HOME/Library/Python/3.9/bin:$PATH"
```

Verify installation:
```bash
semgrep --version
# Expected output: 1.136.0 or higher
```

Alternatively, install using Homebrew:
```bash
brew install semgrep
```

---

## 2. Environment Configuration

The Semgrep engine is configured via environment variables located in `backend/.env`:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `SEMGREP_BIN` | `semgrep` | Path to Semgrep binary or executable name |
| `SEMGREP_CONFIG` | `auto` | Semgrep ruleset configuration (e.g., `auto`, `p/default`, `p/ci`) |
| `SCAN_TIMEOUT_SECONDS` | `120` | Maximum subprocess execution duration before termination |

Example `.env` snippet:
```env
SEMGREP_BIN=semgrep
SEMGREP_CONFIG=auto
SCAN_TIMEOUT_SECONDS=120
```

---

## 3. Scanner Execution Flow

```
┌────────────────────────┐
│  Orchestrator Request  │
└───────────┬────────────┘
            │ scanWithSemgrep(workspacePath, options)
            ▼
┌────────────────────────┐
│  Workspace Validation  │ ──► Reject path traversal / invalid paths
└───────────┬────────────┘
            │ Validated Directory
            ▼
┌────────────────────────┐
│  ProcessRunner (Spawn) │ ──► semgrep scan --config auto --json <workspace>
└───────────┬────────────┘     (Enforces timeout, max buffer limits, segregated stdio)
            │ Raw JSON / Stderr
            ▼
┌────────────────────────┐
│  Semgrep Parser        │ ──► Extracts findings, normalizes paths, redacts secrets
└───────────┬────────────┘
            │ Normalized Findings[]
            ▼
┌────────────────────────┐
│  Provenance Generator  │ ──► Attaches version, timestamps, duration, rule traces
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│  Structured Result     │
│  { success, findings } │
└────────────────────────┘
```

---

## 4. Service Function Usage

Import and call `scanWithSemgrep`:

```javascript
const { scanWithSemgrep } = require('./services/semgrep.service');

async function runAudit() {
  const result = await scanWithSemgrep('/path/to/project/workspace', {
    config: 'auto',
    timeoutSeconds: 120,
    scanId: 'scan_01JAZZ80002'
  });

  if (result.success) {
    console.log(`Scan completed with status: ${result.status}`);
    console.log(`Detected findings: ${result.findings.length}`);
    console.log('Provenance record:', result.provenance);
  } else {
    console.error('Scan failed:', result.errors);
  }
}
```

---

## 5. Normalized Finding Schema

Findings conform to the canonical VULNEX finding specification:

```json
{
  "id": "find_7a2f0e9b1c3d5a4e",
  "scanner": "semgrep",
  "ruleId": "javascript.express.security.audit.sqli",
  "title": "Sqli",
  "category": "SQL_INJECTION",
  "severity": "CRITICAL",
  "confidence": "HIGH",
  "filePath": "src/controllers/user.controller.js",
  "startLine": 42,
  "endLine": 42,
  "message": "Detected direct string interpolation in SQL query. Use parameterized queries instead.",
  "evidence": "const query = `SELECT * FROM users WHERE username = '${req.query.username}'`;",
  "fingerprint": "8f3b2d1c0a9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a",
  "status": "DETECTED",
  "createdAt": "2026-10-31T03:30:00.000Z"
}
```

### Key Normalization Rules
1. **Paths are relative:** Host system paths are stripped; paths are strictly relative to scan workspace.
2. **Severity Mapping:**
   - CVSS / security-severity >= 9.0 $\rightarrow$ `CRITICAL`
   - CVSS / security-severity >= 7.0 $\rightarrow$ `HIGH`
   - CVSS / security-severity >= 4.0 $\rightarrow$ `MEDIUM`
   - Semgrep `ERROR` $\rightarrow$ `HIGH` (or `CRITICAL` based on impact metadata)
   - Semgrep `WARNING` $\rightarrow$ `MEDIUM`
   - Semgrep `INFO` $\rightarrow$ `INFO`
3. **Confidence Mapping:** Taken from rule metadata (`HIGH`, `MEDIUM`, `LOW`). If absent, defaults to `UNKNOWN`. Severity is never conflated with confidence.
4. **Stable Fingerprinting:** Deterministic SHA-256 hash derived from `${ruleId}:${filePath}:${startLine}:${evidence}` for cross-scan deduplication.

---

## 6. Scanner Provenance Structure

Every execution generates a tamper-evident provenance record tracing findings back to execution facts:

```json
{
  "scanner": "semgrep",
  "version": "1.136.0",
  "config": "auto",
  "scanId": "scan_01JAZZ80002",
  "timestamp": "2026-10-31T03:30:00.000Z",
  "durationMs": 4250,
  "exitCode": 0,
  "status": "COMPLETED",
  "findingsCount": 1,
  "errors": [],
  "ruleFindings": [
    {
      "findingId": "find_7a2f0e9b1c3d5a4e",
      "ruleId": "javascript.express.security.audit.sqli",
      "filePath": "src/controllers/user.controller.js",
      "startLine": 42,
      "endLine": 42
    }
  ]
}
```

---

## 7. Error Handling & Scanner Resilience

| Condition | Scanner Status | Result Payload |
| :--- | :--- | :--- |
| Scan succeeded with 0 findings | `COMPLETED` | `success: true, findings: []` |
| Scan succeeded with findings | `COMPLETED` | `success: true, findings: [...]` |
| Scan completed with non-fatal warnings | `PARTIAL` | `success: true, findings: [...], errors: [...]` |
| Semgrep binary missing / not found | `FAILED` | `success: false, errors: ['Semgrep CLI is not installed...']` |
| Workspace path invalid / traversal | `FAILED` | `success: false, errors: ['Workspace validation failed...']` |
| Execution timed out | `FAILED` | `success: false, errors: ['Scanner execution timed out...']` |
| Process crashed / invalid JSON | `FAILED` | `success: false, errors: ['Semgrep exited with non-zero code...']` |

---

## 8. Test Execution

Run the complete test suite using Node.js native test runner:

```bash
cd backend
npm test
```

Execute tests with Semgrep explicitly in `PATH`:
```bash
cd backend
PATH="$HOME/Library/Python/3.9/bin:$PATH" npm test
```

Test coverage includes:
- Valid Semgrep JSON parsing
- Empty and multiple findings handling
- Missing optional fields handling
- Malformed JSON recovery
- Severity and confidence mapping
- Relative file path normalization and traversal blocking
- Stable fingerprint computation
- Secret credential redaction in code evidence
- Provenance record structure and finding traceability
- Scanner unavailable handling without app crashes
- Execution timeout enforcement
- Stdout/stderr buffer limit enforcement
- Live execution on controlled fixture repository

---

## 9. Security Invariants & Limitations

1. **No Shell Interpolation:** Subprocesses are invoked strictly via `child_process.spawn` with an argument array. Shell interpreters (`sh`, `bash`) are never invoked.
2. **Workspace Confinement:** All target workspace paths are normalized and resolved. Non-existent directories, non-directories, and paths containing null bytes are rejected.
3. **No Script Execution:** Semgrep is executed in pure static analysis mode (`--config auto --json`). Repository scripts (`npm postinstall`, build scripts) are never executed.
4. **Environment Isolation:** Child processes only receive an essential whitelist of environment variables (`PATH`, `HOME`, `TMPDIR`, `LANG`). Production API credentials (`GEMINI_API_KEY`, `DATABASE_URL`) are never passed to the scanner subprocess.
5. **Memory Protection:** Stdout and stderr streams are capped at 25MB to prevent memory exhaustion from oversized outputs.
