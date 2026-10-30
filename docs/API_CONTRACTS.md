# VULNEX Canonical API Contracts

> **Document Status:** CANONICAL CONTRACT SPECIFICATION
> **Target Version:** VULNEX v1.0.0
> **Last Updated:** 2026-10-31
> **Applies to:** Backend (Express), Frontend (React/Vite), Orchestrator, CLI, and AI subagent modules.

---

## 1. Architectural Principles & Envelope Specification

All HTTP endpoints in VULNEX must adhere to a strict, predictable response contract. Raw database entities or uncaught internal exceptions must **never** leak across the HTTP boundary.

### 1.1 Common API Response Envelope

Every endpoint returns a JSON payload enclosed in a standard envelope.

#### A. Successful Response (`2xx`)

```json
{
  "success": true,
  "data": {},
  "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1B2"
}
```

- `success`: Always boolean `true`.
- `data`: Object, array, or null representing the canonical Data Transfer Object (DTO).
- `requestId`: Globally unique string identifier generated at request ingress (e.g., UUIDv4 or ULID prefixed with `req_`) for distributed tracing and audit correlation.

#### B. Failed Response (`4xx` / `5xx`)

```json
{
  "success": false,
  "error": {
    "code": "INVALID_INPUT",
    "message": "The supplied input is invalid."
  },
  "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1B2"
}
```

- `success`: Always boolean `false`.
- `error`: Structured object containing:
  - `code`: Stable, uppercase, machine-readable enumeration string (see Section 1.2).
  - `message`: Safe, human-readable description of the error.
  - `details` *(optional)*: Array of field-level validation errors or non-sensitive context.
- `requestId`: Matching request identifier from the ingress header or newly generated.

#### C. Envelope Security Rules

1. **No Stack Traces:** Stack traces, internal file paths (`/Users/...`, `/app/...`), or database engine exceptions must never be serialized into `error.message` or `details`.
2. **No Secret Leakage:** Access tokens, webhook secrets, database credentials, or API keys must be stripped before responses leave the controller.
3. **UTC Timestamps:** All dates and times across all payloads must be ISO 8601 UTC strings formatted as `YYYY-MM-DDTHH:mm:ss.sssZ`.
4. **Idempotency & Tracing:** The `X-Request-ID` HTTP header is accepted on ingress. If absent, backend middleware generates one. The response must mirror this identifier in the HTTP response header `X-Request-ID` and in the envelope's `requestId`.

---

### 1.2 Standard Machine-Readable Error Codes

| Error Code | HTTP Status | Description |
| :--- | :---: | :--- |
| `INVALID_INPUT` | 400 | Request validation failed (schema mismatch, missing required fields). |
| `INVALID_URL` | 400 | Provided repository URL fails protocol, hostname, or format validation. |
| `FILE_TOO_LARGE` | 400 / 413 | Uploaded ZIP archive exceeds configured size limit (`MAX_UPLOAD_MB`). |
| `UNSUPPORTED_ARCHIVE` | 400 | ZIP file is corrupted or contains illegal symlinks/path traversals. |
| `RESOURCE_NOT_FOUND` | 404 | Target repository, scan, finding, or patch ID does not exist. |
| `CONFLICT` | 409 | Resource state precludes requested action (e.g., scan already running). |
| `INVALID_STATE_TRANSITION` | 409 | Attempted entity state change violates the canonical state machine. |
| `APPROVAL_REQUIRED` | 403 | Attempted to apply patch without explicit user approval. |
| `WORKSPACE_ERROR` | 500 | Failed to prepare, isolate, or clean disposable workspace. |
| `SCANNER_FAILURE` | 502 | Upstream detection tool failed to execute. |
| `AI_SERVICE_UNAVAILABLE` | 503 | Upstream LLM provider failed, timed out, or rate-limited. |
| `INTERNAL_SERVER_ERROR` | 500 | Unhandled internal server exception. |

---

### 1.3 Authentication & Authorization Expectations

> **Current Implementation Status:** **Planned Boundary (Not Yet Implemented in Code)**
> The current local development prototype does not enforce authentication tokens or role-based access control. All existing endpoints are unauthenticated to facilitate rapid local multi-agent prototyping.

- **Planned Boundary:** Prior to multi-user or network-exposed deployment, an authentication middleware will be introduced requiring:
  - Header: `Authorization: Bearer <JWT_OR_API_KEY>`
  - Role checks: `ADMIN`, `OPERATOR`, `AUDITOR`.
- **Security Invariant:** Developers must write controller and service code keeping request context (`actorId`, `role`) passed through parameters, so authentication can be enforced without breaking canonical signatures.

---

## 2. Canonical Endpoint Specifications (13 Endpoints)

---

### 2.1 Repository APIs

#### 1. `POST /api/repositories`
- **Purpose:** Register a repository submitted through a supported GitHub URL or uploaded ZIP archive workflow.
- **Authentication:** Planned boundary (optional in local prototype).
- **Request Headers:**
  - `Content-Type: application/json` (for URL registration) OR `multipart/form-data` (for ZIP uploads).
  - `X-Request-ID: <string>` *(optional)*
- **Query Parameters:** None.
- **Request Body Schema (`application/json`):**
  | Field | Type | Required | Nullable | Description |
  | :--- | :--- | :---: | :---: | :--- |
  | `sourceType` | String (`"GITHUB"` \| `"ZIP_UPLOAD"`) | Yes | No | Source mechanism of repository. |
  | `displayName` | String (1..100 chars) | Yes | No | User-friendly label for the project. |
  | `sourceUrl` | String (URL) | Conditional | Yes | Required if `sourceType` is `"GITHUB"`. Must be valid HTTPS Git URL. |
  | `defaultRef` | String | No | No | Branch, tag, or commit to target (default: `"main"`). |
- **Validation Rules:**
  - `sourceUrl` must start with `https://github.com/` (or configured allowed hosts).
  - Internal network URLs (e.g., `http://localhost`, `http://127.0.0.1`, `http://169.254.169.254`) must be rejected.
  - Path traversal indicators (`../`, `~`) in `displayName` are sanitized.
- **Successful Status:** `201 Created`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "id": "repo_01JAZZ80001",
      "sourceType": "GITHUB",
      "displayName": "juice-shop-sample",
      "sanitizedSourceUrl": "https://github.com/juice-shop/juice-shop",
      "defaultRef": "main",
      "createdAt": "2026-10-31T03:00:00.000Z"
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1B2"
  }
  ```
- **Error Responses:**
  - `400 Bad Request` (`INVALID_INPUT`, `INVALID_URL`): Malformed JSON, missing fields, or invalid URL.
  - `413 Payload Too Large` (`FILE_TOO_LARGE`): ZIP upload exceeds `MAX_UPLOAD_MB`.
- **Dependencies:** Repository Service (`repositories/`).
- **State Changes:** Persists new `Repository` entity record.

---

#### 2. `GET /api/repositories`
- **Purpose:** List all registered repositories.
- **Authentication:** Planned boundary.
- **Request Headers:** `X-Request-ID: <string>` *(optional)*
- **Query Parameters:**
  | Parameter | Type | Required | Default | Description |
  | :--- | :--- | :---: | :---: | :--- |
  | `page` | Integer | No | `1` | Pagination page number (>= 1). |
  | `limit` | Integer | No | `20` | Items per page (1..100). |
- **Request Body:** None.
- **Successful Status:** `200 OK`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": [
      {
        "id": "repo_01JAZZ80001",
        "sourceType": "GITHUB",
        "displayName": "juice-shop-sample",
        "sanitizedSourceUrl": "https://github.com/juice-shop/juice-shop",
        "defaultRef": "main",
        "createdAt": "2026-10-31T03:00:00.000Z"
      }
    ],
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1B3"
  }
  ```
- **Error Responses:**
  - `400 Bad Request` (`INVALID_INPUT`): Negative or invalid pagination numbers.
- **Dependencies:** Repository Service.
- **State Changes:** None (Read-only).

---

#### 3. `GET /api/repositories/:id`
- **Purpose:** Retrieve details of a single registered repository by ID.
- **Authentication:** Planned boundary.
- **Path Parameters:**
  - `id` (String, required): Canonical repository identifier (e.g., `repo_01JAZZ80001`).
- **Query Parameters:** None.
- **Request Body:** None.
- **Successful Status:** `200 OK`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "id": "repo_01JAZZ80001",
      "sourceType": "GITHUB",
      "displayName": "juice-shop-sample",
      "sanitizedSourceUrl": "https://github.com/juice-shop/juice-shop",
      "defaultRef": "main",
      "createdAt": "2026-10-31T03:00:00.000Z"
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1B4"
  }
  ```
- **Error Responses:**
  - `404 Not Found` (`RESOURCE_NOT_FOUND`): Repository ID does not exist.
- **Dependencies:** Repository Service.
- **State Changes:** None (Read-only).

---

### 2.2 Scan APIs

#### 4. `POST /api/scans`
- **Purpose:** Initiate a security scan for a registered repository.
- **Authentication:** Planned boundary.
- **Request Headers:**
  - `Content-Type: application/json`
  - `X-Request-ID: <string>` *(optional)*
- **Query Parameters:** None.
- **Request Body Schema (`application/json`):**
  | Field | Type | Required | Nullable | Description |
  | :--- | :--- | :---: | :---: | :--- |
  | `repositoryId` | String | Yes | No | ID of registered repository to scan. |
  | `ref` | String | No | Yes | Specific Git ref (branch/commit) or null for repository default. |
  | `scanners` | Array of Strings | No | No | Specific scanners to invoke (e.g., `["semgrep", "custom-heuristic"]`). If omitted, all enabled scanners run. |
- **Validation Rules:**
  - `repositoryId` must reference an existing repository.
  - Max concurrent scans check enforced (`MAX_CONCURRENT_SCANS`).
- **Successful Status:** `202 Accepted`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "id": "scan_01JAZZ80002",
      "repositoryId": "repo_01JAZZ80001",
      "ref": "main",
      "status": "QUEUED",
      "stage": "QUEUED",
      "toolVersions": {
        "semgrep": "1.70.0",
        "custom-heuristic": "1.0.0"
      },
      "startedAt": null,
      "completedAt": null,
      "errorCode": null,
      "createdAt": "2026-10-31T03:01:00.000Z"
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1B5"
  }
  ```
- **Error Responses:**
  - `400 Bad Request` (`INVALID_INPUT`): Missing `repositoryId`.
  - `404 Not Found` (`RESOURCE_NOT_FOUND`): `repositoryId` not found.
  - `409 Conflict` (`CONFLICT`): An active scan is already in progress for this repository.
- **Dependencies:** Orchestrator, Repository Service, Detection Service.
- **State Changes:** Creates `Scan` record in state `QUEUED`; dispatches async orchestration job.

---

#### 5. `GET /api/scans/:id`
- **Purpose:** Retrieve scan status, execution stage, progress timestamps, events, and error details.
- **Authentication:** Planned boundary.
- **Path Parameters:**
  - `id` (String, required): Scan identifier (e.g., `scan_01JAZZ80002`).
- **Query Parameters:** None.
- **Request Body:** None.
- **Successful Status:** `200 OK`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "id": "scan_01JAZZ80002",
      "repositoryId": "repo_01JAZZ80001",
      "ref": "main",
      "status": "COMPLETED",
      "stage": "COMPLETED",
      "toolVersions": {
        "semgrep": "1.70.0",
        "custom-heuristic": "1.0.0"
      },
      "startedAt": "2026-10-31T03:01:02.000Z",
      "completedAt": "2026-10-31T03:01:45.000Z",
      "errorCode": null,
      "createdAt": "2026-10-31T03:01:00.000Z"
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1B6"
  }
  ```
- **Error Responses:**
  - `404 Not Found` (`RESOURCE_NOT_FOUND`): Scan ID does not exist.
- **Dependencies:** Orchestrator, Persistence layer.
- **State Changes:** None (Read-only).

---

#### 6. `GET /api/scans/:id/findings`
- **Purpose:** Retrieve normalized security findings produced by a scan with robust filtering support.
- **Authentication:** Planned boundary.
- **Path Parameters:**
  - `id` (String, required): Scan identifier.
- **Query Parameters:**
  | Parameter | Type | Required | Description |
  | :--- | :--- | :---: | :--- |
  | `severity` | String | No | Filter by severity: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"INFO"`. |
  | `category` | String | No | Filter by category: `"INJECTION"`, `"BROKEN_AUTH"`, `"SENSITIVE_DATA_EXPOSURE"`, etc. |
  | `filePath` | String | No | Substring or exact match on target file path. |
  | `scanner` | String | No | Filter by scanner name (e.g., `"semgrep"`). |
  | `status` | String | No | Filter by finding state: `"DETECTED"`, `"TRIAGED"`, `"PATCH_PROPOSED"`, etc. |
- **Request Body:** None.
- **Successful Status:** `200 OK`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": [
      {
        "id": "find_01JAZZ80003",
        "scanId": "scan_01JAZZ80002",
        "scanner": "semgrep",
        "ruleId": "javascript.express.security.audit.sqli.express-sqli",
        "title": "SQL Injection in User Query Handler",
        "category": "INJECTION",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "filePath": "src/controllers/user.controller.js",
        "startLine": 42,
        "endLine": 45,
        "message": "User input directly concatenated into database query without parameterization.",
        "evidence": {
          "codeSnippet": "const query = `SELECT * FROM users WHERE id = '${req.params.id}'`;\ndb.query(query);",
          "rawMatch": { "cwe": "CWE-89", "owasp": "A03:2021-Injection" }
        },
        "fingerprint": "a3f5b78d234e7c10b78d234e7c10b78d234e7c10b78d234e7c10b78d234e7c10",
        "status": "DETECTED",
        "createdAt": "2026-10-31T03:01:25.000Z"
      }
    ],
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1B7"
  }
  ```
- **Error Responses:**
  - `404 Not Found` (`RESOURCE_NOT_FOUND`): Scan ID not found.
  - `400 Bad Request` (`INVALID_INPUT`): Unknown filter values provided.
- **Dependencies:** Detection Service, Normalizer, Persistence layer.
- **State Changes:** None (Read-only).

---

### 2.3 Finding APIs

#### 7. `GET /api/findings/:id`
- **Purpose:** Retrieve complete details of a single finding, including scanner evidence, line markers, and attached AI investigation data (if previously generated).
- **Authentication:** Planned boundary.
- **Path Parameters:**
  - `id` (String, required): Finding identifier (e.g., `find_01JAZZ80003`).
- **Query Parameters:** None.
- **Request Body:** None.
- **Successful Status:** `200 OK`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "id": "find_01JAZZ80003",
      "scanId": "scan_01JAZZ80002",
      "scanner": "semgrep",
      "ruleId": "javascript.express.security.audit.sqli.express-sqli",
      "title": "SQL Injection in User Query Handler",
      "category": "INJECTION",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "filePath": "src/controllers/user.controller.js",
      "startLine": 42,
      "endLine": 45,
      "message": "User input directly concatenated into database query without parameterization.",
      "evidence": {
        "codeSnippet": "const query = `SELECT * FROM users WHERE id = '${req.params.id}'`;\ndb.query(query);",
        "rawMatch": { "cwe": "CWE-89" }
      },
      "fingerprint": "a3f5b78d234e7c10b78d234e7c10b78d234e7c10b78d234e7c10b78d234e7c10",
      "status": "TRIAGED",
      "createdAt": "2026-10-31T03:01:25.000Z",
      "investigation": {
        "id": "inv_01JAZZ80004",
        "model": "gemini-1.5-pro",
        "promptVersion": "v1.2.0",
        "assessment": "High probability true positive. Input flows from req.params to db.query unescaped.",
        "explanation": "Dynamic string interpolation allows SQL control characters to modify query syntax.",
        "impact": "Unauthenticated database read/write access and authentication bypass.",
        "recommendation": "Use parameterized queries with db.query('SELECT * FROM users WHERE id = ?', [id]).",
        "confidence": 0.95,
        "limitations": ["Assumes default MySQL/Postgres driver without internal ORM escaping."],
        "createdAt": "2026-10-31T03:02:10.000Z"
      }
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1B8"
  }
  ```
- **Error Responses:**
  - `404 Not Found` (`RESOURCE_NOT_FOUND`): Finding ID does not exist.
- **Dependencies:** Detection Service, Investigation Service, Persistence layer.
- **State Changes:** None (Read-only).

---

#### 8. `POST /api/findings/:id/investigate`
- **Purpose:** Request deep AI-assisted root-cause analysis and contextual investigation for a specific finding.
- **Authentication:** Planned boundary.
- **Path Parameters:**
  - `id` (String, required): Finding identifier.
- **Request Headers:**
  - `Content-Type: application/json`
  - `X-Request-ID: <string>` *(optional)*
- **Query Parameters:** None.
- **Request Body Schema (`application/json`):**
  | Field | Type | Required | Nullable | Description |
  | :--- | :--- | :---: | :---: | :--- |
  | `additionalContext` | String | No | Yes | Optional developer notes or surrounding architectural context. |
- **Validation Rules:**
  - Target finding must exist in state `DETECTED` or `TRIAGED`.
- **Successful Status:** `200 OK`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "id": "inv_01JAZZ80004",
      "findingId": "find_01JAZZ80003",
      "model": "gemini-1.5-pro",
      "promptVersion": "v1.2.0",
      "assessment": "Confirmed true positive. User controller passes req.params.id unescaped to database query.",
      "explanation": "Dynamic string construction permits SQL injection allowing unauthorized reads.",
      "impact": "Full database read compromise.",
      "recommendation": "Refactor to parameterized query syntax.",
      "confidence": 0.95,
      "limitations": [
        "Analysis based on AST snippet; downstream ORM middleware was not evaluated."
      ],
      "createdAt": "2026-10-31T03:02:10.000Z"
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1B9"
  }
  ```
- **Error Responses:**
  - `404 Not Found` (`RESOURCE_NOT_FOUND`): Finding ID not found.
  - `503 Service Unavailable` (`AI_SERVICE_UNAVAILABLE`): LLM API timeout or quota exceeded.
- **Dependencies:** AI Investigation Service (`ai.service.js`), Orchestrator.
- **State Changes:** Transitions Finding state from `DETECTED` to `TRIAGED`; creates `Investigation` record; records `AuditEvent`.

---

### 2.4 Patch APIs

#### 9. `POST /api/findings/:id/patches`
- **Purpose:** Generate a reviewable code patch proposal for a finding.
- **Authentication:** Planned boundary.
- **Path Parameters:**
  - `id` (String, required): Finding identifier.
- **Request Headers:**
  - `Content-Type: application/json`
  - `X-Request-ID: <string>` *(optional)*
- **Query Parameters:** None.
- **Request Body Schema (`application/json`):**
  | Field | Type | Required | Nullable | Description |
  | :--- | :--- | :---: | :---: | :--- |
  | `instructions` | String | No | Yes | Optional constraints (e.g., "Use pg-promise prepared statements"). |
- **Validation Rules:**
  - Finding must exist and be in state `DETECTED` or `TRIAGED`.
- **Successful Status:** `201 Created`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "id": "patch_01JAZZ80005",
      "findingId": "find_01JAZZ80003",
      "diff": "--- a/src/controllers/user.controller.js\n+++ b/src/controllers/user.controller.js\n@@ -42,3 +42,3 @@\n-  const query = `SELECT * FROM users WHERE id = '${req.params.id}'`;\n-  db.query(query);\n+  const query = 'SELECT * FROM users WHERE id = ?';\n+  db.query(query, [req.params.id]);\n",
      "rationale": "Replaces vulnerable dynamic string interpolation with parameterized query placeholders, neutralizing SQL injection.",
      "status": "GENERATED",
      "changedFiles": [
        "src/controllers/user.controller.js"
      ],
      "appliedWorkspaceId": null,
      "createdAt": "2026-10-31T03:03:00.000Z"
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1C0"
  }
  ```
- **Error Responses:**
  - `404 Not Found` (`RESOURCE_NOT_FOUND`): Finding ID not found.
  - `422 Unprocessable Entity` (`INVALID_INPUT`): AI failed to generate valid diff syntax.
  - `503 Service Unavailable` (`AI_SERVICE_UNAVAILABLE`): Upstream LLM provider unavailable.
- **Dependencies:** Patch Service (`patch.service.js`), AI Service, Orchestrator.
- **State Changes:** Creates `Patch` in state `GENERATED`; transitions Finding state to `PATCH_PROPOSED`.

---

#### 10. `POST /api/patches/:id/apply`
- **Purpose:** Apply an explicitly approved patch into an **isolated, disposable temporary workspace**.
- **Security Invariant:** **Never applies directly to the user's primary source directory or original repository.**
- **Authentication:** Planned boundary.
- **Path Parameters:**
  - `id` (String, required): Patch identifier (e.g., `patch_01JAZZ80005`).
- **Request Headers:**
  - `Content-Type: application/json`
  - `X-Request-ID: <string>` *(optional)*
- **Query Parameters:** None.
- **Request Body Schema (`application/json`):**
  | Field | Type | Required | Nullable | Description |
  | :--- | :--- | :---: | :---: | :--- |
  | `approved` | Boolean | Yes | No | Explicit approval flag. Must be strictly `true`. |
  | `approverComments` | String | No | Yes | Optional rationale or audit note. |
- **Validation Rules:**
  - `approved` must be literal boolean `true`. If `false` or missing, return `403 Forbidden` (`APPROVAL_REQUIRED`).
  - Patch must be in state `GENERATED` or `VALIDATED`.
- **Successful Status:** `200 OK`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "id": "patch_01JAZZ80005",
      "findingId": "find_01JAZZ80003",
      "status": "APPLIED_TO_TEMP",
      "appliedWorkspaceId": "ws_disposable_01JAZZ80099",
      "changedFiles": [
        "src/controllers/user.controller.js"
      ],
      "appliedAt": "2026-10-31T03:03:45.000Z"
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1C1"
  }
  ```
- **Error Responses:**
  - `400 Bad Request` (`INVALID_INPUT`): Invalid body schema.
  - `403 Forbidden` (`APPROVAL_REQUIRED`): Patch application requested without explicit approval (`approved !== true`).
  - `404 Not Found` (`RESOURCE_NOT_FOUND`): Patch ID does not exist.
  - `409 Conflict` (`CONFLICT`): Patch diff failed to apply cleanly to disposable workspace (merge conflict).
  - `500 Internal Server Error` (`WORKSPACE_ERROR`): Workspace cloning or file system isolation failure.
- **Dependencies:** Patch Service, Workspace Sandbox Manager, Orchestrator.
- **State Changes:** Clones repository to `.workspaces/<workspaceId>`; applies patch; updates Patch entity state to `APPLIED_TO_TEMP`; updates Finding entity state to `PATCH_APPLIED`; logs `AuditEvent`.

---

#### 11. `POST /api/patches/:id/verify`
- **Purpose:** Run targeted automated tests and post-patch security rescans inside the disposable workspace to verify vulnerability remediation and prevent regressions.
- **Authentication:** Planned boundary.
- **Path Parameters:**
  - `id` (String, required): Patch identifier.
- **Request Headers:**
  - `Content-Type: application/json`
  - `X-Request-ID: <string>` *(optional)*
- **Query Parameters:** None.
- **Request Body Schema (`application/json`):**
  | Field | Type | Required | Nullable | Description |
  | :--- | :--- | :---: | :---: | :--- |
  | `testSuite` | String | No | Yes | Specific test suite name or command to execute. |
- **Validation Rules:**
  - Patch must be in state `APPLIED_TO_TEMP`.
- **Successful Status:** `200 OK`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "id": "ver_01JAZZ80006",
      "patchId": "patch_01JAZZ80005",
      "status": "PASSED",
      "testResults": {
        "syntaxValid": true,
        "testsExecuted": 14,
        "passed": 14,
        "failed": 0,
        "durationMs": 420
      },
      "scannerResults": {
        "originalFindingResolved": true,
        "ruleId": "javascript.express.security.audit.sqli.express-sqli",
        "newFindingsCount": 0,
        "newFindings": []
      },
      "beforeAfterComparison": {
        "astDifferenceVerified": true,
        "regressionDetected": false
      },
      "logsReference": "logs/verification_01JAZZ80006.log",
      "createdAt": "2026-10-31T03:04:15.000Z"
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1C2"
  }
  ```
- **Error Responses:**
  - `404 Not Found` (`RESOURCE_NOT_FOUND`): Patch ID does not exist.
  - `409 Conflict` (`INVALID_STATE_TRANSITION`): Patch is not in `APPLIED_TO_TEMP` state.
  - `500 Internal Server Error` (`WORKSPACE_ERROR`): Verification test execution failed catastrophically.
- **Dependencies:** Verification Service (`verification.service.js`), Scanner Service, Test Runner, Orchestrator.
- **State Changes:** Updates Verification record; transitions Patch state to `VERIFIED` (or `FAILED`); transitions Finding state to `VERIFIED` (or `FAILED`); records `AuditEvent`.

---

### 2.5 Report API

#### 12. `GET /api/scans/:id/report`
- **Purpose:** Retrieve a consolidated, audit-ready security report containing scan metadata, detected findings, AI root-cause assessments, patch outcomes, and verification evidence.
- **Authentication:** Planned boundary.
- **Path Parameters:**
  - `id` (String, required): Scan identifier.
- **Query Parameters:**
  | Parameter | Type | Required | Description |
  | :--- | :--- | :---: | :--- |
  | `format` | String | No | `"json"` (default). Planned future formats: `"pdf"`, `"sarif"`. |
- **Request Body:** None.
- **Successful Status:** `200 OK`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "scan": {
        "id": "scan_01JAZZ80002",
        "repositoryId": "repo_01JAZZ80001",
        "ref": "main",
        "status": "COMPLETED",
        "startedAt": "2026-10-31T03:01:02.000Z",
        "completedAt": "2026-10-31T03:01:45.000Z",
        "summary": {
          "totalFindings": 1,
          "critical": 1,
          "high": 0,
          "medium": 0,
          "low": 0,
          "remediated": 1
        }
      },
      "findings": [
        {
          "id": "find_01JAZZ80003",
          "ruleId": "javascript.express.security.audit.sqli.express-sqli",
          "severity": "CRITICAL",
          "filePath": "src/controllers/user.controller.js",
          "status": "VERIFIED",
          "investigation": {
            "assessment": "High probability true positive.",
            "impact": "Unauthenticated database read/write access."
          },
          "patch": {
            "id": "patch_01JAZZ80005",
            "status": "VERIFIED",
            "diff": "--- a/src/controllers/user.controller.js\n+++ b/src/controllers/user.controller.js\n@@ -42,3 +42,3 @@\n-  const query = `SELECT * FROM users WHERE id = '${req.params.id}'`;\n-  db.query(query);\n+  const query = 'SELECT * FROM users WHERE id = ?';\n+  db.query(query, [req.params.id]);\n"
          },
          "verification": {
            "status": "PASSED",
            "originalFindingResolved": true,
            "regressionDetected": false
          }
        }
      ]
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1C3"
  }
  ```
- **Error Responses:**
  - `404 Not Found` (`RESOURCE_NOT_FOUND`): Scan ID does not exist.
- **Dependencies:** Orchestrator, Reporting Service, Persistence layer.
- **State Changes:** None (Read-only).

---

### 2.6 Health API

#### 13. `GET /api/health`
- **Purpose:** Health check and readiness probe for the VULNEX backend, returning subsystem status without exposing internal paths, environmental variables, or credentials.
- **Authentication:** None (Public).
- **Request Headers:** None.
- **Path Parameters:** None.
- **Query Parameters:** None.
- **Request Body:** None.
- **Successful Status:** `200 OK`
- **Successful Response Example:**
  ```json
  {
    "success": true,
    "data": {
      "status": "UP",
      "version": "1.0.0",
      "timestamp": "2026-10-31T03:00:00.000Z",
      "services": {
        "api": "healthy",
        "scannerEngine": "healthy",
        "aiProvider": "configured"
      }
    },
    "requestId": "req_01HZX87K79W9E2V6G9C5Q3A1C4"
  }
  ```
- **Error Responses:**
  - `503 Service Unavailable`: Critical subsystem is unrecoverable.
- **Dependencies:** Health check utility.
- **State Changes:** None (Read-only).

---

## 3. Existing Non-Canonical Endpoints in Codebase

During the repository analysis, several endpoints were identified in the working prototype that depart from the canonical contract. They are documented here to prevent silent breaking changes, facilitate backward compatibility, and guide future deprecation.

| HTTP Method | Existing Path | Source File | Current Purpose & Implementation Status | Canonical Scope Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `DELETE` | `/api/repositories/:id` | `repository.routes.js` | Deletes repository from in-memory store. Implemented in prototype. | **Retain as Non-Canonical Utility:** Useful for local testing; should be reviewed before production RBAC. |
| `GET` | `/api/scans` | `scan.routes.js` | Lists all scans across all repositories. Calls empty `scannerService.listScans()`. | **Retain as Optional Diagnostic Endpoint:** Review whether listing should be nested under `GET /api/repositories/:id/scans`. |
| `DELETE` | `/api/scans/:id` | `scan.routes.js` | Deletes scan record. Implemented in prototype. | **Deprecate / Review Later:** Deleting scans compromises auditability. Planned for removal. |
| `GET` | `/api/findings` | `finding.routes.js` | Lists findings across all scans with query filters. | **Retain for Global Dashboard View:** Kept as supplementary endpoint alongside canonical `GET /api/scans/:id/findings`. |
| `POST` | `/api/findings/:id/rollback` | `finding.routes.js` | Restores backup file (`.vulnex.bak`) directly on host filesystem. | **Deprecate & Replace:** Directly violates workspace sandboxing rule. Rollbacks in canonical architecture are achieved by destroying the disposable workspace. |
| `POST` | `/api/findings/:id/analyze` | `finding.routes.js` | Prototype route for AI root-cause analysis. | **Migrate to Canonical:** Replace with `POST /api/findings/:id/investigate`. |
| `POST` | `/api/findings/:id/generate-patch`| `finding.routes.js` | Prototype route for patch generation. | **Migrate to Canonical:** Replace with `POST /api/findings/:id/patches`. |
| `POST` | `/api/findings/:id/apply-patch` | `finding.routes.js` | Prototype route for patch application. Applies directly to host disk. | **Migrate to Canonical:** Replace with `POST /api/patches/:id/apply` (pointing to patch ID, strictly disposable workspace). |
| `POST` | `/api/findings/:id/verify-patch`| `finding.routes.js` | Prototype route for patch verification. | **Migrate to Canonical:** Replace with `POST /api/patches/:id/verify`. |

---

## 4. Contract Governance & Change Protocol

These contracts are collaboratively maintained by:
- **Ayush Pratap Singh:** Orchestrator + Investigation
- **Gaurav:** Repository Intelligence + Patch
- **Anand Maurya:** Detection + Verification

### 4.1 Change Procedure
No developer or AI subagent may unilaterally alter:
1. HTTP route paths or methods.
2. Field names in the common response envelope.
3. Property names or nullability rules in canonical DTOs.
4. Allowed state machine enum values.

Any proposed modification requires:
1. Written rationale identifying affected backend, frontend, and test files.
2. Formal PR review and approval from all three team leads.
3. Simultaneous update of `API_CONTRACTS.md`, `DATA_MODELS.md`, and `ARCHITECTURE.md`.
