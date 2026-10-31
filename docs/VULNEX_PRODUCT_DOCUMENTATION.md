# VULNEX: Autonomous AI Software Security Engineer
## Complete Product, UX, Architecture, AI, Security and Operational Blueprint
### Canonical Multi-Page Documentation (v1.0.0)

---

<!-- PAGE BREAK: PAGE 1 -->
# [PAGE 1] System Overview, Product Identity & Architecture

## 1. Executive Summary & Problem Statement

Modern software security tooling inundates developers with hundreds of static alerts, high false-positive rates, and sparse contextual guidance. When developers turn to conversational Large Language Models (LLMs) for remediation, they face a different hazard: hallucinations, syntactically plausible yet broken patches, scope creep, and dangerous security regressions.

**VULNEX** is an autonomous, defensive AI software security engineering platform designed to act as a junior application security engineer for code repositories. Rather than treating an LLM as an unconstrained agent with direct host shell access, VULNEX establishes a **closed-loop remediation pipeline**:
1. **Deterministic Static Analysis:** Discovers security flaws and dependency vulnerabilities using established, audited security engines (Semgrep, `npm audit`).
2. **Context-Bounded AI Investigation:** Analyzes the exact vulnerability context using structured prompts and local fallback playbooks to assess root cause, exploitability, and impact without prompt injection risk.
3. **Surgical Unified Diff Proposals:** Generates minimal, standards-compliant unified diffs targeting only the vulnerable lines.
4. **Isolated Temporary Workspace Application:** Applies patches strictly inside ephemeral, disposable sandboxes (`.workspaces/ws_disposable_*`), never mutating the base repository.
5. **Empirical Dual-Gate Verification:** Runs automated test suites and re-scans the patched workspace to prove whether the issue is neutralized without causing regressions.

> **The Core VULNEX Invariant:** *Scanner output is evidence; AI output is an interpretation or proposal; test runs and re-scans are verification evidence. VULNEX never claims an entire codebase is secure because one finding disappeared or one unit test passed.*

---

## 2. The Bounded Orchestrator Architecture

A central design choice of VULNEX is the deliberate rejection of free-wheeling multi-agent swarms. Free-form multi-agent loops produce non-deterministic cascade failures, state corruption, infinite recursion loops, and unverifiable code modifications.

VULNEX replaces multi-agent chaos with a **Bounded Orchestrator with Deterministic Service Modules**:

```
+-----------------------------------------------------------------------------------+
|                                  VULNEX PLATFORM                                  |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +--------------------+         +--------------------+                            |
|  |   React 19 / Vite  | <=====> |   Express 4 API    | (Canonical JSON Envelope)  |
|  |  Tailwind CSS v4   |         |  Controllers/Auth  | (Global Request Tracing)   |
|  +--------------------+         +---------+----------+                            |
|                                           |                                       |
|                               +-----------v------------+                          |
|                               |   BOUNDED ORCHESTRATOR |                          |
|                               |  Rigid State Machine   |                          |
|                               +-----+----+-------+-----+                          |
|                                     |    |       |                                |
|        +----------------------------+    |       +-------------------------+      |
|        |                                 |                                 |      |
|  +-----v-------+                 +-------v------+                  +-------v----+ |
|  | REPOSITORY  |                 |  DETECTION   |                  | VERIFY &   | |
|  |  SERVICES   |                 |  & AI ENGINE |                  | SANDBOX    | |
|  +-------------+                 +--------------+                  +------------+ |
|  | - SSRF Guard|                 | - Semgrep AST|                  | - Dispos-  | |
|  | - Safe ZIP  |                 | - npm audit  |                  |   able WS  | |
|  |   Extractor |                 | - Normalizer |                  | - Runner   | |
|  | - Inventory |                 | - LLM Prompt |                  | - Rescan   | |
|  +-------------+                 +--------------+                  +------------+ |
+-----------------------------------------------------------------------------------+
```

### Core Architecture Components:
- **Thin Express Controllers:** Parse HTTP requests, validate input against strict Zod schemas, dispatch jobs to the bounded orchestrator or services, and wrap responses in the canonical JSON envelope (`{ success, data, requestId }`).
- **Deterministic State Machines:** Govern lifecycle transitions for Scans (`QUEUED` → `PREPARING` → `SCANNING` → `NORMALIZING` → `COMPLETED` / `PARTIAL` / `FAILED`), Findings (`DETECTED` → `TRIAGED` → `PATCH_PROPOSED` → `PATCH_APPLIED` → `VERIFIED`), and Patches (`GENERATED` → `VALIDATED` → `APPROVED` → `APPLIED_TO_TEMP` → `TESTING` → `VERIFIED`).
- **Pure-Function LLM Adapters:** The LLM is treated as a deterministic pure function (`PromptContext` → `ZodValidatedOutput`). The model never executes arbitrary commands or touches filesystem APIs.

---

## 3. Technology Stack & System Boundaries

| Subsystem | Technology Choice | Architectural Justification |
| :--- | :--- | :--- |
| **Backend Runtime** | Node.js 20+ (CommonJS) | Fast subprocess management, native JSON streaming, high concurrency for I/O bounds. |
| **HTTP Framework** | Express 4 | Minimalist, predictable middleware chain (`requestId` → `cors` → `bodyParser` → `routes` → `notFound` → `errorHandler`). |
| **Frontend Framework** | React 19 + Vite 8 | Instant hot module replacement, zero-lag client interactions, compact production bundle (<150kB gzipped). |
| **UI Styling** | Tailwind CSS v4 + Lucide React | High-contrast dark cyber-defense theme with WCAG AA accessibility compliance. |
| **Schema Validation** | Zod 3 | Type-safe runtime boundary enforcement on all ingress payloads, scanner outputs, and LLM responses. |
| **Static Code Analysis**| Semgrep OSS CLI | Deterministic AST matching across JavaScript/TypeScript without executing untrusted code. |
| **Dependency Audit** | `npm audit --json` | Authoritative National Vulnerability Database (NVD) & GitHub Advisory Database matching. |
| **Sandbox Execution** | Node child_process + restrictedRunner | Resource-bounded process execution with timeouts, output caps, environment sanitization, and isolated directories. |
| **Test Framework** | Native Node Test Runner (`node --test`) | Zero-dependency, ultra-fast test execution across 650+ unit, integration, and security tests. |

---

<!-- PAGE BREAK: PAGE 2 -->
# [PAGE 2] End-to-End Remediation Pipeline & AI Safety

## 1. The 5-Phase Closed-Loop Remediation Cycle

VULNEX executes security engineering as an unbroken, auditable chain across 5 discrete phases:

```
[ Phase 1: Intake ] ===> [ Phase 2: Detect ] ===> [ Phase 3: Investigate ]
         |                         |                          |
         v                         v                          v
  GitHub Clone /           Semgrep AST +             Bounded AI Prompt /
  ZIP Upload (Safe)        npm audit parser          Triage & Blast Radius
                                                              |
[ Phase 5: Verify ] <=== [ Phase 4: Patch ] <=================+
         |                         |
         v                         v
  Targeted Unit Tests +    Unified Diff Proposal +
  Post-Patch Rescan        Disposable Sandbox Apply
```

### Phase 1: Repository Intake & Ingestion
- Accepts target Node.js repositories via public/enterprise HTTPS GitHub URLs or uploaded ZIP archives.
- **SSRF Guard:** Rejects loopback (`127.0.0.1`), link-local (`169.254.169.254`), private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and non-HTTPS protocols before any network request occurs.
- **Safe ZIP Extraction:** Enforces canonical path verification, strictly defeating ZIP Slip directory traversal attempts (`../../`) and absolute entry paths.
- Generates repository inventory (file count, dependencies, package manifest).

### Phase 2: Detection & Finding Normalization
- Concurrently triggers Semgrep security rulesets and `npm audit --json`.
- **Fault-Tolerant Scanner Execution:** If one scanner fails (e.g., syntax error in a legacy file) but another succeeds, the scan transitions to `PARTIAL` rather than crashing, preserving all valid findings.
- **Canonical Finding Normalization:** Disparate scanner outputs are normalized into uniform `Finding` entities with rule IDs, relative file paths, 1-based line markers, scanner messages, and untouched code evidence snippets.
- **Deterministic Fingerprinting:** Computes SHA-256 hashes (`sha256(ruleId + ":" + filePath + ":" + normalizedSnippet)`) to track findings across multiple runs and prevent alert duplicates.

### Phase 3: Bounded AI Investigation
- Formulates a highly constrained prompt combining scanner evidence, relevant AST slice, and vulnerability taxonomy (CWE/OWASP).
- **Prompt Injection Defense:** Source code is encapsulated within strict `<untrusted_source_code>` fences with adversarial instruction filtering.
- **Secret Redaction:** Strips API keys, AWS credentials, JWT tokens, and connection strings before the prompt reaches any LLM.
- **Structured Diagnostic DTO:** The LLM produces a verified JSON structure: assessment (`LIKELY_TRUE`, `LIKELY_FALSE`, `UNCERTAIN`), root-cause explanation, blast radius, preconditions, and remediation recommendations.

### Phase 4: Patch Proposal & Sandboxed Application
- AI synthesizes a minimal, targeted **Unified Diff (`diff -u`)**.
- **Diff & Path Validator:** Validates hunk headers, line counters, and file paths. Rejects path traversal (`../`), absolute paths, binary diffs, and modifications outside the finding's declared scope.
- **Mandatory Human-in-the-Loop Approval:** Patch application requires explicit human review (`approved: true`). Any unconfirmed attempt is rejected with `403 Forbidden`.
- **Disposable Sandbox Execution:** Patches are applied strictly inside `.workspaces/ws_disposable_<id>/`. The base repository is **never** mutated.

### Phase 5: Dual-Gate Verification & Rescan
- **Targeted Test Execution:** Runs automated unit and integration tests inside the disposable workspace within a bounded execution window.
- **Post-Patch Rescan:** Re-executes the exact scanner rule against the patched file.
- **Truthful Status Classification:**
  - `PASSED`: Targeted tests passed AND original finding completely disappeared AND no new findings were introduced.
  - `FAILED`: Tests failed OR original vulnerability persists OR new defects appeared.
  - `INCONCLUSIVE`: Ambiguous fingerprint match or scanner engine unavailable.
  - `PARTIAL`: Some checks completed, others skipped.

---

## 2. AI Safety Model & Secret Redaction

VULNEX enforces strict defensive AI safety controls across every layer:

```
+---------------------------------------------------------------------------------+
|                               AI INGRESS DEFENSE                                |
+---------------------------------------------------------------------------------+
|  1. Untrusted Input Isolation:                                                  |
|     Source code wrapped in <untrusted_source_code file="..." lines="...">       |
|  2. System Instruction Primacy:                                                 |
|     System prompts instruct LLM to ignore instructions inside source code.     |
|  3. Automated Secret Redaction:                                                 |
|     AWS / GitHub / Stripe / Slack / DB URIs replaced with [REDACTED_SECRET].     |
|  4. Strict Zod Schema Enclosure:                                                |
|     LLM response must parse through AIInvestigationOutputSchema or reject.      |
|  5. Local Fallback Resilience:                                                  |
|     If API quota is exceeded or network drops, curated playbooks execute.       |
+---------------------------------------------------------------------------------+
```

---

<!-- PAGE BREAK: PAGE 3 -->
# [PAGE 3] Canonical API Contracts & Data Specifications

## 1. Common Response Envelope Specification

Every VULNEX API endpoint returns a deterministic JSON envelope with request tracing:

### Successful Response (`2xx`)
```json
{
  "success": true,
  "data": { ... },
  "requestId": "req_1730398200_a1b2c3d4"
}
```

### Error Response (`4xx` / `5xx`)
```json
{
  "success": false,
  "error": {
    "code": "APPROVAL_REQUIRED",
    "message": "Patch application requires explicit user approval (approved: true).",
    "details": []
  },
  "requestId": "req_1730398200_a1b2c3d4"
}
```

---

## 2. Complete REST Endpoint Reference

### Repository Management
- `POST /api/repositories`: Register a new repository (GitHub HTTPS URL or ZIP upload). Status: `201 Created`.
- `GET /api/repositories`: List registered repositories with pagination support. Status: `200 OK`.
- `GET /api/repositories/:id`: Retrieve single repository metadata and default branch. Status: `200 OK`.

### Scan Execution & Timeline
- `POST /api/scans`: Initiate a security scan with selectable engines (`semgrep`, `npm-audit`, `patterns`). Status: `202 Accepted`.
- `GET /api/scans`: List all scan execution records. Status: `200 OK`.
- `GET /api/scans/:id`: Retrieve scan details, timestamps, tool versions, and stage. Status: `200 OK`.
- `GET /api/scans/:id/events`: Retrieve real stage event timeline for progress tracking. Status: `200 OK`.
- `GET /api/scans/:id/findings`: Retrieve normalized findings for a scan with severity/scanner filters. Status: `200 OK`.
- `POST /api/scans/:id/cancel`: Cancel an active in-flight scan. Status: `200 OK`.

### Findings & AI Investigation
- `GET /api/findings`: List findings across all scans with query filters (`severity`, `category`, `scanner`, `status`). Status: `200 OK`.
- `GET /api/findings/:id`: Retrieve finding details, raw code snippet, and attached AI investigation. Status: `200 OK`.
- `POST /api/findings/:id/investigate`: Run evidence-bounded AI investigation on a finding. Status: `200 OK`.
- `POST /api/findings/:id/patches`: Synthesize reviewable unified diff patch proposal. Status: `200 OK`.

### Patches & Workspace Remediation
- `GET /api/patches`: List patch proposals with optional `findingId` or `status` filters. Status: `200 OK`.
- `GET /api/patches/:id`: Retrieve patch proposal, diff content, rationale, and review state. Status: `200 OK`.
- `POST /api/patches/:id/approve`: Explicit human approval of patch (`approved: true`). Status: `200 OK`.
- `POST /api/patches/:id/reject`: Human rejection of patch with documented rationale. Status: `200 OK`.
- `POST /api/patches/:id/apply`: Apply approved patch inside disposable workspace. Status: `200 OK`.
- `POST /api/patches/:id/verify`: Execute targeted test suite and post-patch scanner inside workspace. Status: `200 OK`.
- `POST /api/patches/:id/rollback`: Rollback disposable workspace to pristine snapshot. Status: `200 OK`.

### Reporting & Health
- `GET /api/scans/:id/report`: Retrieve consolidated audit report with findings, AI analysis, and verification checklist. Status: `200 OK`.
- `GET /api/scans/:id/export`: Export report in JSON, Markdown, SARIF, or CSV formats. Status: `200 OK`.
- `GET /api/scans/history`: Retrieve cross-scan historical metrics, tool breakdowns, and verification outcomes. Status: `200 OK`.
- `GET /api/health`: Subsystem liveness probe (API, Scanner Engine, AI Adapter). Status: `200 OK`.

---

## 3. Canonical Data Models

```
+---------------------------------------------------------------------------------+
|                             CANONICAL DATA ENTITIES                             |
+---------------------------------------------------------------------------------+
| Repository:    { id, sourceType, displayName, sanitizedSourceUrl, defaultRef }   |
| Scan:          { id, repositoryId, ref, status, stage, toolVersions, startedAt } |
| Finding:       { id, scanId, scanner, ruleId, title, category, severity,        |
|                  filePath, startLine, endLine, message, evidence, fingerprint } |
| Investigation: { id, findingId, model, assessment, explanation, impact,         |
|                  recommendation, confidence, limitations, createdAt }           |
| PatchProposal: { id, findingId, diff, rationale, changedFiles, reviewState }    |
| Verification:  { id, patchId, status, testResults, scannerResults, checklist }  |
| AuditEvent:    { id, actor, action, entityId, outcome, timestamp, requestId }   |
+---------------------------------------------------------------------------------+
```

---

<!-- PAGE BREAK: PAGE 4 -->
# [PAGE 4] Security Hardening, Verification Protocol & Operations

## 1. Security Invariants & Hardening Controls

VULNEX implements military-grade defensive controls to secure its own execution pipeline:

```
+---------------------------------------------------------------------------------+
|                        DEFENSIVE SECURITY ARCHITECTURE                          |
+---------------------------------------------------------------------------------+
|                                                                                 |
|  [ INGRESS BOUNDARY ]                                                           |
|  +-- SSRF Guard: Blocks RFC-1918, RFC-3927, Loopback, Cloud Metadata (169.254)  |
|  +-- ZIP Slip Guard: Rejects archive entries with '../', '~', or absolute paths |
|  +-- File Upload Guard: Enforces 25MB MAX_UPLOAD_MB and MIME validation        |
|                                                                                 |
|  [ EXECUTION BOUNDARY ]                                                         |
|  +-- Disposable Workspace: Patches applied to isolated .workspaces/ copies      |
|  +-- Path Confinement: Canonical realpath check ensures no symlink escapes      |
|  +-- Process Sandbox: Subprocesses spawned with argv arrays (no shell string)    |
|  +-- Resource Guard: Configurable execution timeouts and maxBuffer caps         |
|                                                                                 |
|  [ DATA & AUDIT BOUNDARY ]                                                      |
|  +-- Secret Redaction: Centralized redaction across logs, errors, AI, and APIs  |
|  +-- Approval Gate: Strict 403 Forbidden if approved !== true on patch apply    |
|  +-- Immutable Audit Log: Every registration, scan, patch, and verify recorded  |
+---------------------------------------------------------------------------------+
```

---

## 2. Verification Protocol & Checklist

VULNEX evaluates every code remediation against a 5-point verification checklist:

| Verification Check | Evaluation Criteria | Truthful Status |
| :--- | :--- | :--- |
| **1. Syntax & AST Validity** | Code parses cleanly without syntax or lexical errors. | `PASSED` / `FAILED` |
| **2. Targeted Test Suite** | Pre-existing unit tests pass without regression. | `PASSED` / `FAILED` |
| **3. Vulnerability Neutralized** | Re-scan confirms the targeted rule is no longer triggered. | `PASSED` / `FAILED` |
| **4. Fingerprint Eradication** | Original SHA-256 finding hash is absent from rescan. | `PASSED` / `INCONCLUSIVE` |
| **5. Zero Regressions** | No new vulnerabilities of equal or higher severity introduced. | `PASSED` / `FAILED` |

### Scoped Truthful Wording Standard
VULNEX reports strictly reflect empirical evidence. The platform emits scoped, truthful statements:
- *"Remediation verified: targeted Semgrep rule `express-sqli` was resolved and targeted unit tests passed (14/14)."*
- It **never** emits: *"The application is now completely secure and impenetrable."*

---

## 3. Operational Quickstart & Hackathon Demo Walkthrough

### Prerequisites
- Node.js v20.x or higher
- npm v10.x or higher
- Optional: Semgrep CLI (`brew install semgrep` or `pip install semgrep`)

### Local Setup & Execution
```bash
# 1. Clone the repository
git clone https://github.com/ayush09-15/VULNEX.git
cd VULNEX

# 2. Install dependencies
npm --prefix backend install
npm --prefix frontend install

# 3. Execute complete test suites (650+ tests)
npm --prefix backend test
npm --prefix frontend test

# 4. Build frontend for production
npm --prefix frontend run build

# 5. Start development servers
# Terminal 1: Backend API (port 5001)
npm --prefix backend run dev

# Terminal 2: Frontend Client (port 5173)
npm --prefix frontend run dev
```

### 3-Minute Hackathon Demo Script:
1. **Intake:** Open `http://localhost:5173`. Navigate to **Repositories**. Click **Register Repository** or choose the pre-loaded `intentionally-vulnerable-node-app`.
2. **Scan:** Click **Scan Now**. Observe the real-time stage progress (`QUEUED` → `PREPARING` → `SCANNING` → `NORMALIZING` → `COMPLETED`).
3. **Inspect:** Jump to **Findings**. Open the drawer on the CRITICAL SQL Injection finding. Observe the distinct separation between **Scanner Ground Truth** and **Contextual AI Investigation**.
4. **Patch:** Click **Generate Patch**. Review the syntax-highlighted Unified Diff. Click **Approve Patch** (`approved: true`).
5. **Apply & Verify:** Click **Apply to Temporary Workspace**. Notice the isolated workspace assignment (`ws_disposable_*`). Click **Run Verification**. Watch the 5-point checklist turn green as targeted tests pass and the rescan comes back clean.
6. **Report:** Navigate to **Reports**. Export the consolidated audit trail as a **Markdown** or **SARIF** report.

---
*VULNEX v1.0.0 — Autonomous AI Software Security Engineering Platform*
