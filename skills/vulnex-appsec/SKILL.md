---
name: vulnex-appsec
version: 1.0.0
description: Autonomous evidence-bounded application security remediation workflow. Detects vulnerabilities with static analysis, investigates root-causes using Google Gemma 4, generates minimal reviewable patches, and independently verifies fixes in disposable sandboxes.
author: Ayush Pratap Singh, Kumar Gaurav, Anand Maurya
tags:
  - security
  - appsec
  - gemma
  - semgrep
  - remediation
  - agent-skill
inputs:
  repositoryPath:
    type: string
    description: Absolute or relative path to the target source code repository
    required: true
  findingId:
    type: string
    description: Target finding identifier to investigate and remediate
    required: false
  model:
    type: string
    description: Google open-weight model identifier (e.g., gemma-2-9b-it)
    default: gemma-2-9b-it
outputs:
  status:
    type: string
    description: Final verification state (VERIFIED, FAILED, INCONCLUSIVE, PARTIAL)
  diff:
    type: string
    description: Minimal unified diff patch applying the security fix
  verificationEvidence:
    type: object
    description: Observed test results and post-patch scanner findings
---

# VULNEX AppSec Remediation Skill

VULNEX operates as an autonomous junior application security engineer following the **DETECT → INVESTIGATE → PATCH → VERIFY** closed remediation loop.

## 1. Capabilities & Workflow

1. **Deterministic Static Analysis (`detect`)**:
   - Executes Semgrep SAST process wrappers with strict argument arrays.
   - Extracts structured finding coordinates (file path, line bounds, rule ID, provenance).
   - Normalizes and deduplicates findings with deterministic fingerprints.

2. **Evidence-Bounded Investigation (`investigate`)**:
   - Leverages **Google Gemma 4 / Gemma 2** (`gemma-2-9b-it`) for root-cause analysis.
   - Enforces strict Data/Instruction separation: repository code is framed as untrusted data (`<untrusted_source_code>`).
   - Automatically scrubs API tokens, private keys, and passwords before prompt dispatch.
   - Outputs schema-validated JSON with explicit `confidence`, `evidence`, and `limitations`.

3. **Minimal Unified Diff Patching (`patch`)**:
   - Generates defensive patches resolving the root cause (e.g. converting string interpolation into parameterized queries).
   - Validates diff paths to prevent path traversal or unwanted file modifications.

4. **Independent Sandbox Verification (`verify`)**:
   - Applies the patch only to a temporary, disposable workspace (original repository is untouched).
   - Re-executes the scanner and regression tests.
   - Assigns honest verification states: `VERIFIED`, `FAILED`, `INCONCLUSIVE`, or `NOT_RUN`.

## 2. Model Configuration

Configured via environment variables in `backend/.env`:
- `GEMINI_API_KEY`: Google AI Studio API key (obtainable for free at https://aistudio.google.com/)
- `GEMINI_MODEL`: `gemma-2-9b-it` (or `gemma-2-27b-it`, `gemini-1.5-flash`)
- `AI_TIMEOUT_MS`: `15000` (15-second timeout with deterministic heuristic fallback)

## 3. Invocation Examples

### Investigating a Finding via API
```http
POST /api/findings/finding_sqli_101/investigate
Content-Type: application/json

{
  "codeContext": "router.get('/user', async (req, res) => { db.query(`SELECT * FROM users WHERE id = ${req.query.id}`); });"
}
```

### Verifying a Remediated Patch
```http
POST /api/patches/patch_404/verify
Content-Type: application/json

{
  "approved": true
}
```

## 4. Security Invariants
- Never executes arbitrary shell scripts on the host.
- Never mutates the original git repository directly.
- AI is probabilistic: it proposes fixes, but only actual test and re-scan passes authorize the `VERIFIED` status badge.
