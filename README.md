# VULNEX

**Autonomous Application Security & AI Patch Remediation Platform**

VULNEX bridges the gap between static vulnerability detection and verified code remediation. It pairs multi-engine static analysis with repository-isolated workspaces, evidence-bounded AI investigations powered by Google AI Studio (Gemma & Gemini), and dynamic unified diff patch generation with mandatory human-in-the-loop approval.

---

## 📺 Project Video Demo

Watch the complete demonstration of VULNEX in action:

**[▶️ Watch the VULNEX Walkthrough Video](https://www.youtube.com/watch?v=I3woCLfEXdM)**

---

## 🎯 Key Features

- **Repository-Isolated Multi-Engine Scanning**: Ingests Git repositories or archives into isolated disposable workspaces. Integrates Semgrep SAST rules with a custom syntax-aware detection engine to verify real database execution sinks (SQL injection) and contextual DOM sinks (XSS), eliminating false positives.
- **Evidence-Bounded AI Investigation**: Powered by Google AI Studio using **Gemma 4** (`gemma-4-26b-a4b-it`) and **Gemini**. Performs root-cause security investigations on exact source excerpts on disk, extracting exploit preconditions, realistic impact, and confidence scores while isolating model reasoning thoughts from structured schemas.
- **Dynamic Unified Diff Patch Generation**: Generates targeted, syntactically valid unified diffs directly addressing the vulnerable code (e.g., refactoring dynamic `innerHTML` to safe DOM elements with `textContent`, or converting string concatenations to parameterized SQL queries).
- **Mandatory Human-in-the-Loop Review Gate**: Every proposed patch defaults to `PENDING_REVIEW`. The interactive diff viewer highlights additions and deletions, protects against finding mismatches, and applies changes exclusively into disposable workspaces to keep production repositories untouched.
- **Truthful Verification Checklist**: Validates that patches resolve the original flaw without introducing regressions or modifying files outside the finding's scope.

---

## 🏗️ Architecture

```
                                  ┌───────────────────────────────┐
                                  │      VULNEX Web Console       │
                                  │   (React + Vite + Tailwind)   │
                                  └───────────────┬───────────────┘
                                                  │
                                                  ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   VULNEX Core API (Express)                                     │
├───────────────────────────────┬─────────────────────────────────┬───────────────────────────────┤
│       Scanner Engine          │      AI Investigation & Triage  │      Remediation Engine       │
│  - Semgrep SAST integration   │  - Google AI Studio Adapter     │  - Unified diff generator     │
│  - Syntax-Aware AST analyzer  │  - Gemma 4 reasoning isolation  │  - Human review state gate    │
│  - False-positive filters     │  - Strict Zod schema validation │  - Disposable workspace test  │
└───────────────┬───────────────┴────────────────┬────────────────┴───────────────┬───────────────┘
                │                                │                                │
                ▼                                ▼                                ▼
  ┌───────────────────────────┐    ┌───────────────────────────┐    ┌───────────────────────────┐
  │   Isolated Workspaces     │    │     Google AI Studio      │    │    Verification Engine    │
  │  (.workspaces/repo_*)     │    │  (Gemma 4 / Gemini API)   │    │  (Post-patch regression)  │
  └───────────────────────────┘    └───────────────────────────┘    └───────────────────────────┘
```

---

## 💻 Tech Stack

- **Backend**: Node.js, Express.js, Zod (schema validation), Semgrep CLI.
- **Frontend**: React 18, Vite, Tailwind CSS, Lucide Icons.
- **AI Models & Inference**: Google AI Studio API utilizing **Gemma 4** (`gemma-4-26b-a4b-it`) and **Gemini**.
- **Security & Sandbox**: Isolated temporary workspaces, strict path confinement, secret redaction, and rollback checkpoints.

---

## 🚀 Getting Started

### Prerequisites

- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher
- **Google AI Studio API Key**: (Optional for local deterministic fallback; required for live Gemma/Gemini inference)

### 1. Clone the Repository

```bash
git clone https://github.com/ayush09-15/VULNEX.git
cd VULNEX
```

### 2. Configure Environment

Create your environment configuration in `backend/.env`:

```env
PORT=5001
NODE_ENV=development
CORS_ORIGIN=http://localhost:5173
AI_MODEL=gemma-4-26b-a4b-it
AI_TIMEOUT_MS=45000
GEMINI_API_KEY=your_google_ai_studio_api_key_here
```

### 3. Install Dependencies

```bash
# Install backend dependencies
cd backend && npm install

# Install frontend dependencies
cd ../frontend && npm install
```

### 4. Run the Application

In terminal 1 (Backend):
```bash
cd backend
npm run dev
# Server starts on http://localhost:5001
```

In terminal 2 (Frontend):
```bash
cd frontend
npm run dev
# Web application starts on http://localhost:5173
```

---

## 🧪 Testing & Verification

VULNEX includes comprehensive test suites covering detection accuracy, AI response schema safety, and patch review gates:

```bash
# Run backend test suite (655+ tests)
npm test --prefix backend

# Run frontend test suite (48+ tests)
npm test --prefix frontend

# Run frontend production build
npm run build --prefix frontend
```

---

## 🛡️ Security Invariants

1. **Host Isolation**: Repository files are copied into isolated disposable workspaces (`backend/.workspaces/`) before scanning or patch application. Host root fallback is strictly rejected.
2. **Path Traversal Defense**: All diff headers and target file paths are sanitized to prevent directory traversal (`../`) and absolute path modification.
3. **No Unapproved Execution**: AI models cannot self-authorize patch application or execute shell commands. Patches strictly require explicit human review (`approved: true`).
4. **Secret Redaction**: Environment variables, API keys, and authorization tokens are automatically sanitized before logs or AI prompt dispatch.

---

## 🔮 Roadmap

- [ ] Direct automated GitHub & GitLab Pull Request creation for approved patches.
- [ ] Multi-language taint analysis expansion (Python, Go, Java, Rust).
- [ ] Ephemeral container runners for post-patch dynamic verification and regression testing.
- [ ] Native CI/CD pipeline blocking gates (GitHub Actions, GitLab CI).

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
