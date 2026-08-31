# 🛡️ KAVACH

**A closed-loop, AI-assisted vulnerability defense system for both software and hardware source code — built for the AI Kavach challenge (defence & national security track).**

KAVACH ingests source code — C/C++, Python, JavaScript on the software side; Verilog and VHDL on the hardware side — statically analyzes it for known danger patterns, synthesizes a minimal-diff patch where one can be safely generated, routes anything sensitive through a mandatory human review gate, and (for its benchmark targets) proves the fix actually works via a Triple-Lock verification pipeline before writing anything to a hash-chained, tamper-evident audit ledger.

🔗 Live dashboard: [rakshak-1-83j2.onrender.com](https://rakshak-1-83j2.onrender.com)

---

## Why KAVACH

Manually triaging and patching vulnerabilities in defence-adjacent codebases doesn't scale, and blind auto-patching is not an option when the code in question could end up running on real infrastructure. KAVACH is built around one governing idea: **automate what can be proven, and gate what can't.**

- Finds known-dangerous patterns across five languages spanning two fundamentally different pipelines — software (compiled/interpreted, provably testable) and hardware (RTL, not provable in this environment)
- Synthesizes a fix wherever a safe, minimal-diff template exists — and is explicit, not silent, about the cases where one doesn't
- **Never** auto-applies a change without proof it works: the software pipeline's Triple-Lock (exploit replay + regression suite + clean rebuild) has to pass before anything is marked certified
- **Never** auto-applies a change that can't be proven at all: every hardware finding, and every finding touching credentials, crypto, access control, or marked CRITICAL, is routed to a human — unconditionally, regardless of whether a suggested fix exists
- Keeps every decision — certified, rejected, or pending human review — in a SHA-256 hash-chained ledger, so the audit trail itself can't be silently edited after the fact

---

## Architecture

```
                    Operator Dashboard (HTML/JS)
                              │
                        HTTPS (FastAPI)
                              │
                     FastAPI Backend (backend/app)
                              │
              ┌───────────────┴───────────────┐
              │                                │
     Language Detection              Benchmark Orchestrator
     (extension + content-sniff)     (state machine, retry/backtrack)
              │                                │
     Static Analyzer                  Patch Agent
     (per-language danger rules)      (heuristic → generic pattern → LLM)
              │                                │
              └───────────────┬────────────────┘
                               │
                       Human Review Gate
        (hardware pipeline · high-risk CWE · sensitive keyword ·
                      CRITICAL severity)
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
        Triple-Lock Verifier         (hardware: no verifier —
    (exploit replay · regression ·    always routed to a human,
        clean rebuild)                 fix or no fix available)
                 │                           │
                 └─────────────┬─────────────┘
                               │
              Hash-Chained Audit Ledger (SQLite)
                               │
              Ledger view + per-record HTML report export
```

**Design principle:** a finding is either *proven* safe to auto-apply (software pipeline, passed Triple-Lock) or it goes to a human — there is no third option. Hardware findings are gated unconditionally, independent of severity or whether a fix template exists, because no synthesizer or simulator in this environment can prove an RTL change correct.

---

## Core Features

| Module | What it does |
|---|---|
| **Multi-language static analysis** | Regex-based danger-pattern rules across C/C++, Python, JavaScript, Verilog, and VHDL — no AST/parser dependency, so it runs air-gapped |
| **Auto language & pipeline detection** | Detects language from file extension, falling back to content-sniffing (`module`/`endmodule`, `entity`/`architecture`, etc.); routes each finding to the software or hardware pipeline automatically |
| **Multi-file upload & analysis** | Analyze several files — software, hardware, or a mix — in a single pass, with independent findings and independent suggested fixes per file |
| **Patch synthesis** | Three-tier fallback: hand-written heuristics for the benchmark targets → generic mechanically-safe pattern fixes (NULL-guards, overflow checks, secret→env-var swaps, HDL debug-fuse gating, HDL key redaction) → optional LLM-assisted patching for anything else |
| **Human review gate** | A finding is gated if it's in the hardware pipeline, its CWE falls in a high-risk category (credentials, crypto, access control, hardware-security design flaws), its file/function name matches a sensitive keyword, or it's marked CRITICAL — reasons are always shown in full, never just the first one that fired |
| **Triple-Lock verification** | For the benchmark C targets: exploit replay against an ASan build, a functional regression suite, and a final clean (no-sanitizer) rebuild — all three have to pass before a patch is marked `certified` |
| **Per-finding retry/backtrack** | The orchestrator retries a failed patch up to a configured limit, rolling back cleanly between attempts, without blocking unrelated findings |
| **Hash-chained audit ledger** | Every outcome — `certified`, `rejected`, `pending_review`, `suggested_included` — is recorded with a SHA-256 chain hash; the dashboard shows live chain-integrity verification |
| **Audit report export** | Download any ledger record as a styled, standalone HTML report (serial number, outcome, finding/patch IDs, full hash) — printable to PDF directly from the browser |
| **Operator dashboard** | Live backend status, per-file findings with inline diffs and rationale, approve/reject checkboxes for gated findings, and a full ledger view — all in a single-page vanilla JS/HTML console |

---

## Tech Stack

**Core pipeline** — Python 3, standard library only (zero third-party dependencies by design, so the core stays usable air-gapped)

**Benchmark targets** — C/C++, compiled with GCC/Clang and AddressSanitizer for exploit-replay verification

**Static analysis** — Regex-based per-language danger-pattern rules (`static_analyzer.py`); swappable for a real parser front-end (libclang, an HDL front-end, etc.) per language without changing the rest of the pipeline

**Patch synthesis** — Hand-written heuristics + generic mechanically-safe pattern fixes, with an optional LLM-assisted fallback via a stdlib `urllib` client — no SDK dependency, supports cloud (Claude, OpenAI) or local (Ollama) backends

**Audit trail** — SQLite with a SHA-256 hash chain per record; no external database required

**Backend** — FastAPI (`backend/app/main.py`)

**Frontend** — Vanilla HTML/JS/CSS operator dashboard, no build step

**Deployment** — Docker + docker-compose for local development; backend and dashboard deployed independently on Render for the live demo

---

## Project Structure

```
├── kavach/                     Core pipeline
│   ├── config.py                   Runtime configuration (backend selection, limits)
│   ├── cli.py                      Benchmark target registry + CLI entry point
│   ├── models.py                   Shared dataclasses (Finding, PatchCandidate, VerificationResult, AuditRecord)
│   ├── languages.py                Language detection + software/hardware pipeline routing
│   ├── agents/
│   │   ├── orchestrator.py             Closed-loop state machine (triage → patch → verify → ledger)
│   │   ├── review_gate.py              Human-review gating criteria (single source of truth)
│   │   ├── patch_agent.py              Patch synthesis: heuristic → generic pattern → LLM-assisted
│   │   └── llm_client.py               Stdlib HTTP client for cloud/local LLM backends
│   ├── analyzers/
│   │   ├── static_analyzer.py          Multi-language danger-pattern rule engine
│   │   └── crash_analyzer.py           ASan crash-log parser
│   ├── sandbox/
│   │   ├── patcher.py                  Applies/rolls back patches on disk
│   │   └── verifier.py                 Triple-Lock verification (exploit replay, regression, clean rebuild)
│   └── ledger/
│       └── audit_ledger.py             Hash-chained SQLite audit trail
├── backend/
│   └── app/
│       └── main.py                 FastAPI REST API (benchmark runs, multi-file analysis, ledger)
├── frontend/                   Operator dashboard (static, no build step)
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── src/                         Benchmark C targets (intentionally vulnerable, CWE-tagged)
├── include/                     Headers for the benchmark targets
├── tests/                       Per-target exploit-replay + regression modules
└── docker-compose.yml           Full local stack
```

---

## Getting Started

### Prerequisites
- Python 3.11+
- GCC/Clang with AddressSanitizer (for running the benchmark targets locally)
- Docker & Docker Compose (optional, for containerized runs)

### Run the backend

```bash
git clone https://github.com/dixha171/Rakshak.git
cd Rakshak
pip install -r requirements.txt
uvicorn backend.app.main:app --reload --port 8000
```

### Run the dashboard

```bash
cd frontend
python -m http.server 8080
```

Then open `http://localhost:8080`. Set `API_BASE` in `frontend/app.js` to your backend's URL if it's not running on the same origin.

### Environment variables

Only needed if you want LLM-assisted patching for cases with no template match:

```
KAVACH_BACKEND=cloud_claude   # or cloud_openai / local_ollama
ANTHROPIC_API_KEY=...         # or the equivalent for your chosen backend
```

The core pipeline — static analysis, heuristic/generic-pattern patching, the review gate, Triple-Lock verification, and the audit ledger — runs entirely offline with no configuration required.

---

## Scope & Honest Limitations

In the interest of the same explainability this project is built around:

- **Full Triple-Lock verification is currently scoped to the three benchmark C targets.** The general-purpose multi-file upload endpoint (`/api/analyze`) deliberately does *not* compile or execute uploaded code — it's a public-facing endpoint, and running arbitrary uploaded code server-side would be a remote-code-execution hole in the service itself. Fixes suggested through that endpoint are labeled `suggested_included` in the ledger, distinct from a real `certified` outcome, so the audit trail stays honest about the difference.
- **Hardware findings are always gated, by design.** There is no synthesizer or simulator in this environment to prove an RTL fix correct — a suggested HDL patch (where a template exists) is a starting point for a human hardware engineer to review and re-verify in a real toolchain, never something to trust and apply as-is.
- **Patch coverage is intentionally partial, not exhaustive.** Some CWEs (e.g. `strcpy`/`memcpy` misuse) have no auto-generated fix at all, because a safe fix requires knowing the real destination buffer size — something a text-level scan can't reliably determine. The system says so explicitly rather than guessing.

---

## License

This project is licensed under the [MIT License](./LICENSE).
