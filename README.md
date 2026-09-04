# 🛡️ KAVACH

**A closed-loop, AI-assisted vulnerability defense system for both software and hardware source code — built for the AI Kavach challenge (defence & national security track).**

KAVACH combines three distinct detection layers — **static analysis**, **fuzzing**, and **dynamic verification** — with an AI-assisted patch agent and a mandatory human review gate. It ingests source code across five languages (C/C++, Python, JavaScript on the software side; Verilog and VHDL on the hardware side), finds known-pattern bugs *and* novel ones nobody's written a rule for yet, synthesizes a minimal-diff fix where one can be safely generated, routes anything sensitive through human review, and — for its benchmark targets — proves a fix actually holds via a Triple-Lock verification pipeline before writing anything to a hash-chained, tamper-evident audit ledger.

🔗 Live dashboard: [rakshak-1-83j2.onrender.com](https://rakshak-1-83j2.onrender.com)

---

## Why KAVACH

Manually triaging and patching vulnerabilities in defence-adjacent codebases doesn't scale, and blind auto-patching is not an option when the code in question could end up running on real infrastructure. KAVACH is built around one governing idea: **automate what can be proven, find what hasn't been found yet, and gate what can't be verified.**

- **Static analysis** finds known-dangerous patterns instantly, across software and hardware alike — the fast, cheap first pass.
- **Fuzzing** goes further: it doesn't need a human to have already written a rule for a bug. It mutates real input and throws it at a compiled target, looking for crashes nobody anticipated — the layer that finds genuinely novel bugs.
- **Dynamic verification** (Triple-Lock: exploit replay + regression suite + clean rebuild) proves a proposed fix actually resolves a *specific, known* crash before it's ever marked certified — nothing is trusted on pattern-match alone.
- **Never auto-applies a change that can't be proven.** Every hardware finding, and every finding touching credentials, crypto, access control, or marked CRITICAL (which includes every fuzzer-discovered crash, by design), is routed to a human — unconditionally, regardless of whether a suggested fix exists.
- **Every decision is logged.** Certified, rejected, or pending human review — each outcome lives in a SHA-256 hash-chained ledger, so the audit trail itself can't be silently edited after the fact.

---

## Architecture

```
                    Operator Dashboard (HTML/JS)
                              │
                        HTTPS (FastAPI)
                              │
                     FastAPI Backend (backend/app)
                              │
        ┌──────────────┬──────────────┬───────────────────┐
        │              │              │                    │
 Language Detection  Static        Fuzzer            Benchmark Orchestrator
 (ext + content-     Analyzer   (mutation-based,      (state machine,
  sniff)            (per-lang     stdin harness,       retry/backtrack)
                     danger       ASan crash
                     rules)       detection)
        │              │              │                    │
        │              └──────┬───────┘                    │
        │                     │                             │
        │             Crash → Finding                       │
        │            (CrashAnalyzer.to_finding)              │
        │                     │                             │
        └─────────────────────┴─────────────────────────────┘
                              │
                        Patch Agent
              (heuristic → generic pattern → LLM-assisted)
                              │
                      Human Review Gate
        (hardware pipeline · high-risk CWE · sensitive keyword ·
              CRITICAL severity — crashes are always CRITICAL)
                              │
                ┌─────────────┴─────────────┐
                │                           │
       Triple-Lock Verifier          (hardware: no verifier —
   (exploit replay · regression ·     always routed to a human,
       clean rebuild)                  fix or no fix available)
                │                           │
                └─────────────┬─────────────┘
                              │
             Hash-Chained Audit Ledger (SQLite)
                              │
             Ledger view + per-record HTML report export
```

**Design principle:** a finding is either *proven* safe to auto-apply (software pipeline, passed Triple-Lock) or it goes to a human — there is no third option. Static analysis and fuzzing are two different ways of *finding* a problem; verification and review-gating are what decide whether it's safe to *act* on.

---

## Core Features

| Module | What it does |
|---|---|
| **Static analysis** | Regex-based danger-pattern rules across C/C++, Python, JavaScript, Verilog, and VHDL — no AST/parser dependency, so it runs air-gapped |
| **Fuzzing** | Mutation-based fuzzer that runs mutated inputs against a compiled, ASan-instrumented target looking for crashes no static rule or existing test anticipates. Any crash is parsed into a structured finding and enters the exact same triage → patch → review → verify pipeline as anything else |
| **Dynamic verification (Triple-Lock)** | For the benchmark C targets: exploit replay against an ASan build, a functional regression suite, and a final clean (no-sanitizer) rebuild — all three have to pass before a patch is marked `certified` |
| **Multi-language + multi-pipeline detection** | Detects language from file extension, falling back to content-sniffing; routes each finding to the software or hardware pipeline automatically |
| **Multi-file upload & analysis** | Analyze several files — software, hardware, or a mix — in a single pass, each with independent findings and independent suggested fixes |
| **Patch synthesis** | Three-tier fallback: hand-written heuristics for the benchmark targets → generic mechanically-safe pattern fixes (NULL-guards, overflow checks, secret→env-var swaps, HDL debug-fuse gating, HDL key redaction) → optional LLM-assisted patching for anything else |
| **Human review gate** | A finding is gated if it's in the hardware pipeline, its CWE falls in a high-risk category, its file/function name matches a sensitive keyword, or it's marked CRITICAL (every fuzzer-found crash always is) — all matching reasons are shown, never just the first one that fired |
| **Per-finding retry/backtrack** | The orchestrator retries a failed patch up to a configured limit, rolling back cleanly, without blocking unrelated findings |
| **Hash-chained audit ledger** | Every outcome — `certified`, `rejected`, `pending_review`, `suggested_included` — is recorded with a SHA-256 chain hash; the dashboard shows live chain-integrity verification |
| **Audit report export** | Download any ledger record as a styled, standalone HTML report — printable to PDF directly from the browser |
| **Operator dashboard** | Live backend status, per-file findings with inline diffs and rationale, a fuzz-a-target panel, approve/reject checkboxes for gated findings, and a full ledger view |

---

## Tech Stack

**Core pipeline** — Python 3, standard library only (zero third-party dependencies by design, so the core stays usable air-gapped)

**Benchmark targets** — C/C++, compiled with GCC and AddressSanitizer for both Triple-Lock exploit replay and fuzzing

**Static analysis** — Regex-based per-language danger-pattern rules (`static_analyzer.py`)

**Fuzzing** — Custom mutation-based fuzzer (`kavach/fuzzing/fuzzer.py`), stdlib-only — no AFL/libFuzzer dependency. Mutates a small seed corpus, runs the target via `subprocess` with `ASAN_OPTIONS` set for clean crash detection, and hands any crash to the same `CrashAnalyzer` used for externally-supplied ASan logs

**Patch synthesis** — Hand-written heuristics + generic mechanically-safe pattern fixes, with an optional LLM-assisted fallback via a stdlib `urllib` client — supports cloud (Claude, OpenAI) or local (Ollama) backends

**Audit trail** — SQLite with a SHA-256 hash chain per record; no external database required

**Backend** — FastAPI (`backend/app/main.py`)

**Frontend** — Vanilla HTML/JS/CSS operator dashboard, no build step

**Deployment** — Docker + docker-compose for local development; backend and dashboard deployed independently on Render for the live demo

---

## Project Structure

```
├── kavach/                     Core pipeline
│   ├── config.py                   Runtime configuration (backend selection, limits)
│   ├── cli.py                      Benchmark + fuzz target registry, CLI entry point
│   ├── models.py                   Shared dataclasses (Finding, CrashReport, PatchCandidate, VerificationResult, AuditRecord)
│   ├── languages.py                Language detection + software/hardware pipeline routing
│   ├── agents/
│   │   ├── orchestrator.py             Closed-loop state machine (triage → patch → verify → ledger)
│   │   ├── review_gate.py              Human-review gating criteria (single source of truth)
│   │   ├── patch_agent.py              Patch synthesis: heuristic → generic pattern → LLM-assisted
│   │   └── llm_client.py               Stdlib HTTP client for cloud/local LLM backends
│   ├── analyzers/
│   │   ├── static_analyzer.py          Multi-language danger-pattern rule engine
│   │   └── crash_analyzer.py           ASan crash-log parser + CrashReport → Finding conversion
│   ├── fuzzing/
│   │   └── fuzzer.py                   Mutation-based fuzzer, feeds crashes into the same pipeline
│   ├── sandbox/
│   │   ├── patcher.py                  Applies/rolls back patches on disk
│   │   └── verifier.py                 Triple-Lock verification (exploit replay, regression, clean rebuild)
│   └── ledger/
│       └── audit_ledger.py             Hash-chained SQLite audit trail
├── backend/
│   └── app/
│       └── main.py                 FastAPI REST API (benchmark runs, fuzzing, multi-file analysis, ledger)
├── frontend/                   Operator dashboard (static, no build step)
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── src/                         Benchmark C targets (intentionally vulnerable, CWE-tagged)
├── include/                     Headers for the benchmark targets
├── fuzz/
│   ├── harness/                     Fuzz-driver main() functions (real input → function under test)
│   └── seeds/<target>/              Seed corpora — valid example inputs to mutate from
├── tests/                       Per-target exploit-replay + regression modules
└── docker-compose.yml           Full local stack
```

---

## Getting Started

### Prerequisites
- Python 3.11+
- GCC with AddressSanitizer support (for benchmark verification and fuzzing)
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

### CLI usage

```bash
kavach benchmarks              # list available benchmark targets
kavach run <target>            # triage → patch → verify one target
kavach approve <target>        # apply + verify a target's pending-review finding
kavach fuzz <target> --seconds 30   # fuzz a target; any crash found runs through the same pipeline
kavach ledger                  # print the audit ledger and verify its hash chain
```

### Environment variables

Only needed if you want LLM-assisted patching for cases with no template match:

```
KAVACH_BACKEND=cloud_claude   # or cloud_openai / local_ollama
ANTHROPIC_API_KEY=...         # or the equivalent for your chosen backend
```

The core pipeline — static analysis, fuzzing, heuristic/generic-pattern patching, the review gate, Triple-Lock verification, and the audit ledger — runs entirely offline with no configuration required.

---

## Scope & Honest Limitations

In the interest of the same explainability this project is built around:

- **Fuzzing is currently wired for one target (`packet_parser`), not all three benchmarks.** `auth_session` and `frame_alloc` operate on typed function arguments (a session pointer; an integer count and size) rather than a raw byte stream, so a generic byte-fuzzer can't meaningfully drive them without a dedicated harness that doesn't exist yet — deliberately left unwired rather than pointed at something that wouldn't exercise the real bug.
- **The fuzzer is a simple mutation fuzzer, not a coverage-guided one.** It applies one random mutation per iteration with no feedback loop (no AFL/libFuzzer-style instrumentation), so seed corpus quality matters a lot — a seed sitting exactly at a vulnerable boundary condition may need many iterations (or a seed placed just past the boundary) to reliably trigger a multi-condition bug, since a single mutation may satisfy only one of several conditions a crash requires.
- **Full Triple-Lock verification is currently scoped to the three benchmark C targets.** The general-purpose multi-file upload endpoint (`/api/analyze`) deliberately does *not* compile or execute uploaded code — it's a public-facing endpoint, and running arbitrary uploaded code server-side would be a remote-code-execution hole in the service itself. Fixes suggested through that endpoint are labeled `suggested_included` in the ledger, distinct from a real `certified` outcome.
- **Hardware findings are always gated, by design** — whether found by static analysis or (in future) fuzzing. There is no synthesizer or simulator in this environment to prove an RTL fix correct.
- **Fuzzer-found crashes are always CRITICAL and therefore always gated.** There's no dashboard action yet to approve a fuzz-discovered finding through to certification directly from the fuzz panel — it's visible and logged, but the approve step for it isn't wired into the UI yet.
- **Patch coverage is intentionally partial, not exhaustive.** Some CWEs (e.g. `strcpy`/`memcpy` misuse) have no auto-generated fix at all, because a safe fix requires knowing the real destination buffer size — something a text-level scan can't reliably determine. The system says so explicitly rather than guessing.

---

## Team

Built for the AI Kavach challenge by:

| Name | GitHub |
|---|---|
| Dixha Bharti | [@dixha171](https://github.com/dixha171) |
| Garima Sharma | [@garima-x](https://github.com/garima-x) |

Contributions, issues, and feature requests are welcome — feel free to open a PR or start a discussion.

---

## License

This project is licensed under the [MIT License](./LICENSE).
