# KAVACH

**Closed-loop vulnerability detection, patching, and verification for C/C++ codebases.**

KAVACH ("kavach" — Sanskrit for *shield/armor*) triages memory-safety defects found by static analysis and crash logs, synthesizes a minimal-diff source patch, applies it in a sandbox, and only certifies the fix once it survives a **Triple-Lock Verification**: exploit replay, functional regression, and a clean re-certification build. Every outcome — certified or rejected — is written to a tamper-evident, hash-chained audit ledger.

```
Static Analyzer ─┐
                  ├──► Triage Agent ──► Patch Agent ──► Sandbox (compile/patch/verify) ──► Audit Ledger
Crash Analyzer ──┘         │                                     │
                     Evidence Graph                      Triple-Lock Verification
                                                    (Exploit Replay + Regression + Certification)
```

## Why it exists

Static analyzers find *patterns*. Fuzzers find *crashes*. Neither one, by itself, tells you whether a proposed fix actually closes the hole without breaking anything else. KAVACH closes that loop: it correlates both signal types into one evidence graph, generates the smallest patch that plausibly fixes the root cause, and refuses to certify anything that doesn't independently survive a fresh exploit attempt and the existing test suite.

## Benchmark targets

Three intentionally vulnerable C programs ship in this repo so the pipeline has something real to fix:

| Target | CWE | Bug |
|---|---|---|
| `src/packet_parser.c` | CWE-119 | Tactical packet stream decoder — `memcpy` with no upper-bounds check against a fixed 256-byte buffer |
| `src/auth_session.c` | CWE-416 | Auth session manager — `free()`d session pointer left dangling and reused |
| `src/frame_alloc.c` | CWE-190 | Radar frame allocator — `int` multiplication overflow feeding `malloc()` |

Each has a matching header, a `tests/test_regression_*.py` exploit-replay + regression harness, and is confirmed to crash under AddressSanitizer before KAVACH touches it.

## Quick start

```bash
pip install -r requirements.txt

# Run the full pipeline against all three targets and print a verification summary
python run_demo.py

# Or drive one target at a time via the CLI
python -m kavach.cli benchmarks
python -m kavach.cli run packet_parser
python -m kavach.cli ledger

# Start the API + operator dashboard
uvicorn backend.app.main:app --reload --port 8000
python -m http.server 8080 --directory frontend   # then open http://localhost:8080
```

### Docker

```bash
docker compose up --build
```

Backend on `:8000`, dashboard on `:8080`.

## Package layout

```
include/, src/, tests/, Makefile      Benchmark targets (Step 1)
kavach/config.py                       Zero-dependency LLM backend config (Cloud/Local/Air-gapped)
kavach/models.py                       Shared schemas: Finding, CrashReport, PatchCandidate, VerificationResult, AuditRecord
kavach/analyzers/static_analyzer.py    Danger-pattern scanner
kavach/analyzers/crash_analyzer.py     ASan log parser + backtrace localizer
kavach/agents/triage_agent.py          Correlates static + dynamic evidence into a graph
kavach/agents/patch_agent.py           Synthesizes minimal-diff patches
kavach/agents/orchestrator.py          Closed-loop state machine with retry/backtracking
kavach/sandbox/compiler.py             Multi-compiler interface (GCC/Clang, ASan)
kavach/sandbox/patcher.py              Atomic patch applicator with rollback
kavach/sandbox/verifier.py             Triple-Lock Verification
kavach/ledger/audit_ledger.py          Tamper-evident SQLite audit trail (SHA-256 hash chain)
kavach/cli.py                          CLI: run / ledger / benchmarks
backend/app/main.py                    FastAPI REST backend
frontend/                              Operator web dashboard
run_demo.py                            One-click evaluation suite
docker/, docker-compose.yml            Container setup
```

## Verification summary

Running `python run_demo.py` against the three benchmark targets yields:

```
Buffer Overflow (CWE-119): Patched & Verified in ~120 ms
Use-After-Free (CWE-416): Patched & Verified in ~120 ms
Integer Overflow (CWE-190): Patched & Verified in ~115 ms
Overall Accuracy: 100% Proven (0 Regressions)
```

(Exact timings vary by machine.)

## Configuration

All backend selection is via environment variables (see `kavach/config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `KAVACH_BACKEND` | `air_gapped` | `cloud_claude` \| `cloud_openai` \| `local_ollama` \| `air_gapped` |
| `KAVACH_CC` | `gcc` | Preferred compiler |
| `KAVACH_MAX_DIFF_LINES` | `14` | Patch diff-line budget before the orchestrator abandons a fix |
| `KAVACH_MAX_RETRIES` | `3` | Retry/backtrack attempts per finding |
| `KAVACH_LEDGER_DB` | `kavach_audit.sqlite3` | Audit ledger path |

The default `air_gapped` backend uses only the heuristic patch-template library in `patch_agent.py` — no network calls, no API keys required. Cloud/local LLM-assisted patching is a configuration switch away once you wire in your own API key.

## Extending to real codebases

`kavach/analyzers/static_analyzer.py` is a regex-based danger-pattern scanner by design (zero dependencies). For production use against a real codebase, swap in `libclang` for proper AST analysis — `StaticAnalyzer.analyze_file()`'s return type (`list[VulnerabilityFinding]`) is the integration point the rest of the pipeline consumes.
