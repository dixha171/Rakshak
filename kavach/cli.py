"""
KAVACH command-line interface.

    kavach run <target-name>       - run the full triage->patch->verify pipeline on one target
                                      (stops for human review if the finding is gated — see
                                      kavach.agents.review_gate)
    kavach approve <target-name>   - approve a target's pending review and apply+verify it
    kavach ledger                  - print the audit ledger and verify its hash chain
    kavach benchmarks              - list available benchmark targets
    kavach fuzz <target-name>      - fuzz a target for novel crashes, then run any crash found
                                      through the same triage->patch->verify pipeline as `run`
"""
from __future__ import annotations

import argparse
import os
import sys

from kavach.config import DEFAULT_CONFIG
from kavach.models import VulnerabilityFinding
from kavach.analyzers.static_analyzer import StaticAnalyzer
from kavach.agents.orchestrator import Orchestrator
from kavach.ledger.audit_ledger import AuditLedger

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BENCHMARKS = {
    "packet_parser": {
        "cwe": "CWE-119",
        "source": os.path.join(REPO_ROOT, "src", "packet_parser.c"),
        "header": os.path.join(REPO_ROOT, "include", "packet_parser.h"),
        "test_module": "tests.test_regression_packet",
        "description": "Tactical packet stream decoder — missing upper bounds check on memcpy",
    },
    "auth_session": {
        "cwe": "CWE-416",
        "source": os.path.join(REPO_ROOT, "src", "auth_session.c"),
        "header": os.path.join(REPO_ROOT, "include", "auth_session.h"),
        "test_module": "tests.test_regression_auth",
        "description": "Tactical auth session manager — dangling pointer on logout",
    },
    "frame_alloc": {
        "cwe": "CWE-190",
        "source": os.path.join(REPO_ROOT, "src", "frame_alloc.c"),
        "header": os.path.join(REPO_ROOT, "include", "frame_alloc.h"),
        "test_module": "tests.test_regression_frame",
        "description": "Radar frame allocator — integer multiplication wrap-around",
    },
}

# --- Fuzzing config ---------------------------------------------------
#
# Fuzzing needs a compiled ASan binary that reads its input from stdin
# (or a file passed via argv) and a small seed corpus of valid example
# inputs to mutate from. Only targets shaped like "parse a byte stream"
# are wired here: packet_parser fits that shape directly. auth_session
# and frame_alloc operate on typed function arguments (a session
# pointer; an integer count and size) rather than a raw byte stream, so
# fuzzing them meaningfully would need a small dedicated fuzz harness
# (a main() that reads stdin and maps it onto those arguments) that
# doesn't exist yet — they're deliberately left out rather than pointed
# at something that wouldn't actually exercise the real bug.
FUZZ_BUILD_DIR = os.path.join(REPO_ROOT, ".kavach_fuzz_build")

FUZZ_TARGETS = {
    "packet_parser": {
        "binary": os.path.join(FUZZ_BUILD_DIR, "packet_parser_asan"),
        "seed_dir": os.path.join(REPO_ROOT, "fuzz", "seeds", "packet_parser"),
        # packet_parser.c's own PACKET_PARSER_STANDALONE main() always
        # replays one fixed hardcoded overflow and never reads external
        # input, so it can't be fuzzed directly — build_sources instead
        # combines packet_parser.c (compiled WITHOUT that define, so its
        # main() is left out) with a small harness main() that actually
        # reads the fuzzer's bytes from stdin. See fuzz/harness/.
        "build_sources": [
            os.path.join(REPO_ROOT, "src", "packet_parser.c"),
            os.path.join(REPO_ROOT, "fuzz", "harness", "packet_parser_fuzz_main.c"),
        ],
        "mode": "stdin",
    },
}


def _ensure_fuzz_binary(target_name: str) -> str:
    """
    Compiles the target's ASan binary on demand if it doesn't already
    exist, into FUZZ_BUILD_DIR. Uses a plain single/multi-file clang/gcc
    build — adjust build_sources / add extra -I paths in FUZZ_TARGETS if
    a target needs more than this. Returns the binary path, or raises
    RuntimeError with the compiler's stderr if the build fails.
    """
    import subprocess

    cfg = FUZZ_TARGETS[target_name]
    os.makedirs(FUZZ_BUILD_DIR, exist_ok=True)
    binary = cfg["binary"]
    if os.path.exists(binary):
        return binary

    compiler = os.environ.get("CC", "clang")
    cmd = [
        compiler, "-fsanitize=address", "-g", "-O0",
        "-I", os.path.join(REPO_ROOT, "include"),
        "-o", binary,
        *cfg["build_sources"],
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ASan build failed for '{target_name}':\n{result.stderr}")
    return binary


def cmd_benchmarks(_args: argparse.Namespace) -> None:
    for name, meta in BENCHMARKS.items():
        print(f"{name:15s} {meta['cwe']:10s} {meta['description']}")


def _resolve_finding(target: dict) -> VulnerabilityFinding:
    analyzer = StaticAnalyzer()
    findings = analyzer.analyze_file(target["source"])
    findings = [f for f in findings if f.cwe == target["cwe"]] or [
        VulnerabilityFinding(cwe=target["cwe"], file_path=target["source"], description=target["description"])
    ]
    finding = findings[0]
    finding.file_path = target["source"]
    return finding


def _print_outcome(args_target: str, target: dict, outcome) -> None:
    print(f"Target: {args_target} ({target['cwe']})")
    for line in outcome.log:
        print(f"  - {line}")
    print(f"Final state: {outcome.state.value}")
    if outcome.verification:
        print(f"Verification: {outcome.verification.status.value} in {outcome.verification.duration_ms:.1f}ms")
    if outcome.state.value == "pending_review":
        print(f"\nThis finding requires human review before it can be applied. Run:")
        print(f"  kavach approve {args_target}")
        print("once you've reviewed the reasons above.")


def cmd_run(args: argparse.Namespace) -> None:
    target = BENCHMARKS.get(args.target)
    if not target:
        print(f"Unknown target '{args.target}'. Run `kavach benchmarks` to list options.", file=sys.stderr)
        sys.exit(2)

    sys.path.insert(0, REPO_ROOT)
    finding = _resolve_finding(target)
    orchestrator = Orchestrator(config=DEFAULT_CONFIG)
    outcome = orchestrator.run(finding, target["source"], target["test_module"], header_path=target.get("header"))
    _print_outcome(args.target, target, outcome)


def cmd_approve(args: argparse.Namespace) -> None:
    target = BENCHMARKS.get(args.target)
    if not target:
        print(f"Unknown target '{args.target}'. Run `kavach benchmarks` to list options.", file=sys.stderr)
        sys.exit(2)

    sys.path.insert(0, REPO_ROOT)
    finding = _resolve_finding(target)
    orchestrator = Orchestrator(config=DEFAULT_CONFIG)
    outcome = orchestrator.run(
        finding, target["source"], target["test_module"],
        header_path=target.get("header"), force_apply=True,
    )
    _print_outcome(args.target, target, outcome)


def cmd_fuzz(args: argparse.Namespace) -> None:
    if args.target not in FUZZ_TARGETS:
        available = ", ".join(FUZZ_TARGETS) or "(none configured)"
        print(
            f"'{args.target}' isn't configured for fuzzing yet. Available: {available}\n"
            "Fuzzing needs a stdin/argv-driven ASan binary and a seed corpus — see "
            "FUZZ_TARGETS in this file to add a new target.",
            file=sys.stderr,
        )
        sys.exit(2)

    sys.path.insert(0, REPO_ROOT)
    from kavach.fuzzing.fuzzer import fuzz_target

    cfg = FUZZ_TARGETS[args.target]
    if not os.path.isdir(cfg["seed_dir"]) or not os.listdir(cfg["seed_dir"]):
        print(
            f"No seed files found in {cfg['seed_dir']}. Add at least one valid "
            "example input file there before fuzzing.",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        binary = _ensure_fuzz_binary(args.target)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    print(f"Fuzzing {args.target} for {args.seconds:.0f}s against {binary}...")
    findings = fuzz_target(binary, cfg["seed_dir"], max_seconds=args.seconds)

    if not findings:
        print("No crashes found in this run.")
        return

    print(f"\n{len(findings)} crash(es) found. Running each through triage -> patch -> verify:\n")
    target = BENCHMARKS.get(args.target)
    orchestrator = Orchestrator(config=DEFAULT_CONFIG)
    for finding in findings:
        if target:
            outcome = orchestrator.run(
                finding, target["source"], target["test_module"], header_path=target.get("header")
            )
            _print_outcome(args.target, target, outcome)
        else:
            print(f"  {finding.cwe or '(unclassified)'}: {finding.description}")


def cmd_ledger(_args: argparse.Namespace) -> None:
    ledger = AuditLedger(DEFAULT_CONFIG.ledger_db_path)
    records = ledger.all_records()
    if not records:
        print("(ledger is empty)")
        return
    for r in records:
        print(f"#{r['seq']:04d} {r['outcome']:10s} finding={r['finding_id']} patch={r['patch_id']} hash={r['row_hash'][:12]}...")
    print(f"\nChain integrity: {'OK' if ledger.verify_chain() else 'TAMPERED'}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="kavach")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("benchmarks").set_defaults(func=cmd_benchmarks)

    run_parser = sub.add_parser("run")
    run_parser.add_argument("target", help="benchmark target name (see `kavach benchmarks`)")
    run_parser.set_defaults(func=cmd_run)

    approve_parser = sub.add_parser("approve")
    approve_parser.add_argument("target", help="benchmark target name whose pending review you're approving")
    approve_parser.set_defaults(func=cmd_approve)

    fuzz_parser = sub.add_parser("fuzz")
    fuzz_parser.add_argument("target", help="fuzzable target name (see FUZZ_TARGETS in this file)")
    fuzz_parser.add_argument("--seconds", type=float, default=20.0, help="fuzzing time budget, in seconds")
    fuzz_parser.set_defaults(func=cmd_fuzz)

    sub.add_parser("ledger").set_defaults(func=cmd_ledger)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
