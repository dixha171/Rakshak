"""
KAVACH command-line interface.

    kavach run <target-name>       - run the full triage->patch->verify pipeline on one target
    kavach ledger                  - print the audit ledger and verify its hash chain
    kavach benchmarks              - list available benchmark targets
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


def cmd_benchmarks(_args: argparse.Namespace) -> None:
    for name, meta in BENCHMARKS.items():
        print(f"{name:15s} {meta['cwe']:10s} {meta['description']}")


def cmd_run(args: argparse.Namespace) -> None:
    target = BENCHMARKS.get(args.target)
    if not target:
        print(f"Unknown target '{args.target}'. Run `kavach benchmarks` to list options.", file=sys.stderr)
        sys.exit(2)

    sys.path.insert(0, REPO_ROOT)

    analyzer = StaticAnalyzer()
    findings = analyzer.analyze_file(target["source"])
    findings = [f for f in findings if f.cwe == target["cwe"]] or [
        VulnerabilityFinding(cwe=target["cwe"], file_path=target["source"], description=target["description"])
    ]
    finding = findings[0]
    finding.file_path = target["source"]

    orchestrator = Orchestrator(config=DEFAULT_CONFIG)
    outcome = orchestrator.run(finding, target["source"], target["test_module"], header_path=target.get("header"))

    print(f"Target: {args.target} ({target['cwe']})")
    for line in outcome.log:
        print(f"  - {line}")
    print(f"Final state: {outcome.state.value}")
    if outcome.verification:
        print(f"Verification: {outcome.verification.status.value} in {outcome.verification.duration_ms:.1f}ms")


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

    sub.add_parser("ledger").set_defaults(func=cmd_ledger)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
