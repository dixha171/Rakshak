"""
KAVACH command-line interface.

    kavach run <target-name>       - run the full triage->patch->verify pipeline on one target
                                      (stops for human review if the finding is gated — see
                                      kavach.agents.review_gate)
    kavach approve <target-name>   - approve a target's pending review and apply+verify it
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

    sub.add_parser("ledger").set_defaults(func=cmd_ledger)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
