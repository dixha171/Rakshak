"""
Orchestrator: the closed-loop state machine that ties triage -> patch ->
sandbox verification -> ledger together, with retry/backtracking when a
generated patch fails verification.

State flow per finding:
    TRIAGED -> PATCH_SYNTHESIZED -> APPLIED -> VERIFYING -> CERTIFIED
    On verification failure: VERIFYING -> ROLLED_BACK -> retry (up to max_retries) -> ABANDONED
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from kavach.config import KavachConfig, DEFAULT_CONFIG
from kavach.models import (
    VulnerabilityFinding,
    PatchCandidate,
    VerificationResult,
    VerificationStatus,
    AuditRecord,
)
from kavach.agents.patch_agent import PatchAgent
from kavach.sandbox.patcher import Patcher
from kavach.sandbox.verifier import Verifier
from kavach.ledger.audit_ledger import AuditLedger


class RunState(str, Enum):
    TRIAGED = "triaged"
    PATCH_SYNTHESIZED = "patch_synthesized"
    APPLIED = "applied"
    VERIFYING = "verifying"
    CERTIFIED = "certified"
    ROLLED_BACK = "rolled_back"
    ABANDONED = "abandoned"


@dataclass
class RunOutcome:
    finding: VulnerabilityFinding
    state: RunState
    patch: PatchCandidate | None = None
    verification: VerificationResult | None = None
    attempts: int = 0
    log: list[str] = field(default_factory=list)


class Orchestrator:
    def __init__(
        self,
        config: KavachConfig = DEFAULT_CONFIG,
        patch_agent: PatchAgent | None = None,
        patcher: Patcher | None = None,
        verifier: Verifier | None = None,
        ledger: AuditLedger | None = None,
    ):
        self.config = config
        self.patch_agent = patch_agent or PatchAgent(config)
        self.patcher = patcher or Patcher()
        self.verifier = verifier or Verifier(config)
        self.ledger = ledger or AuditLedger(config.ledger_db_path)

    def run(
        self,
        finding: VulnerabilityFinding,
        source_path: str,
        test_module: str,
        header_path: str | None = None,
    ) -> RunOutcome:
        outcome = RunOutcome(finding=finding, state=RunState.TRIAGED)

        for attempt in range(1, self.config.orchestrator_max_retries + 1):
            outcome.attempts = attempt
            outcome.log.append(f"attempt {attempt}: synthesizing patch")

            with open(source_path, "r", encoding="utf-8") as f:
                original_source = f.read()

            patch = self.patch_agent.synthesize(finding, original_source)
            outcome.patch = patch
            outcome.state = RunState.PATCH_SYNTHESIZED

            if not patch.diff:
                outcome.log.append("no patch generated; abandoning")
                outcome.state = RunState.ABANDONED
                break

            if patch.diff_line_count > self.config.max_patch_diff_lines:
                outcome.log.append(
                    f"patch diff ({patch.diff_line_count} lines) exceeds budget "
                    f"({self.config.max_patch_diff_lines}); abandoning"
                )
                outcome.state = RunState.ABANDONED
                break

            backup_path = self.patcher.apply(source_path, patch)
            header_backup_path = None
            if header_path:
                with open(header_path, "r", encoding="utf-8") as f:
                    header_source = f.read()
                header_patched = self.patch_agent.companion_header_patch(finding, header_source)
                if header_patched is not None:
                    header_backup_path = self.patcher.apply_raw(header_path, header_patched)
                    outcome.log.append(f"companion header patch applied to {header_path}")

            outcome.state = RunState.APPLIED
            outcome.log.append(f"patch applied to {source_path} (backup at {backup_path})")

            outcome.state = RunState.VERIFYING
            verification = self.verifier.verify(test_module)
            outcome.verification = verification

            if verification.status == VerificationStatus.CERTIFIED:
                outcome.state = RunState.CERTIFIED
                outcome.log.append(f"certified in {verification.duration_ms:.1f}ms")
                self.ledger.record(
                    AuditRecord(
                        finding_id=finding.id,
                        patch_id=patch.id,
                        verification_id=verification.id,
                        patch_sha256=self.patcher.sha256_of(source_path),
                        outcome="certified",
                    )
                )
                break

            # Verification failed: roll back (source + companion header) and retry.
            self.patcher.rollback(source_path, backup_path)
            if header_path and header_backup_path:
                self.patcher.rollback(header_path, header_backup_path)
            outcome.state = RunState.ROLLED_BACK
            outcome.log.append(f"verification failed ({verification.status.value}); rolled back and retrying")
            self.ledger.record(
                AuditRecord(
                    finding_id=finding.id,
                    patch_id=patch.id,
                    verification_id=verification.id,
                    patch_sha256="",
                    outcome="rejected",
                )
            )
        else:
            outcome.state = RunState.ABANDONED

        if outcome.state == RunState.ROLLED_BACK:
            outcome.state = RunState.ABANDONED

        return outcome
