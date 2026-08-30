"""Structured schemas shared across KAVACH's analyzers, agents, and sandbox."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationStatus(str, Enum):
    PENDING = "pending"
    EXPLOIT_REPLAY_PASSED = "exploit_replay_passed"
    REGRESSION_PASSED = "regression_passed"
    CERTIFIED = "certified"
    FAILED = "failed"


@dataclass
class VulnerabilityFinding:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    cwe: str = ""
    file_path: str = ""
    line: int = 0
    function: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    source: str = "static_analyzer"  # or "crash_analyzer"
    language: str = "c"  # e.g. "c", "python", "javascript", "verilog", "vhdl"
    detected_at: float = field(default_factory=time.time)


@dataclass
class CrashReport:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    binary: str = ""
    asan_log: str = ""
    crash_type: str = ""       # e.g. heap-buffer-overflow, use-after-free
    faulting_function: str = ""
    faulting_file: str = ""
    faulting_line: int = 0
    stack_trace: list[str] = field(default_factory=list)
    captured_at: float = field(default_factory=time.time)


@dataclass
class PatchCandidate:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    finding_id: str = ""
    file_path: str = ""
    diff: str = ""
    diff_line_count: int = 0
    rationale: str = ""
    generated_by: str = "patch_agent"
    generated_at: float = field(default_factory=time.time)


@dataclass
class VerificationResult:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    patch_id: str = ""
    status: VerificationStatus = VerificationStatus.PENDING
    exploit_replay_ok: Optional[bool] = None
    regression_ok: Optional[bool] = None
    certified_ok: Optional[bool] = None
    duration_ms: float = 0.0
    log: str = ""
    verified_at: float = field(default_factory=time.time)


@dataclass
class AuditRecord:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    finding_id: str = ""
    patch_id: str = ""
    verification_id: str = ""
    patch_sha256: str = ""
    outcome: str = ""  # "certified" | "rejected" | "reverted"
    recorded_at: float = field(default_factory=time.time)
