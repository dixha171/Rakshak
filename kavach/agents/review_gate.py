"""
Human review gate.

Some findings/patches must never be auto-applied and auto-certified
without a human explicitly signing off, even if the patch would otherwise
pass the Triple-Lock verifier. This module is the single place that
decides that, so the criteria are auditable in one spot rather than
scattered through the orchestrator.

CRITERIA (a finding is gated if ANY of these are true):

  1. HARDWARE PIPELINE. The finding is in a hardware description language
     (Verilog/VHDL). There is no synthesizer/simulator toolchain in this
     environment, so a hardware "fix" can never be proven the way a C
     patch can be (compiled + exploit-replayed + regression-tested).
     Every hardware finding is gated, unconditionally, regardless of any
     other criterion below — this reflects a real capability limit, not
     a configurable policy.

  2. HIGH-RISK CWE CATEGORY. The finding's CWE falls in a fixed list of
     weakness classes where an automated fix (even a technically correct
     one) can have consequences beyond the immediate bug: hardcoded
     credentials, cryptographic weaknesses, broken access control/
     authentication, insecure deserialization, and hardware-security
     design flaws (debug backdoors, uncleared secrets). These are exactly
     the categories where "it compiles and the test suite passes" is not
     sufficient evidence that the fix is actually correct or complete.

  3. SENSITIVE-DATA KEYWORD MATCH. The file path, function/module name, or
     description contains a keyword associated with authentication,
     secrets, or access control (see SENSITIVE_KEYWORDS below). This is a
     coarse, intentionally over-inclusive signal — false positives here
     just mean an extra human glance at something that turned out to be
     fine, which is a much cheaper mistake than the reverse.

  4. CRITICAL SEVERITY. The static analyzer or crash analyzer marked the
     finding CRITICAL. Reserved for findings where the failure mode is
     arbitrary code execution, a hardcoded secret, or a hardware backdoor.

A finding can be gated for more than one reason at once; all matching
reasons are surfaced so a reviewer can see the full picture, not just the
first rule that happened to fire.
"""
from __future__ import annotations

from dataclasses import dataclass

from kavach.models import VulnerabilityFinding, Severity
from kavach.languages import pipeline_for

HIGH_RISK_CWES = {
    "CWE-798",   # hardcoded credentials
    "CWE-259",   # hardcoded password
    "CWE-321", "CWE-322", "CWE-326", "CWE-327",  # crypto key/algorithm weaknesses
    "CWE-311", "CWE-312", "CWE-319",             # cleartext sensitive data
    "CWE-284", "CWE-285", "CWE-287", "CWE-306",  # access control / auth
    "CWE-502",   # insecure deserialization
    "CWE-95",    # eval/exec of untrusted input
    "CWE-1191", "CWE-1234", "CWE-1245", "CWE-1271", "CWE-1272",  # hardware security design flaws
}

SENSITIVE_KEYWORDS = [
    "auth", "session", "token", "password", "passwd", "secret", "credential",
    "crypto", "encrypt", "decrypt", "hash", "salt", "cert", "private_key",
    "login", "logout", "permission", "privilege", "admin", "root", "sudo",
    "apikey", "api_key", "jtag", "debug_enable", "backdoor", "lock_bit",
    "secure_boot", "fuse",
]


@dataclass
class ReviewDecision:
    requires_review: bool
    reasons: list[str]


def evaluate(finding: VulnerabilityFinding) -> ReviewDecision:
    reasons: list[str] = []

    if pipeline_for(finding.language) == "hardware":
        reasons.append(
            "hardware-pipeline finding (Verilog/VHDL) — no synthesizer/simulator exists in this "
            "environment to prove a fix, so it must be reviewed and re-verified by a hardware engineer "
            "in a real toolchain before use"
        )

    if finding.cwe in HIGH_RISK_CWES:
        reasons.append(f"{finding.cwe} is a high-risk category (credentials/crypto/access-control/hardware-security)")

    haystack = f"{finding.file_path} {finding.function} {finding.description}".lower()
    hit_keywords = sorted({kw for kw in SENSITIVE_KEYWORDS if kw in haystack})
    if hit_keywords:
        reasons.append(f"touches sensitive-data keywords: {', '.join(hit_keywords)}")

    if finding.severity == Severity.CRITICAL:
        reasons.append("finding marked CRITICAL severity")

    return ReviewDecision(requires_review=bool(reasons), reasons=reasons)
