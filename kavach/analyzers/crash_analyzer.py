"""
AddressSanitizer (ASan) log parser and backtrace localizer.

Parses raw ASan stderr output into a structured CrashReport, extracting
the crash type (heap-buffer-overflow, use-after-free, etc.), the first
in-project stack frame (file:line + function), and the full stack trace.

Also converts a CrashReport into a VulnerabilityFinding (see to_finding
below), so a crash discovered dynamically — whether fed in externally or
found by kavach.fuzzing.fuzzer — enters the exact same triage -> patch ->
review-gate -> verify pipeline as a statically-detected finding, tagged
source="crash_analyzer" per kavach.models.VulnerabilityFinding's own
docstring comment.
"""
from __future__ import annotations

import re

from kavach.models import CrashReport, VulnerabilityFinding, Severity

CRASH_TYPE_RE = re.compile(r"ERROR: AddressSanitizer: (\S+)")
FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(\S+\.c[c]?):(\d+)")
SUMMARY_RE = re.compile(r"SUMMARY: AddressSanitizer: (\S+).*?in\s+(\S+)")

# Maps ASan's crash_type string to the closest CWE already used elsewhere
# in the pipeline (static_analyzer.py's rules use the same identifiers),
# so a dynamically-found bug and a statically-found one referencing the
# same weakness class both show up under one consistent CWE, and both
# get evaluated by review_gate.py's HIGH_RISK_CWES the same way.
_CRASH_TYPE_TO_CWE = {
    "heap-buffer-overflow": "CWE-119",
    "stack-buffer-overflow": "CWE-119",
    "global-buffer-overflow": "CWE-119",
    "use-after-free": "CWE-416",
    "heap-use-after-free": "CWE-416",
    "SEGV": "CWE-119",
}


class CrashAnalyzer:
    def parse(self, binary: str, asan_log: str) -> CrashReport:
        report = CrashReport(binary=binary, asan_log=asan_log)
        m = CRASH_TYPE_RE.search(asan_log)
        if m:
            report.crash_type = m.group(1)
        else:
            m2 = SUMMARY_RE.search(asan_log)
            if m2:
                report.crash_type = m2.group(1)

        frames = FRAME_RE.findall(asan_log)
        report.stack_trace = [f"{func} {file}:{line}" for func, file, line in frames]

        # Localize to the first frame that lives under src/ or include/,
        # skipping libc/ASan runtime frames.
        for func, file, line in frames:
            if "/src/" in file or file.startswith("src/") or "/include/" in file:
                report.faulting_function = func
                report.faulting_file = file
                report.faulting_line = int(line)
                break
        if not report.faulting_function and frames:
            func, file, line = frames[0]
            report.faulting_function = func
            report.faulting_file = file
            report.faulting_line = int(line)

        return report

    def parse_file(self, binary: str, log_path: str) -> CrashReport:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            return self.parse(binary, f.read())

    def to_finding(self, report: CrashReport) -> VulnerabilityFinding:
        """
        Converts a parsed CrashReport into a VulnerabilityFinding, the
        shape every other stage of the pipeline (patch_agent, review_gate,
        orchestrator) already operates on. A crash is always CRITICAL —
        by definition, an ASan abort means memory corruption or invalid
        access actually occurred, which is a stronger signal than any
        static pattern match.

        CWE is looked up from the crash type where a mapping exists;
        unrecognized ASan crash types (rare, but ASan does have more
        classes than the ones mapped above) fall through with an empty
        CWE rather than a guessed one, so review_gate's keyword/severity
        checks still apply even when the CWE-specific check can't.
        """
        cwe = _CRASH_TYPE_TO_CWE.get(report.crash_type, "")
        description = (
            f"AddressSanitizer detected a {report.crash_type or 'crash'} "
            f"in {report.faulting_function or '(unknown function)'}"
            + (f" at {report.faulting_file}:{report.faulting_line}" if report.faulting_file else "")
            + ". This was triggered by an actual input, not a pattern match — "
              "see the attached ASan log for the full stack trace."
        )

        return VulnerabilityFinding(
            cwe=cwe,
            file_path=report.faulting_file,
            line=report.faulting_line,
            function=report.faulting_function,
            description=description,
            severity=Severity.CRITICAL,
            source="crash_analyzer",
            language="c",  # ASan targets are C/C++ by construction today
        )
