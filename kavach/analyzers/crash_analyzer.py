"""
AddressSanitizer (ASan) log parser and backtrace localizer.

Parses raw ASan stderr output into a structured CrashReport, extracting
the crash type (heap-buffer-overflow, use-after-free, etc.), the first
in-project stack frame (file:line + function), and the full stack trace.
"""
from __future__ import annotations

import re

from kavach.models import CrashReport

CRASH_TYPE_RE = re.compile(r"ERROR: AddressSanitizer: (\S+)")
FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(\S+\.c[c]?):(\d+)")
SUMMARY_RE = re.compile(r"SUMMARY: AddressSanitizer: (\S+).*?in\s+(\S+)")


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
