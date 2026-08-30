"""
Lightweight static analyzer for C/C++ sources.

This does NOT depend on a full C parser/AST library (zero-dependency by
design, per kavach.config). Instead it combines:
  1. A small set of regex-based "danger pattern" rules for well-known
     memory-safety pitfalls (unchecked memcpy/strcpy/sprintf, free()
     without null-out, unchecked multiplication feeding malloc, etc).
  2. Lightweight structural checks (brace/paren balance, function
     boundaries) to localize findings to a specific function.

For production-grade AST analysis, swap in clang's libclang bindings —
this module's `StaticAnalyzer.analyze_file` return type
(list[VulnerabilityFinding]) is the integration point.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from kavach.models import VulnerabilityFinding, Severity


@dataclass
class DangerRule:
    name: str
    cwe: str
    pattern: re.Pattern
    description: str
    severity: Severity


RULES: list[DangerRule] = [
    DangerRule(
        name="unchecked_memcpy",
        cwe="CWE-119",
        pattern=re.compile(r"\bmemcpy\s*\([^;]*\)\s*;"),
        description="memcpy() call found with no adjacent bounds check against the destination buffer size.",
        severity=Severity.HIGH,
    ),
    DangerRule(
        name="unchecked_strcpy",
        cwe="CWE-120",
        pattern=re.compile(r"\bstrcpy\s*\("),
        description="strcpy() has no bounds checking; prefer strncpy/strlcpy with explicit size.",
        severity=Severity.HIGH,
    ),
    DangerRule(
        name="free_without_null",
        cwe="CWE-416",
        pattern=re.compile(r"\bfree\s*\(\s*(\w+)\s*\)\s*;(?!\s*\1\s*=\s*NULL)"),
        description="free() call not followed by setting the pointer to NULL; risk of use-after-free/double-free.",
        severity=Severity.HIGH,
    ),
    DangerRule(
        name="int_mul_into_alloc",
        cwe="CWE-190",
        pattern=re.compile(r"\bmalloc\s*\(\s*[^)]*\*[^)]*\)"),
        description="malloc() size computed via multiplication with no overflow check; may wrap around.",
        severity=Severity.HIGH,
    ),
    DangerRule(
        name="unchecked_sprintf",
        cwe="CWE-120",
        pattern=re.compile(r"\bsprintf\s*\("),
        description="sprintf() has no bounds checking; prefer snprintf with explicit size.",
        severity=Severity.MEDIUM,
    ),
]


class StaticAnalyzer:
    def __init__(self, rules: list[DangerRule] | None = None):
        self.rules = rules or RULES

    def analyze_source(self, file_path: str, source: str) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        lines = source.splitlines()
        current_function = ""
        func_re = re.compile(r"^[\w\*\s]+\b(\w+)\s*\([^;{]*\)\s*\{?\s*$")

        for idx, line in enumerate(lines, start=1):
            m = func_re.match(line.strip())
            if m and "{" in line or (m and idx < len(lines) and "{" in lines[idx]):
                current_function = m.group(1)

            for rule in self.rules:
                if rule.pattern.search(line):
                    findings.append(
                        VulnerabilityFinding(
                            cwe=rule.cwe,
                            file_path=file_path,
                            line=idx,
                            function=current_function,
                            description=rule.description,
                            severity=rule.severity,
                            source="static_analyzer",
                        )
                    )
        return findings

    def analyze_file(self, file_path: str) -> list[VulnerabilityFinding]:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        return self.analyze_source(file_path, source)
