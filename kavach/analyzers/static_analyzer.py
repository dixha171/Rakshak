"""
Lightweight, multi-language static analyzer.

This does NOT depend on full parser/AST libraries for any language
(zero-dependency by design, per kavach.config). Instead it combines:
  1. Regex-based "danger pattern" rules, one set per language, covering
     well-known weakness classes for that language.
  2. Lightweight structural checks (function/module boundaries) to
     localize findings to a specific function/module.

Two pipelines' worth of languages are covered (see kavach.languages):
  - software: C, Python, JavaScript
  - hardware: Verilog, VHDL

For production-grade analysis, swap in a real parser per language (e.g.
libclang for C, an AST-based tool for Python/JS, a Verilog/VHDL front-end
for HDL) — `StaticAnalyzer.analyze_file`'s return type
(list[VulnerabilityFinding]) is the integration point.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from kavach.models import VulnerabilityFinding, Severity
from kavach.languages import detect_language


@dataclass
class DangerRule:
    name: str
    cwe: str
    pattern: re.Pattern
    description: str
    severity: Severity
    language: str = "c"


RULES: list[DangerRule] = [
    # ---------------------------------------------------------------- C ---
    DangerRule(
        name="unchecked_memcpy",
        cwe="CWE-119",
        pattern=re.compile(r"\bmemcpy\s*\([^;]*\)\s*;"),
        description="memcpy() call found with no adjacent bounds check against the destination buffer size.",
        severity=Severity.HIGH,
        language="c",
    ),
    DangerRule(
        name="unchecked_strcpy",
        cwe="CWE-120",
        pattern=re.compile(r"\bstrcpy\s*\("),
        description="strcpy() has no bounds checking; prefer strncpy/strlcpy with explicit size.",
        severity=Severity.HIGH,
        language="c",
    ),
    DangerRule(
        name="free_without_null",
        cwe="CWE-416",
        pattern=re.compile(r"\bfree\s*\(\s*(\w+)\s*\)\s*;(?!\s*\1\s*=\s*NULL)"),
        description="free() call not followed by setting the pointer to NULL; risk of use-after-free/double-free.",
        severity=Severity.HIGH,
        language="c",
    ),
    DangerRule(
        name="int_mul_into_alloc",
        cwe="CWE-190",
        pattern=re.compile(r"\bmalloc\s*\(\s*[^)]*\*[^)]*\)"),
        description="malloc() size computed via multiplication with no overflow check; may wrap around.",
        severity=Severity.HIGH,
        language="c",
    ),
    DangerRule(
        name="unchecked_sprintf",
        cwe="CWE-120",
        pattern=re.compile(r"\bsprintf\s*\("),
        description="sprintf() has no bounds checking; prefer snprintf with explicit size.",
        severity=Severity.MEDIUM,
        language="c",
    ),
    # ------------------------------------------------------------ Python ---
    DangerRule(
        name="py_eval_exec",
        cwe="CWE-95",
        pattern=re.compile(r"\b(eval|exec)\s*\("),
        description="eval()/exec() on potentially untrusted input allows arbitrary code execution.",
        severity=Severity.CRITICAL,
        language="python",
    ),
    DangerRule(
        name="py_os_system",
        cwe="CWE-78",
        pattern=re.compile(r"\bos\.system\s*\("),
        description="os.system() passes a string to the shell; untrusted input here enables OS command injection.",
        severity=Severity.HIGH,
        language="python",
    ),
    DangerRule(
        name="py_subprocess_shell_true",
        cwe="CWE-78",
        pattern=re.compile(r"subprocess\.(run|call|Popen|check_output)\([^)]*shell\s*=\s*True"),
        description="subprocess call with shell=True; untrusted arguments here enable OS command injection.",
        severity=Severity.HIGH,
        language="python",
    ),
    DangerRule(
        name="py_pickle_loads",
        cwe="CWE-502",
        pattern=re.compile(r"\bpickle\.loads?\s*\("),
        description="pickle.load()/loads() on untrusted data can execute arbitrary code during deserialization.",
        severity=Severity.CRITICAL,
        language="python",
    ),
    DangerRule(
        name="py_yaml_unsafe_load",
        cwe="CWE-502",
        pattern=re.compile(r"\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"),
        description="yaml.load() without Loader=yaml.SafeLoader can construct arbitrary Python objects from input.",
        severity=Severity.HIGH,
        language="python",
    ),
    DangerRule(
        name="py_hardcoded_secret",
        cwe="CWE-798",
        pattern=re.compile(r"(?i)\b(password|secret|api_key|apikey|token)\s*=\s*[\"'][^\"']{4,}[\"']"),
        description="Hardcoded credential/secret literal in source; should come from a secrets manager or environment variable.",
        severity=Severity.CRITICAL,
        language="python",
    ),
    # -------------------------------------------------------- JavaScript ---
    DangerRule(
        name="js_eval",
        cwe="CWE-95",
        pattern=re.compile(r"\beval\s*\("),
        description="eval() on potentially untrusted input allows arbitrary code execution.",
        severity=Severity.CRITICAL,
        language="javascript",
    ),
    DangerRule(
        name="js_child_process_exec",
        cwe="CWE-78",
        pattern=re.compile(r"\b(child_process\.)?(exec|execSync)\s*\("),
        description="child_process.exec()/execSync() passes a string to the shell; untrusted input enables OS command injection.",
        severity=Severity.HIGH,
        language="javascript",
    ),
    DangerRule(
        name="js_inner_html_assign",
        cwe="CWE-79",
        pattern=re.compile(r"\.innerHTML\s*="),
        description="Assigning to innerHTML with unsanitized input enables cross-site scripting (XSS).",
        severity=Severity.HIGH,
        language="javascript",
    ),
    DangerRule(
        name="js_hardcoded_secret",
        cwe="CWE-798",
        pattern=re.compile(r"(?i)\b(password|secret|apiKey|api_key|token)\s*[:=]\s*[\"'][^\"']{4,}[\"']"),
        description="Hardcoded credential/secret literal in source; should come from a secrets manager or environment variable.",
        severity=Severity.CRITICAL,
        language="javascript",
    ),
    # ----------------------------------------------------------- Verilog ---
    DangerRule(
        name="hdl_jtag_debug_hardcoded_enable",
        cwe="CWE-1191",
        pattern=re.compile(r"(?i)\b(jtag|debug)_?en(?:able)?\s*=\s*1'b1"),
        description="On-chip debug/JTAG interface appears hardcoded enabled with no access-control gating; "
                    "should be gated by a fuse/lock bit or disabled in production builds.",
        severity=Severity.CRITICAL,
        language="verilog",
    ),
    DangerRule(
        name="hdl_hardcoded_key_constant",
        cwe="CWE-798",
        pattern=re.compile(r"(?i)\b(param(?:eter)?|localparam)\s+\w*key\w*\s*=\s*\d*'h[0-9a-f]{8,}"),
        description="Hardcoded key/secret constant in RTL; a fixed key baked into silicon/bitstream cannot be "
                    "rotated and is extractable via readback or side-channel analysis.",
        severity=Severity.CRITICAL,
        language="verilog",
    ),
    # -------------------------------------------------------------- VHDL ---
    DangerRule(
        name="hdl_vhdl_jtag_debug_hardcoded_enable",
        cwe="CWE-1191",
        pattern=re.compile(r"(?i)\b(jtag|debug)_?en(?:able)?\s*<=\s*'1'"),
        description="On-chip debug/JTAG interface appears hardcoded enabled with no access-control gating; "
                    "should be gated by a fuse/lock bit or disabled in production builds.",
        severity=Severity.CRITICAL,
        language="vhdl",
    ),
    DangerRule(
        name="hdl_vhdl_hardcoded_key_constant",
        cwe="CWE-798",
        pattern=re.compile(r"(?i)\bconstant\s+\w*key\w*\s*:.*:=\s*x\"[0-9a-f]{8,}\""),
        description="Hardcoded key/secret constant in RTL; a fixed key baked into silicon/bitstream cannot be "
                    "rotated and is extractable via readback or side-channel analysis.",
        severity=Severity.CRITICAL,
        language="vhdl",
    ),
]

# Function/module-boundary patterns used to attribute a finding to a named
# scope, one per language family.
_FUNC_PATTERNS = {
    "c": re.compile(r"^[\w\*\s]+\b(\w+)\s*\([^;{]*\)\s*\{?\s*$"),
    "python": re.compile(r"^\s*def\s+(\w+)\s*\("),
    "javascript": re.compile(r"^\s*(?:async\s+)?function\s+(\w+)\s*\(|^\s*const\s+(\w+)\s*=\s*(?:async\s*)?\("),
    "verilog": re.compile(r"^\s*module\s+(\w+)"),
    "vhdl": re.compile(r"^\s*entity\s+(\w+)", re.IGNORECASE),
}


class StaticAnalyzer:
    def __init__(self, rules: list[DangerRule] | None = None):
        self.rules = rules or RULES

    def analyze_source(
        self, file_path: str, source: str, language: str | None = None
    ) -> list[VulnerabilityFinding]:
        lang = language or detect_language(file_path, source)
        applicable_rules = [r for r in self.rules if r.language == lang]

        findings: list[VulnerabilityFinding] = []
        lines = source.splitlines()
        current_scope = ""
        func_re = _FUNC_PATTERNS.get(lang, _FUNC_PATTERNS["c"])

        for idx, line in enumerate(lines, start=1):
            m = func_re.match(line)
            if m:
                current_scope = next((g for g in m.groups() if g), current_scope)

            for rule in applicable_rules:
                if rule.pattern.search(line):
                    findings.append(
                        VulnerabilityFinding(
                            cwe=rule.cwe,
                            file_path=file_path,
                            line=idx,
                            function=current_scope,
                            description=rule.description,
                            severity=rule.severity,
                            source="static_analyzer",
                            language=lang,
                        )
                    )
        return findings

    def analyze_file(self, file_path: str, language: str | None = None) -> list[VulnerabilityFinding]:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        return self.analyze_source(file_path, source, language=language)
