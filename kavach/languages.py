"""
Language detection and pipeline classification.

KAVACH runs two conceptually different pipelines:

  - "software": C, Python, JavaScript, etc. — languages where a fix can be
    compiled/interpreted and (for C, today) actually exploit-replayed and
    regression-tested in this environment, so an automatic fix can be
    CERTIFIED with real evidence behind that label.

  - "hardware": Verilog, VHDL — hardware description languages. There is no
    synthesizer/simulator toolchain in this environment, so a "fix" here
    can never be proven the way a C patch can be. Findings in this pipeline
    are therefore ALWAYS routed through human review (see review_gate.py)
    regardless of any other criteria — this isn't a policy choice so much
    as an honest acknowledgment of what can and can't be automatically
    verified here.
"""
from __future__ import annotations

import os

EXTENSION_LANGUAGE_MAP = {
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
    ".cxx": "c",
    ".hpp": "c",
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",  # treated with the same rule set for now
    ".v": "verilog",
    ".sv": "verilog",
    ".vh": "verilog",
    ".vhd": "vhdl",
    ".vhdl": "vhdl",
}

LANGUAGE_PIPELINE = {
    "c": "software",
    "python": "software",
    "javascript": "software",
    "verilog": "hardware",
    "vhdl": "hardware",
}

LANGUAGE_DISPLAY_NAME = {
    "c": "C/C++",
    "python": "Python",
    "javascript": "JavaScript/TypeScript",
    "verilog": "Verilog/SystemVerilog",
    "vhdl": "VHDL",
}


def detect_language(filename: str, source: str | None = None) -> str:
    """Detects a source file's language, first by extension, then (if the
    extension is missing/unknown) by a couple of very cheap content
    sniffs. Defaults to 'c' if nothing matches, to preserve existing
    behavior for callers that don't specify a language."""
    ext = os.path.splitext(filename)[1].lower()
    if ext in EXTENSION_LANGUAGE_MAP:
        return EXTENSION_LANGUAGE_MAP[ext]

    if source:
        head = source[:2000]
        if "module " in head and "endmodule" in source:
            return "verilog"
        if "entity " in head and "architecture" in source:
            return "vhdl"
        if "def " in head or "import " in head:
            return "python"
        if "function " in head or "const " in head or "require(" in head:
            return "javascript"

    return "c"


def pipeline_for(language: str) -> str:
    return LANGUAGE_PIPELINE.get(language, "software")


def display_name(language: str) -> str:
    return LANGUAGE_DISPLAY_NAME.get(language, language)


def extension_for(language: str) -> str:
    """Default file extension to use when writing/downloading a file for
    a given language (the reverse of EXTENSION_LANGUAGE_MAP, since that
    map has several extensions pointing at the same language)."""
    defaults = {
        "c": ".c",
        "python": ".py",
        "javascript": ".js",
        "verilog": ".v",
        "vhdl": ".vhd",
    }
    return defaults.get(language, ".txt")
