"""
Multi-compiler interface with cross-platform fallback (GCC -> Clang).
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class CompileResult:
    ok: bool
    compiler_used: str
    stdout: str
    stderr: str
    binary_path: str


class Compiler:
    CANDIDATES = ["gcc", "clang", "cc"]

    def __init__(self, preferred: str | None = None):
        self.preferred = preferred

    def _resolve_compiler(self) -> str:
        order = [self.preferred] if self.preferred else []
        order += [c for c in self.CANDIDATES if c != self.preferred]
        for candidate in order:
            if candidate and shutil.which(candidate):
                return candidate
        raise RuntimeError(
            "No usable C compiler found on PATH (tried: gcc, clang, cc). "
            "Install build-essential or clang."
        )

    def compile(
        self,
        sources: list[str],
        output: str,
        extra_flags: list[str] | None = None,
        defines: list[str] | None = None,
    ) -> CompileResult:
        cc = self._resolve_compiler()
        flags = extra_flags or []
        define_flags = [f"-D{d}" for d in (defines or [])]
        cmd = [cc, "-g", "-O0", "-Wall"] + define_flags + sources + flags + ["-o", output]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return CompileResult(
            ok=proc.returncode == 0,
            compiler_used=cc,
            stdout=proc.stdout,
            stderr=proc.stderr,
            binary_path=output if proc.returncode == 0 else "",
        )

    def compile_with_asan(self, sources: list[str], output: str, defines: list[str] | None = None) -> CompileResult:
        return self.compile(
            sources,
            output,
            extra_flags=["-fsanitize=address", "-fno-omit-frame-pointer"],
            defines=defines,
        )
