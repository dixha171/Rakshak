"""
Lightweight mutation-based fuzzer.

Closes the "fuzzers" gap named in the AI Kavach brief: static_analyzer.py
finds known-pattern bugs, and sandbox/verifier.py's exploit replay proves
a fix against an ALREADY-KNOWN crash. Neither one explores the input
space to find NEW crashes nobody has already written a test for — that's
this module's job.

Deliberately simple and dependency-free, consistent with the rest of
KAVACH: no coverage instrumentation, no corpus scheduling — just seed
mutation plus crash detection via process exit signal / ASan abort. This
is a starting point for surfacing novel crashes on the C benchmark
targets, not a production-grade fuzzer (no AFL/libFuzzer-style feedback
loop, no corpus minimization).

Any input that crashes the target is saved to disk and parsed through
kavach.analyzers.crash_analyzer.CrashAnalyzer — the exact same parser
used for externally-supplied ASan logs — so a fuzzer-discovered crash is
localized, typed, and turned into a VulnerabilityFinding identically to
any other crash-derived finding, then flows through the same
triage -> patch -> review-gate -> verify pipeline as everything else.
"""
from __future__ import annotations

import os
import random
import subprocess
import time
from dataclasses import dataclass

from kavach.models import CrashReport, VulnerabilityFinding
from kavach.analyzers.crash_analyzer import CrashAnalyzer

# A short list of byte values that classically trip up size/bounds
# handling — not exhaustive, just the standard "edge case" bytes.
_INTERESTING_BYTES = bytes([0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE])


@dataclass
class FuzzConfig:
    target_binary: str
    seed_dir: str
    crash_dir: str = "fuzz_crashes"
    max_iterations: int = 2000
    max_seconds: float = 60.0
    timeout_per_run: float = 2.0
    mode: str = "stdin"  # "stdin" or "argv" — how input reaches the target
    asan_options: str = "abort_on_error=1:exitcode=134"


class Fuzzer:
    """
    Runs a compiled, ASan-built target binary against mutated versions of
    a seed corpus, looking for inputs that crash it. Intended to run
    against the same ASan builds the Triple-Lock verifier already uses
    for exploit replay — this fuzzer doesn't build anything itself.
    """

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.crash_analyzer = CrashAnalyzer()
        os.makedirs(self.config.crash_dir, exist_ok=True)

    def run(self) -> list[CrashReport]:
        """Returns raw CrashReports, already parsed via CrashAnalyzer.
        Use fuzz_and_triage() below if you want VulnerabilityFindings
        instead, ready to hand to Orchestrator.run()."""
        seeds = self._load_seeds()
        if not seeds:
            raise ValueError(
                f"No seed files found in {self.config.seed_dir}; the fuzzer "
                "needs at least one valid example input to mutate from."
            )

        crashes: list[CrashReport] = []
        start = time.time()
        iteration = 0

        while (
            iteration < self.config.max_iterations
            and (time.time() - start) < self.config.max_seconds
        ):
            iteration += 1
            seed = random.choice(seeds)
            candidate = self._mutate(seed)

            crashed, stderr_text, _returncode = self._run_target(candidate)
            if crashed:
                crashes.append(self._build_crash_report(candidate, stderr_text, iteration))

        return crashes

    def _load_seeds(self) -> list[bytes]:
        seeds = []
        for name in sorted(os.listdir(self.config.seed_dir)):
            path = os.path.join(self.config.seed_dir, name)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    seeds.append(f.read())
        return seeds

    def _mutate(self, seed: bytes) -> bytes:
        """
        Applies ONE random mutation per iteration, from a small classic
        mutation set. Kept simple on purpose — with no coverage feedback
        loop, more elaborate scheduling wouldn't actually buy anything
        here; the value is in running many cheap mutations fast.
        """
        data = bytearray(seed) if seed else bytearray(b"\x00")
        strategy = random.choice(
            ["bitflip", "byte_sub", "insert_interesting", "truncate", "extend"]
        )

        if strategy == "bitflip" and data:
            idx = random.randrange(len(data))
            data[idx] ^= 1 << random.randrange(8)

        elif strategy == "byte_sub" and data:
            idx = random.randrange(len(data))
            data[idx] = random.choice(_INTERESTING_BYTES)

        elif strategy == "insert_interesting":
            idx = random.randrange(len(data) + 1)
            data[idx:idx] = bytes([random.choice(_INTERESTING_BYTES)])

        elif strategy == "truncate" and len(data) > 1:
            cut = random.randrange(1, len(data))
            data = data[:cut]

        elif strategy == "extend":
            data += bytes(random.choice(_INTERESTING_BYTES) for _ in range(random.randint(1, 16)))

        return bytes(data)

    def _run_target(self, data: bytes) -> tuple[bool, str, int]:
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = self.config.asan_options

        try:
            if self.config.mode == "stdin":
                proc = subprocess.run(
                    [self.config.target_binary],
                    input=data,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    env=env,
                    timeout=self.config.timeout_per_run,
                )
            else:  # "argv" mode — write to a temp file and pass its path
                tmp_path = os.path.join(self.config.crash_dir, ".fuzz_input.tmp")
                with open(tmp_path, "wb") as f:
                    f.write(data)
                proc = subprocess.run(
                    [self.config.target_binary, tmp_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    env=env,
                    timeout=self.config.timeout_per_run,
                )
        except subprocess.TimeoutExpired:
            # A hang is arguably its own finding (potential DoS), but this
            # fuzzer's scope is crash discovery for the existing
            # ASan-crash pipeline — timeouts are skipped rather than
            # forced into a CrashReport shape that doesn't fit them.
            return False, "", -1

        stderr_text = proc.stderr.decode("utf-8", errors="replace")
        crashed = (
            proc.returncode < 0
            or proc.returncode == 134
            or "ERROR: AddressSanitizer" in stderr_text
        )
        return crashed, stderr_text, proc.returncode

    def _build_crash_report(self, data: bytes, stderr_text: str, iteration: int) -> CrashReport:
        crash_path = os.path.join(self.config.crash_dir, f"crash_{iteration:06d}.bin")
        with open(crash_path, "wb") as f:
            f.write(data)

        # Delegate to the real parser instead of a local fallback — this
        # is the same CrashAnalyzer.parse() used for externally-supplied
        # ASan logs, so fuzzer-found and externally-reported crashes are
        # localized and typed identically, with no drift between the two.
        report = self.crash_analyzer.parse(self.config.target_binary, stderr_text)
        return report

    def fuzz_and_triage(self) -> list[VulnerabilityFinding]:
        """
        Runs the fuzzer and converts every crash straight into a
        VulnerabilityFinding, ready to pass to Orchestrator.run() the
        same way a static_analyzer or externally-reported finding would.
        This is the entry point most callers (CLI, orchestrator hook)
        should actually use — run() is exposed separately for callers
        who want the raw CrashReports instead.
        """
        reports = self.run()
        return [self.crash_analyzer.to_finding(r) for r in reports]


def fuzz_target(
    target_binary: str,
    seed_dir: str,
    crash_dir: str = "fuzz_crashes",
    max_iterations: int = 2000,
    max_seconds: float = 60.0,
) -> list[VulnerabilityFinding]:
    """Convenience entry point for CLI / orchestrator integration.
    Returns VulnerabilityFindings, not raw CrashReports — use Fuzzer.run()
    directly if you need the raw reports instead."""
    config = FuzzConfig(
        target_binary=target_binary,
        seed_dir=seed_dir,
        crash_dir=crash_dir,
        max_iterations=max_iterations,
        max_seconds=max_seconds,
    )
    return Fuzzer(config).fuzz_and_triage()
