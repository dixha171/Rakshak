"""
Regression + exploit-replay harness for Target 1 (cwe_119_buffer_overflow).

Run standalone:
    python3 tests/test_regression_packet.py

This is also invoked by kavach/sandbox/verifier.py as part of the
Triple-Lock Verification flow (Exploit Replay + Regression Suite + Certification).
"""
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(ROOT, "build")
BIN_PATH = os.path.join(BIN_DIR, "packet_parser_harness")


def build(cc="gcc", extra_flags=None):
    os.makedirs(BIN_DIR, exist_ok=True)
    flags = extra_flags or []
    cmd = [
        cc, "-g", "-O0",
        "-DPACKET_PARSER_STANDALONE",
        os.path.join(ROOT, "src", "packet_parser.c"),
        "-o", BIN_PATH,
    ] + flags
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result


def run_exploit_replay():
    """Build with ASan and confirm the known overflow input crashes (pre-patch)
    or passes cleanly (post-patch)."""
    build_result = build(extra_flags=["-fsanitize=address", "-fno-omit-frame-pointer"])
    if build_result.returncode != 0:
        print("BUILD FAILED:\n", build_result.stderr)
        return False, build_result.stderr

    run_result = subprocess.run([BIN_PATH], capture_output=True, text=True)
    crashed = run_result.returncode != 0 or "AddressSanitizer" in run_result.stderr
    return crashed, run_result.stderr


def run_regression_suite():
    """Functional regression cases that must keep passing after a patch."""
    cases_ok = True
    build_result = build()
    if build_result.returncode != 0:
        print("BUILD FAILED:\n", build_result.stderr)
        return False
    run_result = subprocess.run([BIN_PATH], capture_output=True, text=True)
    if run_result.returncode != 0:
        cases_ok = False
    return cases_ok


if __name__ == "__main__":
    crashed, stderr = run_exploit_replay()
    if crashed:
        print("[PRE-PATCH] Exploit replay reproduced the crash (expected before patch).")
        print(stderr[-500:] if stderr else "")
        sys.exit(1)
    else:
        print("[POST-PATCH] Exploit replay did NOT crash — vulnerability appears patched.")
        ok = run_regression_suite()
        print("Regression suite:", "PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)
