"""
Regression + exploit-replay harness for Target 3 (cwe_190_integer_overflow).
"""
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(ROOT, "build")
BIN_PATH = os.path.join(BIN_DIR, "frame_alloc_harness")


def build(cc="gcc", extra_flags=None):
    os.makedirs(BIN_DIR, exist_ok=True)
    flags = extra_flags or []
    cmd = [
        cc, "-g", "-O0",
        "-DFRAME_ALLOC_STANDALONE",
        os.path.join(ROOT, "src", "frame_alloc.c"),
        "-o", BIN_PATH,
    ] + flags
    return subprocess.run(cmd, capture_output=True, text=True)


def run_exploit_replay():
    build_result = build(extra_flags=["-fsanitize=address", "-fno-omit-frame-pointer"])
    if build_result.returncode != 0:
        print("BUILD FAILED:\n", build_result.stderr)
        return False, build_result.stderr
    run_result = subprocess.run([BIN_PATH], capture_output=True, text=True)
    crashed = run_result.returncode != 0 or "AddressSanitizer" in run_result.stderr
    return crashed, run_result.stderr


def run_regression_suite():
    build_result = build()
    if build_result.returncode != 0:
        return False
    run_result = subprocess.run([BIN_PATH], capture_output=True, text=True)
    return run_result.returncode == 0


if __name__ == "__main__":
    crashed, stderr = run_exploit_replay()
    if crashed:
        print("[PRE-PATCH] Exploit replay reproduced the integer-overflow crash (expected before patch).")
        print(stderr[-500:] if stderr else "")
        sys.exit(1)
    else:
        print("[POST-PATCH] Exploit replay did NOT crash — vulnerability appears patched.")
        ok = run_regression_suite()
        print("Regression suite:", "PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)
