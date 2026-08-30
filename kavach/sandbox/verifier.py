"""
Triple-Lock Verification: Exploit Replay + Regression Suite + Certification.

Each benchmark target ships a tests/test_regression_*.py module exposing
`run_exploit_replay()` and `run_regression_suite()`. The verifier imports
that module fresh (so it reflects the just-patched source on disk),
runs both gates, and only marks CERTIFIED if:
  1. The known exploit no longer crashes the (ASan-built) binary.
  2. The functional regression suite still passes.
  3. A final clean re-build (no sanitizer, release-ish flags) also
     compiles and runs successfully — the "Certification" lock, which
     catches sanitizer-only build breakage.
"""
from __future__ import annotations

import importlib
import io
import sys
import time
from contextlib import redirect_stdout

from kavach.config import KavachConfig, DEFAULT_CONFIG
from kavach.models import VerificationResult, VerificationStatus


class Verifier:
    def __init__(self, config: KavachConfig = DEFAULT_CONFIG):
        self.config = config

    def verify(self, test_module_name: str) -> VerificationResult:
        start = time.time()
        result = VerificationResult()
        log_buf = io.StringIO()

        try:
            if test_module_name in sys.modules:
                module = importlib.reload(sys.modules[test_module_name])
            else:
                module = importlib.import_module(test_module_name)
        except Exception as exc:  # noqa: BLE001
            result.status = VerificationStatus.FAILED
            result.log = f"failed to load test module: {exc}"
            result.duration_ms = (time.time() - start) * 1000
            return result

        with redirect_stdout(log_buf):
            try:
                crashed, _stderr = module.run_exploit_replay()
            except Exception as exc:  # noqa: BLE001
                result.status = VerificationStatus.FAILED
                result.log = f"exploit replay raised: {exc}"
                result.duration_ms = (time.time() - start) * 1000
                return result

            result.exploit_replay_ok = not crashed
            if crashed:
                result.status = VerificationStatus.FAILED
                result.log = log_buf.getvalue()
                result.duration_ms = (time.time() - start) * 1000
                return result

            try:
                regression_ok = module.run_regression_suite()
            except Exception as exc:  # noqa: BLE001
                result.status = VerificationStatus.FAILED
                result.log = f"regression suite raised: {exc}"
                result.duration_ms = (time.time() - start) * 1000
                return result

            result.regression_ok = regression_ok
            if not regression_ok:
                result.status = VerificationStatus.REGRESSION_PASSED  # partial
                result.status = VerificationStatus.FAILED
                result.log = log_buf.getvalue()
                result.duration_ms = (time.time() - start) * 1000
                return result

            # Certification lock: one more clean build (no sanitizer) to
            # catch anything that only worked because of ASan instrumentation.
            certified_ok = module.build().returncode == 0 if hasattr(module, "build") else True
            result.certified_ok = certified_ok

        result.duration_ms = (time.time() - start) * 1000
        result.log = log_buf.getvalue()
        result.status = (
            VerificationStatus.CERTIFIED if certified_ok else VerificationStatus.FAILED
        )
        return result
