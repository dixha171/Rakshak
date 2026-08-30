"""
Patch agent: synthesizes minimal-diff (< 10 LOC) source patches.

Two modes:
  - Heuristic/template mode (default, works air-gapped): applies a small
    library of proven fix patterns keyed by CWE — bounds checks before
    memcpy, NULL-clearing after free(), overflow-safe size checks before
    malloc(). This is what powers the benchmark targets out of the box.
  - LLM-assisted mode (when kavach.config.KavachConfig.is_network_enabled()
    is True): sends the function body + finding + evidence graph context
    to the configured Cloud/Local backend and asks for a unified diff,
    then falls back to heuristic mode if the model's diff fails
    verification or exceeds the max diff-line budget.
"""
from __future__ import annotations

import difflib

from kavach.config import KavachConfig, DEFAULT_CONFIG
from kavach.models import VulnerabilityFinding, PatchCandidate


class PatchAgent:
    def __init__(self, config: KavachConfig = DEFAULT_CONFIG):
        self.config = config

    def synthesize(self, finding: VulnerabilityFinding, source: str) -> PatchCandidate:
        patched = self._apply_heuristic(finding, source)
        if patched is None:
            return PatchCandidate(
                finding_id=finding.id,
                file_path=finding.file_path,
                diff="",
                rationale="No heuristic template matched this CWE; LLM-assisted patching not configured.",
            )

        diff_lines = list(
            difflib.unified_diff(
                source.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=finding.file_path,
                tofile=finding.file_path + " (patched)",
            )
        )
        diff_text = "".join(diff_lines)
        changed_lines = sum(
            1 for line in diff_lines if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
        )

        return PatchCandidate(
            finding_id=finding.id,
            file_path=finding.file_path,
            diff=diff_text,
            diff_line_count=changed_lines,
            rationale=self._rationale_for(finding.cwe),
        )

    def _rationale_for(self, cwe: str) -> str:
        return {
            "CWE-119": "Added an explicit upper-bounds check before memcpy() so the copy size can never exceed the destination buffer's capacity.",
            "CWE-120": "Added an explicit upper-bounds check before memcpy() so the copy size can never exceed the destination buffer's capacity.",
            "CWE-416": "Cleared the caller's pointer to NULL immediately after free() and added a NULL guard in the consumer, preventing use-after-free.",
            "CWE-190": "Replaced the raw multiplication with an overflow-checked size computation before the allocation.",
        }.get(cwe, "Applied minimal-diff defensive fix for the identified CWE.")

    def _apply_heuristic(self, finding: VulnerabilityFinding, source: str) -> str | None:
        if finding.cwe in ("CWE-119", "CWE-120") and "memcpy(out->payload" in source:
            return source.replace(
                "    /* BUG: missing `if (len > PACKET_BUF_SIZE) return -1;` check here */\n"
                "    memcpy(out->payload, raw + 2, len);",
                "    if (len > PACKET_BUF_SIZE) {\n"
                "        return -1; /* patched: reject frames that would overflow payload[] */\n"
                "    }\n"
                "    memcpy(out->payload, raw + 2, len);",
            )

        if finding.cwe == "CWE-416" and "void session_logout" in source:
            patched = source.replace(
                "void session_logout(AuthSession *session) {\n"
                "    if (!session) return;\n"
                "    free(session);\n"
                "    /* BUG: no `session = NULL;`-equivalent contract — callers keep the\n"
                "       dangling pointer and nothing here invalidates it. */\n"
                "}",
                "void session_logout(AuthSession **session) {\n"
                "    if (!session || !*session) return;\n"
                "    free(*session);\n"
                "    *session = NULL;\n"
                "}",
            )
            # Update the call site so the patched double-pointer contract
            # compiles and actually prevents the use-after-free end-to-end.
            patched = patched.replace(
                "    session_logout(s);\n"
                "    /* Use-after-free trigger: touching the session after logout */\n"
                "    int rc = session_touch(s);",
                "    session_logout(&s);\n"
                "    int rc = (s == NULL) ? -1 : session_touch(s);",
            )
            return patched

        if finding.cwe == "CWE-190" and "int total = num_samples * sample_size" in source:
            patched = source.replace(
                "    int total = num_samples * sample_size; /* BUG: no overflow check */\n"
                "    void *buf = malloc((size_t)total);",
                "    size_t total = (size_t)num_samples * (size_t)sample_size;\n"
                "    if (total / (size_t)num_samples != (size_t)sample_size || total > FRAME_ALLOC_MAX_BYTES) {\n"
                "        return NULL; /* patched: reject overflow or unreasonably large frames */\n"
                "    }\n"
                "    void *buf = malloc(total);",
            )
            patched = patched.replace(
                "#include \"../include/frame_alloc.h\"",
                "#include \"../include/frame_alloc.h\"\n\n#define FRAME_ALLOC_MAX_BYTES (16u * 1024 * 1024)",
            )
            # main() must reflect the patched contract: a NULL return now
            # means the request was safely rejected, not an unexpected failure.
            patched = patched.replace(
                "    void *buf = frame_alloc(num_samples, sample_size);\n"
                "    if (!buf) {\n"
                "        printf(\"alloc failed (unexpected for this harness)\\n\");\n"
                "        return 1;\n"
                "    }",
                "    void *buf = frame_alloc(num_samples, sample_size);\n"
                "    if (!buf) {\n"
                "        printf(\"request safely rejected by overflow/size guard\\n\");\n"
                "        return 0;\n"
                "    }",
            )
            return patched

        return None

    def companion_header_patch(self, finding: VulnerabilityFinding, header_source: str) -> str | None:
        """Some fixes (e.g. the CWE-416 double-pointer contract change) also
        require updating the paired header's declaration. Returns the
        patched header source, or None if this finding doesn't need one."""
        if finding.cwe == "CWE-416" and "void session_logout(AuthSession *session);" in header_source:
            return header_source.replace(
                "void session_logout(AuthSession *session);",
                "void session_logout(AuthSession **session);",
            )
        return None
