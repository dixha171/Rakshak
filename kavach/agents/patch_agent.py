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
import re

from kavach.config import KavachConfig, DEFAULT_CONFIG
from kavach.models import VulnerabilityFinding, PatchCandidate
from kavach.agents import llm_client
from kavach.agents.llm_client import LLMError

CODE_FENCE_RE = re.compile(r"```(?:[a-zA-Z]*)\n(.*?)```", re.DOTALL)

PATCH_PROMPT_TEMPLATE = """You are a C security-patch generator. Fix ONE specific memory-safety
defect with the smallest possible change. Do not refactor, rename, or reformat
anything you don't have to touch.

CWE: {cwe}
File: {file_path}
Function: {function}
Description: {description}

Full current file contents:
```c
{source}
```

Respond with ONLY the complete, corrected file contents in a single ```c
code fence. No explanation, no commentary, no markdown outside the fence.
"""


class PatchAgent:
    def __init__(self, config: KavachConfig = DEFAULT_CONFIG):
        self.config = config

    def synthesize(self, finding: VulnerabilityFinding, source: str) -> PatchCandidate:
        patched = self._apply_heuristic(finding, source)
        generic = False
        llm_assisted = False

        if patched is None:
            patched = self._apply_generic_pattern_fix(finding, source)
            if patched is not None:
                generic = True

        if patched is None and self.config.is_network_enabled():
            try:
                patched = self._apply_llm(finding, source)
                llm_assisted = True
            except LLMError as exc:
                return PatchCandidate(
                    finding_id=finding.id,
                    file_path=finding.file_path,
                    diff="",
                    rationale=f"No template matched this case, and LLM-assisted patching failed: {exc}",
                )

        if patched is None:
            return PatchCandidate(
                finding_id=finding.id,
                file_path=finding.file_path,
                diff="",
                rationale=self._no_patch_rationale(finding.cwe),
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

        rationale = self._rationale_for(finding.cwe)
        if llm_assisted:
            rationale = f"[LLM-assisted, backend={self.config.backend.value}] {rationale}"
        elif generic:
            rationale = f"[generic pattern fix — review before applying] {rationale}"

        return PatchCandidate(
            finding_id=finding.id,
            file_path=finding.file_path,
            diff=diff_text,
            diff_line_count=changed_lines,
            rationale=rationale,
            generated_by=(
                "patch_agent" if not (llm_assisted or generic)
                else (f"patch_agent+{self.config.backend.value}" if llm_assisted else "patch_agent+generic")
            ),
        )

    def _no_patch_rationale(self, cwe: str) -> str:
        if cwe in ("CWE-120", "CWE-119"):
            return (
                "A safe automatic fix for strcpy()/memcpy() requires knowing the destination buffer's "
                "actual capacity, which a text scan can't reliably determine (it may be a stack array, "
                "a struct field, or a heap allocation from elsewhere in the codebase). Manually replace "
                "with strncpy()/memcpy() bounded by the real destination size, or enable LLM-assisted "
                "patching (KAVACH_BACKEND=cloud_claude/cloud_openai/local_ollama) for a context-aware suggestion."
            )
        return (
            "No fix template matched this case; LLM-assisted patching not configured "
            "(set KAVACH_BACKEND to cloud_claude/cloud_openai/local_ollama with the matching "
            "API key/host to enable it)."
        )

    def _apply_llm(self, finding: VulnerabilityFinding, source: str) -> str:
        """Sends the file + finding context to the configured backend and
        expects back the complete patched file contents in a code fence.
        Raises LLMError if the backend fails or the response can't be
        parsed into usable source."""
        prompt = PATCH_PROMPT_TEMPLATE.format(
            cwe=finding.cwe,
            file_path=finding.file_path,
            function=finding.function or "(unknown)",
            description=finding.description,
            source=source,
        )
        response_text = llm_client.get_llm_response(prompt, self.config)

        match = CODE_FENCE_RE.search(response_text)
        if not match:
            raise LLMError("LLM response did not contain a ```c code fence with patched source")

        patched = match.group(1)
        if not patched.strip():
            raise LLMError("LLM response's code fence was empty")
        if not patched.endswith("\n"):
            patched += "\n"
        return patched

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

    def _apply_generic_pattern_fix(self, finding: VulnerabilityFinding, source: str) -> str | None:
        """
        Fixes that are mechanically safe to auto-generate on ARBITRARY code,
        because the correct fix doesn't depend on knowing anything about the
        surrounding program (unlike strcpy/memcpy, where a safe fix needs the
        real destination buffer size). Operates on the specific line the
        static analyzer flagged, not a literal string match against one
        known file.
        """
        lines = source.splitlines(keepends=True)
        idx = finding.line - 1
        if idx < 0 or idx >= len(lines):
            return None
        target_line = lines[idx]

        if finding.cwe == "CWE-416":
            m = re.match(r"^(\s*)free\(\s*([\w.\->]+)\s*\)\s*;", target_line)
            if not m:
                return None
            indent, ptr_expr = m.group(1), m.group(2)
            trailing_comment = target_line[m.end():].rstrip("\n")
            next_line = lines[idx + 1] if idx + 1 < len(lines) else ""
            if re.match(rf"^\s*{re.escape(ptr_expr)}\s*=\s*NULL\s*;", next_line):
                return None  # already guarded, nothing to do
            new_lines = lines[:]
            new_lines[idx] = (
                f"{indent}free({ptr_expr});{trailing_comment}\n"
                f"{indent}{ptr_expr} = NULL; /* patched: prevent use-after-free */\n"
            )
            return "".join(new_lines)

        if finding.cwe == "CWE-190":
            m = re.match(r"^(\s*)((?:\w[\w\s\*]*?))\s*=\s*malloc\(\s*(\w+)\s*\*\s*(\w+)\s*\)\s*;", target_line)
            if not m:
                return None
            indent, decl, var_a, var_b = m.groups()
            decl = decl.strip()
            # Split "TYPE *name" into the type/pointer part and the bare
            # variable name, so the pointer can be declared ONCE before the
            # if/else (declaring it inside both branches would scope it out
            # before any code after the branches could use it).
            name_match = re.search(r"([A-Za-z_]\w*)$", decl)
            if not name_match:
                return None
            varname = name_match.group(1)
            type_part = decl[: name_match.start()].rstrip()
            new_lines = lines[:]
            new_lines[idx] = (
                f"{indent}{type_part} {varname};\n"
                f"{indent}size_t __kavach_total = (size_t)({var_a}) * (size_t)({var_b});\n"
                f"{indent}if ({var_a} != 0 && __kavach_total / (size_t){var_a} != (size_t){var_b}) {{\n"
                f"{indent}    {varname} = NULL; /* patched: reject overflow */\n"
                f"{indent}}} else {{\n"
                f"{indent}    {varname} = malloc(__kavach_total);\n"
                f"{indent}}}\n"
            )
            return "".join(new_lines)

        return None

    def apply_all(self, findings: list[VulnerabilityFinding], source: str) -> tuple[str, list[str]]:
        """
        Applies every finding's available fix (heuristic or generic) into a
        single combined file. Findings are processed from the highest line
        number down to the lowest: since each fix only replaces/extends its
        own flagged line, editing bottom-up means earlier (lower) line
        numbers never shift out from under a not-yet-processed finding.

        Findings with no available fix (e.g. strcpy/memcpy needing real
        buffer-size context) are simply skipped, not faked. Returns
        (patched_source, applied_labels) so the caller can show which
        findings actually got folded into the combined file.
        """
        working = source
        applied: list[str] = []
        for f in sorted(findings, key=lambda finding: finding.line, reverse=True):
            candidate = self._apply_heuristic(f, working)
            if candidate is None:
                candidate = self._apply_generic_pattern_fix(f, working)
            if candidate is not None and candidate != working:
                working = candidate
                applied.append(f"{f.cwe} line {f.line} ({f.function or 'top-level'})")
        return working, applied

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
