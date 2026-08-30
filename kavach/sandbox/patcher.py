"""
Atomic patch applicator with rollback capability.

Applies a PatchCandidate's unified diff to a source file on disk,
keeping a timestamped backup so the orchestrator can roll back
instantly if verification fails.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import time

from kavach.models import PatchCandidate


class Patcher:
    def __init__(self, backup_dir: str = ".kavach_backups"):
        self.backup_dir = backup_dir
        os.makedirs(self.backup_dir, exist_ok=True)

    def apply(self, source_path: str, patch: PatchCandidate) -> str:
        """Applies the patched content (reconstructed from the diff) to
        source_path, returning the backup path for rollback."""
        backup_path = os.path.join(
            self.backup_dir,
            f"{os.path.basename(source_path)}.{int(time.time() * 1000)}.bak",
        )
        shutil.copy2(source_path, backup_path)

        patched_content = self._apply_unified_diff(source_path, patch.diff)
        with open(source_path, "w", encoding="utf-8") as f:
            f.write(patched_content)

        return backup_path

    def apply_raw(self, file_path: str, new_content: str) -> str:
        """Directly writes new_content to file_path (used for companion
        header patches), returning the backup path."""
        backup_path = os.path.join(
            self.backup_dir,
            f"{os.path.basename(file_path)}.{int(time.time() * 1000)}.bak",
        )
        shutil.copy2(file_path, backup_path)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return backup_path

    def rollback(self, source_path: str, backup_path: str) -> None:
        shutil.copy2(backup_path, source_path)

    def sha256_of(self, file_path: str) -> str:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    @staticmethod
    def _apply_unified_diff(source_path: str, diff_text: str) -> str:
        """Applies a unified diff (as produced by difflib.unified_diff)
        to the current contents of source_path and returns the result."""
        with open(source_path, "r", encoding="utf-8") as f:
            original_lines = f.readlines()

        if not diff_text.strip():
            return "".join(original_lines)

        result_lines: list[str] = []
        orig_idx = 0
        diff_lines = diff_text.splitlines(keepends=True)

        i = 0
        while i < len(diff_lines):
            line = diff_lines[i]
            if line.startswith("@@"):
                header = line.strip("@ \n")
                old_part = header.split(" ")[0]
                old_start = int(old_part.split(",")[0].lstrip("-")) - 1
                while orig_idx < old_start:
                    result_lines.append(original_lines[orig_idx])
                    orig_idx += 1
                i += 1
                while i < len(diff_lines) and not diff_lines[i].startswith("@@"):
                    hline = diff_lines[i]
                    if hline.startswith("+") and not hline.startswith("+++"):
                        result_lines.append(hline[1:])
                    elif hline.startswith("-") and not hline.startswith("---"):
                        orig_idx += 1
                    elif hline.startswith(" "):
                        result_lines.append(hline[1:])
                        orig_idx += 1
                    i += 1
                continue
            i += 1

        while orig_idx < len(original_lines):
            result_lines.append(original_lines[orig_idx])
            orig_idx += 1

        return "".join(result_lines)
