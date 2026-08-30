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
from kavach.languages import pipeline_for, display_name
from kavach.agents import llm_client
from kavach.agents.llm_client import LLMError

CODE_FENCE_RE = re.compile(r"```(?:[a-zA-Z]*)\n(.*?)```", re.DOTALL)

PATCH_PROMPT_TEMPLATE = """You are a {language} security-patch generator. Fix ONE specific
weakness with the smallest possible change. Do not refactor, rename, or reformat
anything you don't have to touch.

CWE: {cwe}
File: {file_path}
Function/module: {function}
Description: {description}

Full current file contents:
