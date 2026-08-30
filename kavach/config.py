"""
Zero-dependency configuration for KAVACH's LLM backend.

Supports three tiers, selected purely via environment variables so the
core package has no hard dependency on any particular SDK:

  1. Cloud LLMs      - Claude (Anthropic) / OpenAI, via plain HTTPS calls.
  2. Local SLMs      - Ollama-hosted models (e.g. deepseek-coder), for
                       air-gap-adjacent or low-cost operation.
  3. Air-Gapped      - no network calls at all; falls back to the
                       heuristic-only static analyzer / patch templates.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum


class BackendKind(str, Enum):
    CLOUD_CLAUDE = "cloud_claude"
    CLOUD_OPENAI = "cloud_openai"
    LOCAL_OLLAMA = "local_ollama"
    AIR_GAPPED = "air_gapped"


@dataclass
class KavachConfig:
    backend: BackendKind = field(default_factory=lambda: BackendKind(
        os.environ.get("KAVACH_BACKEND", BackendKind.AIR_GAPPED.value)
    ))

    # Cloud (Claude)
    anthropic_api_key: str | None = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY"))
    anthropic_model: str = field(default_factory=lambda: os.environ.get("KAVACH_ANTHROPIC_MODEL", "claude-sonnet-4-6"))

    # Cloud (OpenAI)
    openai_api_key: str | None = field(default_factory=lambda: os.environ.get("OPENAI_API_KEY"))
    openai_model: str = field(default_factory=lambda: os.environ.get("KAVACH_OPENAI_MODEL", "gpt-4.1"))

    # Local (Ollama)
    ollama_host: str = field(default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    ollama_model: str = field(default_factory=lambda: os.environ.get("KAVACH_OLLAMA_MODEL", "deepseek-coder:6.7b"))

    # Sandbox / verification
    compiler: str = field(default_factory=lambda: os.environ.get("KAVACH_CC", "gcc"))
    max_patch_diff_lines: int = int(os.environ.get("KAVACH_MAX_DIFF_LINES", "14"))
    orchestrator_max_retries: int = int(os.environ.get("KAVACH_MAX_RETRIES", "3"))

    # Ledger
    ledger_db_path: str = field(default_factory=lambda: os.environ.get("KAVACH_LEDGER_DB", "kavach_audit.sqlite3"))

    def is_network_enabled(self) -> bool:
        return self.backend != BackendKind.AIR_GAPPED

    def describe(self) -> str:
        return f"KAVACH backend={self.backend.value} compiler={self.compiler}"


DEFAULT_CONFIG = KavachConfig()
