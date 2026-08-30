"""
Zero-framework LLM client for KAVACH's LLM-assisted patch synthesis.

Uses only `urllib` from the standard library (no `requests`/SDK
dependency) so the air-gapped default stays true to zero-dependency,
and the network-enabled tiers work without pinning an SDK version.

Each backend function raises LLMError on any failure (bad key, timeout,
non-2xx response, malformed body) so callers can uniformly fall back to
the heuristic patch templates without inspecting backend-specific
exceptions.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error

from kavach.config import KavachConfig, BackendKind


class LLMError(RuntimeError):
    pass


def _post_json(url: str, headers: dict, body: dict, timeout: float = 30.0) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMError(f"HTTP {exc.code} from {url}: {detail[:500]}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(f"network error contacting {url}: {exc.reason}") from exc
    except (TimeoutError, json.JSONDecodeError) as exc:
        raise LLMError(f"error contacting {url}: {exc}") from exc


def call_cloud_claude(prompt: str, config: KavachConfig) -> str:
    if not config.anthropic_api_key:
        raise LLMError("ANTHROPIC_API_KEY is not set")

    body = {
        "model": config.anthropic_model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {
        "content-type": "application/json",
        "x-api-key": config.anthropic_api_key,
        "anthropic-version": "2023-06-01",
    }
    data = _post_json("https://api.anthropic.com/v1/messages", headers, body)

    try:
        blocks = data["content"]
        text = "".join(b["text"] for b in blocks if b.get("type") == "text")
    except (KeyError, TypeError) as exc:
        raise LLMError(f"unexpected Claude response shape: {data}") from exc

    if not text:
        raise LLMError("Claude returned no text content")
    return text


def call_cloud_openai(prompt: str, config: KavachConfig) -> str:
    if not config.openai_api_key:
        raise LLMError("OPENAI_API_KEY is not set")

    body = {
        "model": config.openai_model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    }
    headers = {
        "content-type": "application/json",
        "authorization": f"Bearer {config.openai_api_key}",
    }
    data = _post_json("https://api.openai.com/v1/chat/completions", headers, body)

    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"unexpected OpenAI response shape: {data}") from exc

    if not text:
        raise LLMError("OpenAI returned no text content")
    return text


def call_local_ollama(prompt: str, config: KavachConfig) -> str:
    body = {
        "model": config.ollama_model,
        "prompt": prompt,
        "stream": False,
    }
    headers = {"content-type": "application/json"}
    url = config.ollama_host.rstrip("/") + "/api/generate"
    data = _post_json(url, headers, body)

    text = data.get("response")
    if not text:
        raise LLMError(f"unexpected Ollama response shape: {data}")
    return text


def get_llm_response(prompt: str, config: KavachConfig) -> str:
    """Dispatches to the configured backend. Raises LLMError on any
    failure — callers should catch this and fall back to heuristics."""
    if config.backend == BackendKind.CLOUD_CLAUDE:
        return call_cloud_claude(prompt, config)
    if config.backend == BackendKind.CLOUD_OPENAI:
        return call_cloud_openai(prompt, config)
    if config.backend == BackendKind.LOCAL_OLLAMA:
        return call_local_ollama(prompt, config)
    raise LLMError(f"backend {config.backend} has no network client (air-gapped)")
