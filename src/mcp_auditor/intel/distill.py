"""OPTIONAL, off-by-default LLM distillation of a candidate into a draft pattern.

Guardrails (deliberate):
  * Disabled unless explicitly enabled (`use_llm=True`). The deterministic,
    free path is the default; rules stay human-written and explainable.
  * The LLM only ever sees a paper's title + abstract — NEVER any target code.
  * Results are cached by content hash so re-runs cost ~0 tokens.
  * A human still approves whatever becomes an Atlas entry / signature rule
    (autodraft's tier/dedup gate stands in for that human on the merge path;
    see intel/autodraft.py).

Two providers are supported — pick whichever API key you actually have:
  * "gemini"    (google-genai, GEMINI_API_KEY / GOOGLE_API_KEY) — generous free
    tier, the default when a Gemini key is present and no provider is forced.
  * "anthropic" (anthropic, ANTHROPIC_API_KEY)

This module proposes a structured draft; it never writes to the knowledge base.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .model import Candidate

_PROMPT = (
    "You are helping curate a static-analysis signature set for Model Context "
    "Protocol (MCP) server security. Given the title and abstract of a research "
    "paper, propose at most 3 candidate detection ideas a STATIC scanner could "
    "use (regex-style metadata/code signals). Reply as JSON with keys: "
    "threat_name, lifecycle_phase, static_signals (list), draft_patterns (list). "
    "If nothing is statically detectable, say so."
)

DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-8",
    "gemini": "gemini-2.5-flash",
}


def _cache_key(candidate: Candidate) -> str:
    blob = f"{candidate.ident}\n{candidate.title}\n{candidate.summary}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _pick_provider() -> str:
    """Auto-select a provider from whichever API key is set. Gemini first —
    it's the free-tier-friendly default; Anthropic if only that key is set."""
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return "gemini"  # no key at all: fail with the gemini install/key message


def distill(
    candidate: Candidate,
    use_llm: bool = False,
    cache_dir: str | Path | None = None,
    model: str | None = None,
    provider: str | None = None,
) -> dict[str, Any]:
    """Return a draft distillation for `candidate`.

    With `use_llm=False` (default) this returns a manual-curation placeholder
    and makes no network call. With `use_llm=True` it consults a cache, then
    calls `provider` (or auto-detects one from the API keys set in the
    environment — see `_pick_provider`), caching the structured result.
    """
    if not use_llm:
        return {
            "status": "manual",
            "ident": candidate.ident,
            "note": "LLM distillation disabled. Read the abstract and encode a "
            "rule by hand into signatures.yaml + threats.yaml.",
            "matched": candidate.matched,
        }

    key = _cache_key(candidate)
    cache_path = Path(cache_dir) / f"{key}.json" if cache_dir else None
    if cache_path and cache_path.exists():
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        cached["status"] = "cached"
        return cached

    provider = provider or _pick_provider()
    model = model or DEFAULT_MODELS.get(provider, DEFAULT_MODELS["gemini"])
    if provider == "anthropic":
        result = _call_anthropic(candidate, model)
    elif provider == "gemini":
        result = _call_gemini(candidate, model)
    else:
        raise ValueError(f"Unknown LLM provider: {provider!r} (expected 'anthropic' or 'gemini')")

    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _parse_draft(text: str, candidate: Candidate) -> dict[str, Any]:
    draft: dict[str, Any]
    try:
        draft = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        draft = {"raw": text}
    draft["status"] = "drafted"
    draft["ident"] = candidate.ident
    return draft


def _call_anthropic(candidate: Candidate, model: str) -> dict[str, Any]:
    """Consult the Anthropic API on the abstract only. Lazy import + clear error."""
    try:
        import anthropic  # optional dependency; only needed for --use-llm
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "LLM distillation via Anthropic requires the 'anthropic' package. "
            "Install it (pip install anthropic) and set ANTHROPIC_API_KEY."
        ) from exc

    client = anthropic.Anthropic()
    msg = client.messages.create(
        model=model,
        max_tokens=700,
        system=_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Title: {candidate.title}\n\nAbstract: {candidate.summary}",
            }
        ],
    )
    text = "".join(getattr(block, "text", "") for block in msg.content)
    return _parse_draft(text, candidate)


def _call_gemini(candidate: Candidate, model: str) -> dict[str, Any]:
    """Consult the Gemini API on the abstract only. Lazy import + clear error."""
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "LLM distillation via Gemini requires the 'google-genai' package. "
            "Install it (pip install google-genai) and set GEMINI_API_KEY."
        ) from exc

    client = genai.Client()  # reads GEMINI_API_KEY / GOOGLE_API_KEY from the environment
    response = client.models.generate_content(
        model=model,
        contents=f"Title: {candidate.title}\n\nAbstract: {candidate.summary}",
        config=types.GenerateContentConfig(
            system_instruction=_PROMPT,
            response_mime_type="application/json",
            max_output_tokens=700,
        ),
    )
    return _parse_draft(response.text or "", candidate)
