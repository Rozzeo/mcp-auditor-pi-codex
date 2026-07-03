"""OPTIONAL, off-by-default LLM distillation of a candidate into a draft pattern.

Guardrails (deliberate):
  * Disabled unless explicitly enabled (`use_llm=True`). The deterministic,
    free path is the default; rules stay human-written and explainable.
  * The LLM only ever sees a paper's title + abstract — NEVER any target code.
  * Results are cached by content hash so re-runs cost ~0 tokens.
  * A human still approves whatever becomes an Atlas entry / signature rule.

This module proposes a structured draft; it never writes to the knowledge base.
"""

from __future__ import annotations

import hashlib
import json
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


def _cache_key(candidate: Candidate) -> str:
    blob = f"{candidate.ident}\n{candidate.title}\n{candidate.summary}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def distill(
    candidate: Candidate,
    use_llm: bool = False,
    cache_dir: str | Path | None = None,
    model: str = "claude-opus-4-8",
) -> dict[str, Any]:
    """Return a draft distillation for `candidate`.

    With `use_llm=False` (default) this returns a manual-curation placeholder and
    makes no network call. With `use_llm=True` it consults a cache, then the
    Anthropic API (abstract only), caching the structured result.
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

    result = _call_llm(candidate, model)

    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _call_llm(candidate: Candidate, model: str) -> dict[str, Any]:
    """Consult the Anthropic API on the abstract only. Lazy import + clear error."""
    try:
        import anthropic  # optional dependency; only needed for --use-llm
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "LLM distillation requires the 'anthropic' package. "
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
    draft: dict[str, Any]
    try:
        draft = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        draft = {"raw": text}
    draft["status"] = "drafted"
    draft["ident"] = candidate.ident
    return draft
