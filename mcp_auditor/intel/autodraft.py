"""Unattended drafting AND merging of Atlas entries from high-quality intel.

This is the automation layer on top of `distill()`. Candidates that pass the
included/excluded criteria below are merged straight into the live
`threats.yaml` — no human copy/paste step. The included/excluded gate below
*is* the review: tier + dedup + keyword match + "the LLM actually found
something statically detectable" stand in for a person reading the abstract.

INCLUDED — a candidate is auto-merged only if ALL of these hold:
  * tier is "advisory" (a confirmed CVE/OSV vulnerability) or "top"/"ranked"
    (a peer-reviewed security/ML venue — see intel.model.VENUE_PATTERNS).
  * it is not already cited anywhere in the Atlas (dedup by ident).
  * it matched at least one MCP-security keyword (defence in depth; every
    source already filters on this before queuing).
  * the LLM distillation (title + abstract ONLY, never target code) returns a
    parseable draft with at least one static_signal or draft_pattern.

EXCLUDED — tagged with a machine-readable reason, never silently dropped:
  * "tier_below_threshold" — tier is "community" (researcher blogs, Hacker
    News) or "preprint" (arXiv with no recorded venue): fresh but unverified,
    kept out of the automatic Atlas — these are the ones worth a human glance
    (`mcp-audit intel review`), everything else is genuinely too noisy to trust
    unattended (anyone can post a blog; nobody peer-reviewed it).
  * "already_in_atlas" — duplicate of a source already cited.
  * "no_keyword_match" — safety net; should not normally trigger.
  * "llm_disabled" — `use_llm=False`, so nothing can be drafted.
  * "nothing_statically_detectable" — the LLM explicitly said so.
  * "malformed_llm_output" — the LLM reply did not parse as the requested JSON.

One thing this automates on purpose and one it deliberately does NOT:
  * Automated: adding the *documentation* — id, name, summary, static signals,
    citation — to the Atlas. That data is never executed; a wrong entry is a
    wrong sentence, not a security hole.
  * NOT automated: writing the *executable* detector. `rules.py::run_rules`
    dispatches each rule id to a hand-written Python matcher function; there is
    no generic "run this regex" path. So every merged entry keeps `rules: []`
    (the Atlas's existing convention for "known gap") until a person writes
    and reviews that matcher. Auto-generating and auto-running LLM-authored
    Python as part of the scanner would be a code-execution risk, not a
    documentation one — that step stays manual by design, not by oversight.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from ..atlas import DEFAULT_ATLAS_PATH, load_atlas_safe
from .distill import distill
from .model import Candidate
from .queue import known_identifiers

# advisory=0, top=1, ranked=2 pass at the default floor; community=3, preprint=4 never do.
_TIER_ORDER = {"advisory": 0, "top": 1, "ranked": 2, "community": 3, "preprint": 4, "": 4}
DEFAULT_MIN_TIER = "ranked"

_ID_SAFE_RE = re.compile(r"[^A-Za-z0-9]+")


def _atlas_id(prefix: str, ident: str) -> str:
    """A stable, YAML-safe Atlas id from a source identifier (arXiv id, CVE id,
    or a blog/HN URL — the latter needs scheme/slash characters stripped)."""
    return f"{prefix}-{_ID_SAFE_RE.sub('-', ident).strip('-').upper()}"[:64]


@dataclass
class DraftResult:
    included: list[dict[str, Any]] = field(default_factory=list)
    excluded: list[dict[str, Any]] = field(default_factory=list)


def _tier_passes(tier: str, min_tier: str) -> bool:
    return _TIER_ORDER.get(tier, 4) <= _TIER_ORDER.get(min_tier, 2)


def _exclusion_reason(cand: Candidate, known: set[str], min_tier: str, use_llm: bool) -> str | None:
    if cand.ident and cand.ident in known:
        return "already_in_atlas"
    if not _tier_passes(cand.tier, min_tier):
        return "tier_below_threshold"
    if not cand.matched:
        return "no_keyword_match"
    if not use_llm:
        return "llm_disabled"
    return None


def autodraft(
    candidates: list[Candidate],
    *,
    min_tier: str = DEFAULT_MIN_TIER,
    use_llm: bool = False,
    cache_dir: str | None = None,
    atlas: dict | None = None,
    model: str | None = None,
) -> DraftResult:
    """Gate `candidates` through the included/excluded criteria above, then
    distill the included ones into draft Atlas stanzas. Callers are responsible
    for writing `DraftResult.included` to a staging file (see `write_drafts`) —
    this function never touches the real knowledge base.
    """
    if atlas is None:
        atlas = load_atlas_safe()
    known = known_identifiers(atlas)

    result = DraftResult()
    for cand in candidates:
        reason = _exclusion_reason(cand, known, min_tier, use_llm)
        if reason:
            result.excluded.append({"ident": cand.ident, "title": cand.title, "reason": reason})
            continue

        draft = distill(cand, use_llm=use_llm, cache_dir=cache_dir, model=model)
        if "raw" in draft:
            result.excluded.append(
                {"ident": cand.ident, "title": cand.title, "reason": "malformed_llm_output"}
            )
            continue

        signals = draft.get("static_signals") or []
        patterns = draft.get("draft_patterns") or []
        if not signals and not patterns:
            result.excluded.append(
                {"ident": cand.ident, "title": cand.title, "reason": "nothing_statically_detectable"}
            )
            continue

        result.included.append(
            {
                "id": _atlas_id("AUTO", cand.ident),
                "name": draft.get("threat_name") or cand.title,
                "summary": cand.summary[:500] or draft.get("threat_name") or cand.title,
                "status": "auto-drafted",
                "needs_review": True,
                "lifecycle": draft.get("lifecycle_phase", ""),
                "static_signals": signals,
                "draft_patterns": patterns,
                "source": {
                    "source": cand.source,
                    "ident": cand.ident,
                    "title": cand.title,
                    "url": cand.url,
                    "venue": cand.venue,
                    "tier": cand.tier,
                },
            }
        )
    return result


def build_human_draft(
    cand: Candidate,
    *,
    name: str,
    lifecycle: str = "",
    static_signal: str = "",
) -> dict[str, Any]:
    """Build one entry in the same shape `autodraft().included` produces, but
    from a human's own two-line answer instead of an LLM call — the LLM-free
    path for when `--use-llm` isn't worth the API cost yet. Feed the result
    straight into `merge_into_atlas`. Marked `needs_review: False`: a person
    typed this, there is nothing left to review.
    """
    return {
        "id": _atlas_id("HUMAN", cand.ident),
        "name": name,
        "summary": cand.summary[:500] or name,
        "status": "human-curated",
        "needs_review": False,
        "lifecycle": lifecycle,
        "static_signals": [static_signal] if static_signal else [],
        "draft_patterns": [],
        "source": {
            "source": cand.source,
            "ident": cand.ident,
            "title": cand.title,
            "url": cand.url,
            "venue": cand.venue,
            "tier": cand.tier,
        },
    }


def write_drafts(path: str | Path, drafts: list[dict[str, Any]]) -> None:
    """Write auto-drafted stanzas to a staging YAML file — an audit trail of
    what got merged and why, not a review gate (see `merge_into_atlas`)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        yaml.safe_dump({"drafts": drafts}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


# --- merging straight into the live Atlas -------------------------------------

_VERSION_RE = re.compile(r"^version:\s*(\d+)\s*$", re.MULTILINE)
_RELEASED_RE = re.compile(r'^released:\s*"[^"]*"\s*$', re.MULTILINE)


def _to_atlas_entry(draft: dict[str, Any]) -> dict[str, Any]:
    """Translate an autodraft() result into a threats.yaml-schema entry.

    `rules: []` is deliberate, not an oversight — see the module docstring:
    no executable matcher exists for this id until a human writes one.
    """
    src = draft["source"]
    status = draft.get("status", "auto-drafted")
    note_verb = "curated" if status == "human-curated" else "auto-drafted"
    source_entry: dict[str, Any] = {
        "title": src["title"],
        "url": src["url"],
        "note": f"{note_verb} from {src['source']} ({src['venue'] or src['tier']})",
    }
    return {
        "id": draft["id"],
        "name": draft["name"],
        "aliases": [],
        "attacker": "unclassified",
        "lifecycle": draft.get("lifecycle") or "unclassified",
        "phase_group": "operation",
        "severity": "unclassified",
        "status": status,
        "needs_review": draft.get("needs_review", True),
        "summary": draft.get("summary", draft["name"]),
        "static_detectability": "partial",
        "static_signals": draft.get("static_signals", []),
        "candidate_patterns": draft.get("draft_patterns", []),
        "rules": [],
        "mitigations": [],
        "sources": [source_entry],
    }


def _render_atlas_block(entries: list[dict[str, Any]]) -> str:
    dumped = yaml.safe_dump(entries, sort_keys=False, allow_unicode=True, default_flow_style=False)
    indented = "\n".join(("  " + line if line else line) for line in dumped.splitlines())
    header = "  # --- Added by `mcp-audit intel autodraft` / `intel curate` (see status/needs_review per entry) ---"
    return f"\n{header}\n{indented}\n"


def merge_into_atlas(drafts: list[dict[str, Any]], atlas_path: str | Path | None = None) -> int:
    """Append `drafts` (from `autodraft().included`) directly onto the live
    threats.yaml and bump its version/released date. Editing the raw text
    (instead of a full yaml.safe_load + safe_dump round-trip) is deliberate:
    the file's header comments are hand-written documentation and a round-trip
    would silently discard them.

    Returns the number of entries merged (0 if `drafts` is empty — the file is
    left untouched).
    """
    if not drafts:
        return 0

    path = Path(atlas_path) if atlas_path else DEFAULT_ATLAS_PATH
    text = path.read_text(encoding="utf-8")

    m = _VERSION_RE.search(text)
    if m:
        new_version = int(m.group(1)) + 1
        text = _VERSION_RE.sub(f"version: {new_version}", text, count=1)
    text = _RELEASED_RE.sub(f'released: "{date.today().isoformat()}"', text, count=1)

    entries = [_to_atlas_entry(d) for d in drafts]
    text = text.rstrip("\n") + "\n" + _render_atlas_block(entries)

    path.write_text(text, encoding="utf-8")
    return len(entries)
