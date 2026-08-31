"""The intel review queue — persisted candidates awaiting human curation.

The queue is a JSON-Lines file (one Candidate per line). New candidates are
deduplicated against (a) identifiers already cited in the Threat Atlas and
(b) identifiers already in the queue, so re-running `intel fetch` never piles up
the same paper/CVE twice. Curation is a human step: read the queue, decide what
becomes an Atlas entry + signature rule, then encode it by hand.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..atlas import load_atlas_safe
from .model import Candidate


def known_identifiers(atlas: dict | None) -> set[str]:
    """Every arXiv id and CVE id already cited in the Atlas."""
    ids: set[str] = set()
    if not atlas:
        return ids
    refs = {r.get("key"): r for r in atlas.get("references", []) if isinstance(r, dict)}
    for ref in refs.values():
        if ref.get("arxiv"):
            ids.add(ref["arxiv"])
    for threat in atlas.get("threats", []):
        for src in threat.get("sources", []) if isinstance(threat, dict) else []:
            if not isinstance(src, dict):
                continue
            if src.get("id"):
                ids.add(src["id"])          # inline CVE/advisory id
            if src.get("arxiv"):
                ids.add(src["arxiv"])
            if src.get("ref"):
                ref = refs.get(src["ref"], {})
                if ref.get("arxiv"):
                    ids.add(ref["arxiv"])
    return ids


def dedup(
    candidates: list[Candidate],
    atlas: dict | None = None,
    existing_ids: set[str] | None = None,
) -> list[Candidate]:
    """Drop candidates already cited in the Atlas or already seen."""
    known = known_identifiers(atlas)
    seen = set(existing_ids or set())
    out: list[Candidate] = []
    for cand in candidates:
        if cand.ident and (cand.ident in known or cand.ident in seen):
            continue
        if cand.ident:
            seen.add(cand.ident)
        out.append(cand)
    return out


def load_queue(path: str | Path) -> list[Candidate]:
    p = Path(path)
    if not p.exists():
        return []
    items: list[Candidate] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            items.append(Candidate.from_dict(json.loads(line)))
    return items


def save_queue(path: str | Path, candidates: list[Candidate]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        for cand in candidates:
            fh.write(json.dumps(cand.to_dict()) + "\n")


def add_candidates(
    path: str | Path,
    candidates: list[Candidate],
    atlas: dict | None = None,
) -> list[Candidate]:
    """Merge new, deduped candidates into the queue file. Returns the newly added."""
    if atlas is None:
        atlas = load_atlas_safe()
    existing = load_queue(path)
    existing_ids = {c.ident for c in existing if c.ident}
    new = dedup(candidates, atlas=atlas, existing_ids=existing_ids)
    if new:
        save_queue(path, existing + new)
    return new
