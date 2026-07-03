"""Living threat-intelligence pipeline (roadmap Phase 5 — the anti-rot system).

Machine fetches candidate threats from research/CVE feeds; a human curates which
become Atlas entries + signature rules. Nothing here auto-edits the knowledge
base — the pipeline only proposes; a person approves.

Submodules:
  model       Candidate dataclass shared by all sources.
  arxiv       Fetch + parse recent MCP-security papers (arXiv Atom feed).
  advisories  Fetch CVEs touching MCP SDK packages (OSV.dev).
  queue       Persist a review queue, deduped against the Atlas + prior queue.
  distill     OPTIONAL, off-by-default LLM drafting from abstracts only.
"""

from .model import Candidate

__all__ = ["Candidate"]
