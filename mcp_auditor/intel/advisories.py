"""CVE/advisory intel source — fetch vulnerabilities touching MCP SDK packages.

Uses OSV.dev (free, public, JSON). Parsing is separated from fetching so it can
be unit-tested against a saved payload with no network.
"""

from __future__ import annotations

from .model import Candidate

OSV_API = "https://api.osv.dev/v1/query"
_TIMEOUT = 20

# MCP SDK / common server packages to watch.
MCP_PACKAGES = [
    ("PyPI", "mcp"),
    ("PyPI", "fastmcp"),
    ("npm", "@modelcontextprotocol/sdk"),
]


def _collapse(text: str) -> str:
    return " ".join((text or "").split())


def parse_osv(payload: dict, package: str = "") -> list[Candidate]:
    """Parse an OSV.dev query response into Candidates (no network)."""
    out: list[Candidate] = []
    for vuln in payload.get("vulns", []) if isinstance(payload, dict) else []:
        if not isinstance(vuln, dict):
            continue
        vid = vuln.get("id", "")
        title = vuln.get("summary") or vid
        out.append(
            Candidate(
                source="osv",
                ident=vid,
                title=_collapse(title),
                summary=_collapse(vuln.get("details", "")),
                url=f"https://osv.dev/vulnerability/{vid}" if vid else "",
                published=vuln.get("published", ""),
                matched=[package] if package else [],
                venue="OSV/CVE",
                # A confirmed vulnerability, not a paper — always curation-worthy.
                tier="advisory",
            )
        )
    return out


def query_osv(ecosystem: str, name: str, session=None) -> list[Candidate]:
    if session is None:
        import requests  # lazy

        session = requests.Session()
    resp = session.post(
        OSV_API,
        json={"package": {"ecosystem": ecosystem, "name": name}},
        headers={"User-Agent": "mcp-auditor"},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return parse_osv(resp.json(), package=name)


def fetch(session=None) -> list[Candidate]:
    """Fetch advisories for all watched MCP packages (best-effort per package)."""
    out: list[Candidate] = []
    for ecosystem, name in MCP_PACKAGES:
        try:
            out.extend(query_osv(ecosystem, name, session))
        except Exception:
            # One failing package must not sink the whole fetch.
            continue
    return out
