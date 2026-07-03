"""Integrity tests for the Threat Atlas and its mapping to the signature set."""

from mcp_auditor.atlas import load_atlas, resolve_sources, threats_by_id
from mcp_auditor.rules import load_signatures

ATLAS = load_atlas()
SIGS = load_signatures()

VALID_PHASES = {"creation", "deployment", "operation", "maintenance"}
VALID_DETECT = {"yes", "partial", "no"}
VALID_SEV = {"critical", "high", "medium", "low", "info"}


def test_atlas_and_signatures_versions_match():
    # Atlas and signatures are versioned in lockstep (antivirus-style).
    assert ATLAS["version"] == SIGS["version"]


def test_every_threat_has_required_fields():
    for t in ATLAS["threats"]:
        for key in ("id", "name", "attacker", "phase_group", "severity", "summary", "static_detectability"):
            assert key in t, f"{t.get('id')} missing {key}"
        assert t["phase_group"] in VALID_PHASES
        assert t["static_detectability"] in VALID_DETECT
        assert t["severity"] in VALID_SEV


def test_threat_ids_are_unique():
    ids = [t["id"] for t in ATLAS["threats"]]
    assert len(ids) == len(set(ids))


def test_every_rule_maps_to_a_known_threat():
    by_id = threats_by_id(ATLAS)
    for rid, rule in SIGS["rules"].items():
        threat = rule.get("threat")
        assert threat, f"rule {rid} has no threat backref"
        assert threat in by_id, f"rule {rid} -> unknown threat {threat}"


def test_threat_rule_backrefs_point_to_real_rules():
    rule_ids = set(SIGS["rules"].keys())
    for t in ATLAS["threats"]:
        for r in t.get("rules", []):
            assert r in rule_ids, f"threat {t['id']} -> unknown rule {r}"


def test_runtime_only_threats_are_honest_gaps():
    # A threat marked 'no' (not statically detectable) must claim no rule.
    for t in ATLAS["threats"]:
        if t["static_detectability"] == "no":
            assert not t.get("rules"), f"{t['id']} is runtime-only but lists rules"


def test_resolve_sources_expands_paper_and_cve():
    src = resolve_sources(ATLAS, "MCP-T04")
    assert any(s.get("section") == "5.1.4" for s in src)
    assert any(s.get("id") == "CVE-2025-54135" for s in src)
    # ref-expansion pulls the arXiv id from the references table.
    assert any(s.get("arxiv") == "2503.23278" for s in src)


def test_resolve_sources_empty_for_unknown_threat():
    assert resolve_sources(ATLAS, None) == []
    assert resolve_sources(ATLAS, "MCP-T99") == []
