from mcp_auditor.scorer import score_findings, SEVERITY_WEIGHTS
from mcp_auditor.types import Finding


def mk(severity):
    return Finding("X", "meta", severity, None, "f", "m", "e", "r")


def test_clean_findings_score_100():
    assert score_findings([]) == 100


def test_documented_weights():
    assert SEVERITY_WEIGHTS == {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 0}


def test_single_critical_subtracts_40():
    assert score_findings([mk("critical")]) == 60


def test_mixed_severities_sum_weights():
    findings = [mk("critical"), mk("high"), mk("medium"), mk("low"), mk("info")]
    # 100 - 40 - 20 - 10 - 5 - 0 = 25
    assert score_findings(findings) == 25


def test_score_floors_at_zero():
    findings = [mk("critical")] * 5  # -200
    assert score_findings(findings) == 0


def test_info_only_keeps_score_100():
    assert score_findings([mk("info"), mk("info")]) == 100


def test_score_is_deterministic():
    findings = [mk("high"), mk("critical"), mk("low")]
    assert score_findings(findings) == score_findings(findings) == 35
