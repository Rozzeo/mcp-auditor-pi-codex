"""End-to-end acceptance tests mapped 1:1 to the MVP acceptance criteria (§11).

These run the real `audit()` core and the real CLI against on-disk fixtures.
"""

import ast
import json
import subprocess
import sys
from pathlib import Path

from mcp_auditor.core import audit

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = str(FIXTURES / "clean-server")
POISONED = str(FIXTURES / "poisoned-server")
NON_MCP = str(FIXTURES / "non-mcp-repo")


def _cli(args):
    return subprocess.run(
        [sys.executable, "-m", "mcp_auditor.cli", *args],
        capture_output=True,
        text=True,
    )


def test_ac1_clean_server_high_score_zero_critical():
    report = audit(CLEAN)
    assert report.is_mcp_server is True
    assert report.score >= 80
    assert report.summary()["critical"] == 0


def test_ac2_poisoned_fixture_flagged_critical_tp001():
    report = audit(POISONED)
    assert any(f.id == "TP-001" for f in report.findings)
    assert report.summary()["critical"] >= 1


def test_ac3_json_emits_valid_report_and_nothing_else_on_stdout():
    proc = _cli([POISONED, "--json"])
    assert proc.returncode == 0
    parsed = json.loads(proc.stdout)  # whole stdout is valid JSON
    assert parsed["is_mcp_server"] is True
    assert "findings" in parsed and "summary" in parsed


def test_ac4_non_mcp_repo_graceful_no_score():
    report = audit(NON_MCP)
    assert report.is_mcp_server is False
    assert report.score is None
    assert report.message


def test_ac5_no_target_code_is_ever_executed():
    """Guard against regressions: the codebase must never import/exec/eval/run
    target content. We assert the source contains no such calls on target data."""
    src_dir = Path(__file__).parent.parent / "src" / "mcp_auditor"
    forbidden = {"eval", "exec", "compile"}
    forbidden_import = {"importlib", "runpy"}
    for py in src_dir.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden, f"{py.name} calls {node.func.id}()"
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in forbidden_import, f"{py.name} imports {alias.name}"


def test_ac6_fail_on_high_exits_nonzero_when_high_plus_present():
    proc = _cli([POISONED, "--json", "--fail-on", "high"])
    assert proc.returncode != 0
    clean = _cli([CLEAN, "--json", "--fail-on", "high"])
    assert clean.returncode == 0


def test_ac7_scoring_is_deterministic():
    a = audit(POISONED)
    b = audit(POISONED)
    assert a.score == b.score
    assert [f.id for f in a.findings] == [f.id for f in b.findings]
