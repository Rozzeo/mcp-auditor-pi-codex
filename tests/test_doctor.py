"""`mcp-audit doctor` — the install diagnosis.

The command exists because every install failure this project produces looks
identical from the outside ("the command does not work") while having three
unrelated causes. These tests hold it to naming each cause rather than just
reporting a pass/fail.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from mcp_auditor.cli import _all_on_path, _collect_diagnostics, main


def _checks(report: dict) -> dict[str, dict]:
    return {c["check"]: c for c in report["checks"]}


def test_doctor_reports_the_interpreter_and_the_definitions():
    checks = _checks(_collect_diagnostics())

    assert checks["python"]["ok"] is True
    assert checks["threat atlas"]["ok"] is True
    assert checks["signatures"]["ok"] is True
    # A version the report can be traced back to, not just "loaded".
    assert "v" in checks["signatures"]["detail"]


def test_doctor_requires_every_hard_dependency():
    checks = _checks(_collect_diagnostics())

    for dist in ("click", "rich", "PyYAML", "requests"):
        assert checks[f"dep: {dist}"]["ok"] is True, f"{dist} should be present in a dev env"


def test_optional_dependencies_are_neither_pass_nor_fail():
    """A missing optional dep is information, not a problem to be fixed."""
    checks = _checks(_collect_diagnostics())

    for dist in ("mcp", "openpyxl"):
        assert checks[f"dep: {dist}"]["ok"] in (True, None)


def test_json_mode_is_machine_readable_and_carries_the_verdict():
    result = CliRunner().invoke(main, ["doctor", "--json"])

    payload = json.loads(result.output)
    assert payload["ok"] is (result.exit_code == 0)
    assert isinstance(payload["checks"], list) and payload["checks"]


def test_human_mode_names_each_check():
    result = CliRunner().invoke(main, ["doctor"])

    for expected in ("python", "signatures", "threat atlas"):
        assert expected in result.output


def test_all_on_path_finds_every_copy_not_just_the_winner(tmp_path, monkeypatch):
    """The shadowing case is the whole reason this helper exists.

    `shutil.which` returns the winner, which is precisely the fact that hides an
    old install still sitting earlier on PATH.
    """
    first, second = tmp_path / "a", tmp_path / "b"
    for directory in (first, second):
        directory.mkdir()
        (directory / "mcp-audit").write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setenv("PATH", f"{first}{__import__('os').pathsep}{second}")
    found = _all_on_path("mcp-audit")

    assert len(found) == 2
    assert found[0].startswith(str(first))


def test_all_on_path_is_empty_when_nothing_matches(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))

    assert _all_on_path("mcp-audit") == []
