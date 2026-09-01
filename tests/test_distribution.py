"""Public installation and release contracts.

These tests protect the path a new user follows outside this checkout.  The
import package remains ``mcp_auditor`` and the command remains ``mcp-audit``;
the distribution name must be unique because ``mcp-auditor`` on PyPI belongs to
an unrelated project.
"""

from __future__ import annotations

import re
import runpy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _project_version() -> str:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert match
    return match.group(1)


def test_distribution_name_does_not_collide_with_unrelated_pypi_project():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'name = "mcp-auditor-static"' in pyproject
    assert 'mcp-audit = "mcp_auditor.cli:main"' in pyproject


def test_python_module_entrypoint_uses_the_same_click_cli(monkeypatch):
    calls: list[bool] = []
    monkeypatch.setattr("mcp_auditor.cli.main", lambda: calls.append(True))

    runpy.run_module("mcp_auditor", run_name="__main__")

    assert calls == [True]


def test_versions_stay_in_sync():
    import mcp_auditor

    plugin = (ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")

    assert mcp_auditor.__version__ == _project_version()
    assert f'"version": "{_project_version()}"' in plugin


def _readme_commands() -> str:
    """Only the fenced blocks — the lines a reader will actually paste."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    blocks = readme.split("```")[1::2]
    return "\n".join(blocks)


def test_readme_installs_this_github_project_and_has_windows_path_fallback():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    # The PyPI name `mcp-auditor` belongs to a different author and a different
    # product, so no command in the README may install it. Prose *must* be free
    # to name it, though -- warning the reader off it is the whole point of the
    # naming section, and a plain substring check forbade the warning along with
    # the mistake.
    assert "pip install mcp-auditor\n" not in _readme_commands()
    assert "pip install mcp-auditor " not in _readme_commands()
    assert "github.com/Rozzeo/mcp-auditor-pi-codex" in readme
    assert "py -m mcp_auditor --help" in readme
    assert "The term 'mcp-audit' is not recognized" in readme


def test_ci_and_release_workflows_are_versioned():
    workflows = ROOT / ".github" / "workflows"

    assert (workflows / "ci.yml").is_file()
    assert (workflows / "release.yml").is_file()
