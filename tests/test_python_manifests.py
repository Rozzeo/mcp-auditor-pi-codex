"""RP-001 lists pyproject.toml as a manifest, but the loader never read one.

The validation corpus surfaced this: three Python servers with equally unpinned
dependency ranges and no lockfile in scope went unreported, because .toml was
not among the extensions the loader collects.
"""

from mcp_auditor.loader import load_local
from mcp_auditor.rules import load_signatures, run_rules


PYPROJECT = '''
[project]
name = "mcp-server-git"
dependencies = [
    "click>=8.1.7",
    "gitpython>=3.1.50",
]
'''

PINNED = '''
[project]
name = "mcp-server-git"
dependencies = [
    "click==8.1.7",
]
'''


def _ids(files):
    return {f.id for f in run_rules([], load_signatures(None), has_auth_signal=True, files=files)}


def test_a_pyproject_is_loaded_from_disk(tmp_path):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")

    assert "pyproject.toml" in load_local(str(tmp_path))


def test_unpinned_python_ranges_with_no_lockfile_are_reported():
    assert "RP-001" in _ids({"pyproject.toml": PYPROJECT})


def test_pinned_python_dependencies_are_not_reported():
    assert "RP-001" not in _ids({"pyproject.toml": PINNED})


def test_a_lockfile_next_to_the_pyproject_clears_it():
    assert "RP-001" not in _ids({"pyproject.toml": PYPROJECT, "uv.lock": "version = 1"})


def test_a_lockfile_is_loaded_from_disk(tmp_path):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    files = load_local(str(tmp_path))

    assert "uv.lock" in files
    assert "RP-001" not in _ids(files)
