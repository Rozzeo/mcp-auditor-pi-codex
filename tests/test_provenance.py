"""A doc-derived tool list is only worth as much as the check against its page."""

from __future__ import annotations

import json

from mcp_auditor.matrix import ActionRow, apply_provenance, write_csv
from mcp_auditor.provenance import (
    Provenance,
    declared_source,
    is_on_page,
    page_text,
    verify,
)

PAGE = """
<html><head><style>.wpcom-secret-tool {}</style></head><body>
  <h2>wpcom-user-sites</h2>
  <p>List WordPress.com sites.</p>
  <h2>wpcom-mcp-content-authoring</h2>
  <ul><li><code>posts.list</code></li><li><code>posts.create</code></li></ul>
  <p>The facade also supports <em>describe</em>.</p>
  <script>var hidden = "wpcom-script-only-tool";</script>
</body></html>
"""


class _Resp:
    def __init__(self, text: str) -> None:
        self.text = text

    def raise_for_status(self) -> None:
        pass


class _Session:
    def __init__(self, text: str = PAGE) -> None:
        self.text = text
        self.calls: list[str] = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        return _Resp(self.text)


class _DeadSession:
    def get(self, url, **kwargs):
        raise ConnectionError("no route to host")


# --- text reduction --------------------------------------------------------


def test_page_text_drops_script_and_style_bodies():
    text = page_text(PAGE)
    assert "wpcom-user-sites" in text
    assert "wpcom-script-only-tool" not in text
    assert "wpcom-secret-tool" not in text


# --- name matching ---------------------------------------------------------


def test_plain_name_present_and_absent():
    text = page_text(PAGE)
    assert is_on_page("wpcom-user-sites", text)
    assert not is_on_page("wpcom-delete-everything", text)


def test_facade_name_requires_both_halves():
    text = page_text(PAGE)
    assert is_on_page("wpcom-mcp-content-authoring -> posts.list", text)
    # The facade is documented; this operation is not.
    assert not is_on_page("wpcom-mcp-content-authoring -> posts.delete", text)


def test_alternatives_inside_one_segment_are_or():
    text = page_text(PAGE)
    # "list" is generic and proves nothing; "describe" carries the segment.
    assert is_on_page("wpcom-mcp-content-authoring -> action: list / describe", text)


def test_separator_variants_still_match():
    text = page_text("<p>wpcom_user_sites and WPCOM-USER-SITES</p>")
    assert is_on_page("wpcom-user-sites", text)


def test_word_boundaries_prevent_substring_matches():
    text = page_text("<p>drafts.postslisting is unrelated</p>")
    assert not is_on_page("posts.list", text)


def test_name_made_only_of_generic_words_is_never_confirmed():
    """Silence must not read as assent: nothing checkable means unconfirmed."""
    assert not is_on_page("list", page_text("<p>list list list</p>"))
    assert not is_on_page("get / set", page_text("<p>get and set</p>"))


# --- declared source -------------------------------------------------------


def test_declared_source_reads_only_http_urls():
    assert declared_source(json.dumps({"_source": "https://docs.example/tools"})) == \
        "https://docs.example/tools"
    assert declared_source(json.dumps({"_source": "./notes.md"})) == ""
    assert declared_source(json.dumps({"tools": []})) == ""
    assert declared_source("not json at all") == ""


# --- verify ----------------------------------------------------------------


def test_verify_splits_found_from_missing():
    prov = verify(
        ["wpcom-user-sites", "wpcom-delete-everything"],
        "https://docs.example/tools",
        session=_Session(),
    )
    assert prov.status == "checked"
    assert prov.found == {"wpcom-user-sites"}
    assert prov.missing == ["wpcom-delete-everything"]
    assert "1/2 names confirmed" in prov.summary()


def test_unreachable_page_does_not_lose_the_matrix():
    prov = verify(["anything"], "https://docs.example/tools", session=_DeadSession())
    assert prov.status == "unreachable"
    assert prov.found == set()
    assert "could not fetch" in prov.summary()


# --- cells and the matrix column -------------------------------------------


def test_cell_states_are_distinguishable():
    prov = verify(["wpcom-user-sites", "made-up-tool"], "https://docs.example/t",
                  session=_Session())
    assert prov.cell("wpcom-user-sites").startswith("on page · ")
    assert prov.cell("made-up-tool").startswith("NOT ON PAGE · ")
    assert "https://docs.example/t" in prov.cell("made-up-tool")


def test_no_source_means_no_column(tmp_path):
    rows = [ActionRow("c", "posts.list", "Read", "d")]
    apply_provenance(rows, Provenance())
    out = tmp_path / "m.csv"
    write_csv(rows, out)
    header = out.read_text(encoding="utf-8-sig").splitlines()[0]
    assert "source" not in header


def test_source_column_appears_only_when_verified(tmp_path):
    rows = [
        ActionRow("c", "wpcom-user-sites", "Read", "d"),
        ActionRow("c", "made-up-tool", "Read", "d"),
    ]
    prov = verify([r.action for r in rows], "https://docs.example/t", session=_Session())
    apply_provenance(rows, prov)

    out = tmp_path / "m.csv"
    write_csv(rows, out)
    lines = out.read_text(encoding="utf-8-sig").splitlines()
    assert lines[0].endswith("source")
    assert "NOT ON PAGE" in [line for line in lines if "made-up-tool" in line][0]
    assert "on page" in [line for line in lines if "wpcom-user-sites" in line][0]


def test_skipped_verification_still_records_the_source():
    prov = Provenance(source="https://docs.example/t", status="skipped")
    assert "--no-verify" in prov.cell("anything")
    assert prov.active


# --- through the CLI -------------------------------------------------------


def _no_network(monkeypatch):
    """Any fetch during these tests is a bug, so make one fail loudly."""
    def boom(*args, **kwargs):
        raise AssertionError("the matrix command must not fetch here")

    monkeypatch.setattr("mcp_auditor.provenance.fetch_page", boom)


def _run(tmp_path, payload, *extra):
    from click.testing import CliRunner

    from mcp_auditor.cli import main

    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps(payload), encoding="utf-8")
    out = tmp_path / "m.csv"
    result = CliRunner().invoke(
        main, ["matrix", str(tools), "--format", "csv", "--out", str(out), *extra]
    )
    return result, out


def test_cli_no_verify_skips_the_fetch_but_keeps_the_source(tmp_path, monkeypatch):
    _no_network(monkeypatch)
    payload = {"_source": "https://docs.example/tools",
               "tools": [{"name": "posts.list", "description": "List posts."}]}
    result, out = _run(tmp_path, payload, "--no-verify")

    assert result.exit_code == 0, result.output
    lines = out.read_text(encoding="utf-8-sig").splitlines()
    assert lines[0].endswith("source")
    assert "unchecked (--no-verify)" in lines[1]
    assert "https://docs.example/tools" in lines[1]


def test_cli_without_declared_source_never_reaches_the_network(tmp_path, monkeypatch):
    _no_network(monkeypatch)
    payload = {"tools": [{"name": "posts.list", "description": "List posts."}]}
    result, out = _run(tmp_path, payload)

    assert result.exit_code == 0, result.output
    assert "source" not in out.read_text(encoding="utf-8-sig").splitlines()[0]


def test_cli_marks_and_reports_names_absent_from_the_page(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_auditor.provenance.fetch_page",
                        lambda url, session=None: page_text(PAGE))
    payload = {"_source": "https://docs.example/tools", "tools": [
        {"name": "wpcom-user-sites", "description": "List sites."},
        {"name": "wpcom-delete-everything", "description": "Invented."},
    ]}
    result, out = _run(tmp_path, payload)

    assert result.exit_code == 0, result.output
    assert "1 operation(s) not found" in result.output
    assert "wpcom-delete-everything" in result.output
    body = out.read_text(encoding="utf-8-sig")
    assert "NOT ON PAGE" in [line for line in body.splitlines() if "delete-everything" in line][0]
