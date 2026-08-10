"""Connector approval matrix — classification and export.

The accuracy expectations below are measured against two hand-labelled review
matrices (WordPress.com MCP, 83 operations; Google/Microsoft 365 MCP, 30). The
labels those reviewers used are the ground truth; the classifier is not allowed
to regress against them.
"""

import csv

import pytest

from mcp_auditor.matrix import (
    DELETE, DISCOVERY, READ, SEARCH, SEND, WRITE,
    Overrides, build_matrix, classify, expand_facade, summarize, write_csv,
)
from mcp_auditor.types import Tool


def t(name):
    return classify(name, "")[0]


# --- classification ---------------------------------------------------------


@pytest.mark.parametrize("name,expected", [
    ("posts.list", READ), ("posts.get", READ), ("posts.create", WRITE),
    ("posts.update", WRITE), ("posts.delete", DELETE),
    ("content-search", SEARCH), ("newsletter.get_settings", READ),
    ("manage-site.set-visibility", WRITE), ("outlook_send_mail", SEND),
    ("outlook_batch_delete_messages", DELETE), ("outlook_untrash_thread", WRITE),
    ("sharepoint_upload_file", WRITE), ("read_resource", READ),
])
def test_classifies_common_operation_names(name, expected):
    assert t(name) == expected


def test_noun_that_looks_like_a_verb_is_not_treated_as_one():
    """`sharepoint_*` must not read as the verb `share`, and `set-mail-service`
    must not read as `mail` — prefix matching got both wrong."""
    assert t("sharepoint_search") == SEARCH
    assert t("sharepoint_folder_search") == SEARCH
    assert t("wpcom-domain-set-mail-service") == WRITE
    assert t("outlook_email_search") == SEARCH


def test_verb_is_found_mid_string_in_hyphenated_vendor_names():
    assert t("wpcom-domain-update-dns-records") == WRITE
    assert t("wpcom-domain-restore-default-dns-records") == WRITE
    assert t("wpcom-domain-purchase") == WRITE


def test_facade_catalog_operation_is_discovery_but_data_list_is_read():
    assert t("wpcom-mcp-site -> list") == DISCOVERY
    assert t("wpcom-mcp-site -> describe") == DISCOVERY
    assert t("wpcom-mcp-content-authoring -> posts.list") == READ


def test_declared_destructive_annotation_wins_over_the_name():
    assert classify("archive_thing", "", {"destructiveHint": True})[0] == DELETE


def test_capabilities_are_used_when_the_name_carries_no_verb():
    from mcp_auditor.types import CapabilityEvidence
    caps = [CapabilityEvidence(capability="filesystem.delete", evidence="os.remove(p)")]
    assert classify("thing_handler", "", {}, caps)[0] == DELETE


def test_unclassifiable_name_defaults_to_read_and_says_so():
    label, reason = classify("wpcom-user-sites", "")
    assert label == READ
    assert "verify manually" in reason


def test_overrides_supply_connector_specific_labels():
    ov = Overrides(exact={"outlook_set_vacation": "Mailbox settings"})
    assert classify("outlook_set_vacation", "", overrides=ov)[0] == "Mailbox settings"


def test_override_patterns_match_by_regex():
    ov = Overrides(patterns=[(__import__("re").compile(r"_event$"), "Scheduling")])
    assert classify("outlook_create_event", "", overrides=ov)[0] == "Scheduling"


# --- facade expansion -------------------------------------------------------


def test_facade_tool_expands_one_row_per_enumerated_operation():
    tool = Tool("wpcom-mcp-site", "Site facade.",
                {"type": "object",
                 "properties": {"operation": {"enum": ["posts.list", "posts.delete"]}}},
                "manifest.json")
    assert expand_facade(tool) == ["wpcom-mcp-site -> posts.list",
                                   "wpcom-mcp-site -> posts.delete"]


def test_facade_without_an_enum_is_not_guessed_at():
    """Inventing operations a schema does not list would put unverifiable rows
    in front of a review board."""
    tool = Tool("facade", "d", {"properties": {"operation": {"type": "string"}}}, "m.json")
    assert expand_facade(tool) == []


# --- matrix assembly and export --------------------------------------------


def _tools():
    return [
        Tool("posts.list", "List posts.", {}, "m.json"),
        Tool("posts.delete", "Delete a post.", {}, "m.json"),
        Tool("outlook_send_mail", "Send an email.", {}, "m.json"),
    ]


def test_prefilled_recommendation_follows_the_type():
    rows = {r.action: r for r in build_matrix(_tools(), "Demo")}
    assert rows["posts.list"].recommends == "Approved"
    assert rows["outlook_send_mail"].recommends == "Approved (with confirmation)"
    assert rows["posts.delete"].recommends == "No"
    assert rows["posts.delete"].status == "Pending InfoSec review"


def test_override_label_does_not_downgrade_the_recommendation():
    """A connector-specific label says nothing about risk. `outlook_set_vacation`
    relabelled "Mailbox settings" is still a write and must keep the write
    default, not fall through to plain Approved."""
    ov = Overrides(exact={"outlook_set_vacation": "Mailbox settings"})
    tools = [Tool("outlook_set_vacation", "Set the out-of-office message.", {}, "m.json")]
    (row,) = build_matrix(tools, "Demo", overrides=ov)
    assert row.type == "Mailbox settings"
    assert row.recommends == "Approved (with confirmation)"


def test_no_prefill_leaves_the_human_columns_empty():
    rows = build_matrix(_tools(), "Demo", prefill=False)
    assert all(r.recommends == "" and r.status == "" for r in rows)
    assert all(r.comments == "" for r in rows)


def test_summary_counts_by_type():
    assert summarize(build_matrix(_tools(), "Demo")) == {READ: 1, DELETE: 1, SEND: 1}


def test_csv_export_has_the_expected_header_and_rows(tmp_path):
    out = tmp_path / "m.csv"
    write_csv(build_matrix(_tools(), "Demo"), out)
    with open(out, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["connector", "action", "type", "description",
                       "AI team recomends", "Status - Approved by InfoSec", "Comments"]
    assert len(rows) == 4
    assert rows[1][0] == "Demo"


def test_platform_column_appears_only_when_requested(tmp_path):
    out = tmp_path / "p.csv"
    rows = build_matrix(_tools(), "Demo", platform="Claude, Base44")
    write_csv(rows, out, platform=True)
    with open(out, encoding="utf-8-sig", newline="") as fh:
        header, first = list(csv.reader(fh))[:2]
    assert header[-1] == "platform"
    assert first[-1] == "Claude, Base44"


def test_xlsx_export_is_readable(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    from mcp_auditor.matrix import write_xlsx
    out = tmp_path / "m.xlsx"
    write_xlsx(build_matrix(_tools(), "Demo"), out)
    ws = openpyxl.load_workbook(out).active
    assert [c.value for c in ws[1]][:3] == ["connector", "action", "type"]
    assert ws.max_row == 4


# --- regression against the hand-labelled matrices --------------------------

# (action, reviewer label) pairs sampled across both source matrices, mapped to
# the core vocabulary. Connector-specific labels (Scheduling, Mailbox settings,
# Write (destructive)) are excluded — those are the overrides file's job.
GROUND_TRUTH = [
    ("wpcom-mcp-site -> list", DISCOVERY), ("categories.get", READ),
    ("comments.list", READ), ("media.create", WRITE), ("tags.create", WRITE),
    ("settings.update", WRITE), ("categories.delete", DELETE),
    ("media.delete", DELETE), ("content-search", SEARCH),
    ("account-protection.activate", WRITE), ("monitor.status", READ),
    ("domains.set_primary", WRITE), ("outlook_calendar_search", SEARCH),
    ("chat_message_search", SEARCH), ("outlook_forward_mail", SEND),
    ("outlook_send_draft", SEND), ("outlook_create_reply_all_draft", WRITE),
    ("outlook_delete_label", DELETE), ("sharepoint_move_item", WRITE),
    ("sharepoint_delete_item", DELETE), ("outlook_modify_thread_labels", WRITE),
    ("outlook_trash_thread", DELETE),
]


@pytest.mark.parametrize("action,expected", GROUND_TRUTH)
def test_matches_reviewer_labels(action, expected):
    assert t(action) == expected
