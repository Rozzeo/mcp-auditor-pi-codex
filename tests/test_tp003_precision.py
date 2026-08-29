"""TP-003 flagged half of a real Jira server.

The pattern `[A-Z][A-Z0-9_]{3,}(_KEY|_TOKEN|...)` is written for SCREAMING_SNAKE
constants like `AWS_SECRET_KEY`. Compiled case-insensitively, it also matches
`issue_key`, `project_key` and `space_key` — the ordinary domain vocabulary of
an issue tracker. On the holdout it produced 48 false positives and not one true
one, which is most of the noise a reviewer would have had to clear by hand.
"""

import pytest

from mcp_auditor.rules import load_signatures, run_rules
from mcp_auditor.types import Tool


def _fires(description: str) -> bool:
    tool = Tool(name="t", description=description, location="server.py:1")
    findings = run_rules([tool], load_signatures(None), has_auth_signal=True, files={})
    return any(f.id == "TP-003" for f in findings)


@pytest.mark.parametrize("description", [
    "Get a Jira issue by issue_key.",
    "List issues for a project_key.",
    "Fetch a Confluence page in space_key.",
    "Continue a listing with page_token.",
    "Link an issue using inward_issue_key.",
])
def test_domain_identifiers_are_not_secret_references(description):
    assert not _fires(description)


@pytest.mark.parametrize("description", [
    "Reads AWS_SECRET_KEY from the environment.",
    "Requires GITHUB_TOKEN to be set.",
    "Uses the STRIPE_API_KEY constant.",
])
def test_screaming_snake_secrets_are_still_caught(description):
    assert _fires(description)


@pytest.mark.parametrize("description", [
    "Send your api key with every request.",
    "Provide the API-KEY header.",
    "Reads process.env for configuration.",
    "Loads credentials from ~/.ssh.",
])
def test_the_other_secret_signals_are_untouched(description):
    assert _fires(description)
