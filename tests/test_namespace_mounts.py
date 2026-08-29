"""A tool's registered name is not always the name a client calls.

FastMCP servers compose: a parent mounts sub-servers under a namespace, and the
wire name becomes `<namespace>_<function>`. `mcp-atlassian` does exactly this,
and reporting the unprefixed name means the inventory, the capability matrix and
every finding refer to tools no client can invoke.

This was found by a holdout, and only because a second labeller used the names
the project's README documents rather than the names in its decorators.
"""

from mcp_auditor.extractor import extract


MOUNTED = '''
from mcp.server.fastmcp import FastMCP

jira_mcp = FastMCP("jira")
confluence_mcp = FastMCP("confluence")
main_mcp = FastMCP("atlassian")


@jira_mcp.tool()
def get_issue(issue_key: str) -> str:
    """Get a Jira issue."""
    return issue_key


@confluence_mcp.tool()
def get_page(page_id: str) -> str:
    """Get a Confluence page."""
    return page_id


main_mcp.mount(jira_mcp, namespace="jira")
main_mcp.mount(confluence_mcp, namespace="confluence")
'''

UNMOUNTED = '''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("plain")


@mcp.tool()
def get_issue(issue_key: str) -> str:
    """Get an issue."""
    return issue_key
'''


def _names(files):
    return sorted(tool.name for tool in extract(files).tools)


def test_a_mounted_toolset_reports_the_namespaced_name():
    assert _names({"server.py": MOUNTED}) == ["confluence_get_page", "jira_get_issue"]


def test_an_unmounted_server_is_unchanged():
    assert _names({"server.py": UNMOUNTED}) == ["get_issue"]


def test_the_mount_may_live_in_another_module():
    """mcp-atlassian declares its tools in jira.py and mounts them in main.py."""
    files = {
        "servers/jira.py": '''
from mcp.server.fastmcp import FastMCP

jira_mcp = FastMCP("jira")


@jira_mcp.tool()
def get_issue(issue_key: str) -> str:
    """Get a Jira issue."""
    return issue_key
''',
        "servers/main.py": '''
from mcp.server.fastmcp import FastMCP
from .jira import jira_mcp

main_mcp = FastMCP("atlassian")
main_mcp.mount(jira_mcp, namespace="jira")
''',
    }

    assert _names(files) == ["jira_get_issue"]


def test_the_positional_prefix_form_is_recognized():
    """FastMCP has spelled this `mount(prefix, server)` as well."""
    source = MOUNTED.replace(
        'main_mcp.mount(jira_mcp, namespace="jira")', 'main_mcp.mount("jira", jira_mcp)'
    ).replace(
        'main_mcp.mount(confluence_mcp, namespace="confluence")',
        'main_mcp.mount("confluence", confluence_mcp)',
    )

    assert _names({"server.py": source}) == ["confluence_get_page", "jira_get_issue"]


def test_a_mount_without_a_namespace_does_not_rename():
    source = MOUNTED.replace('main_mcp.mount(jira_mcp, namespace="jira")', "main_mcp.mount(jira_mcp)")
    names = _names({"server.py": source})

    assert "get_issue" in names
    assert "confluence_get_page" in names


def test_an_already_prefixed_name_is_not_prefixed_twice():
    source = MOUNTED.replace("def get_issue(", "def jira_get_issue(")
    names = _names({"server.py": source})

    assert "jira_get_issue" in names
    assert "jira_jira_get_issue" not in names
