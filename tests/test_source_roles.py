"""P1: classify what a source file *is* before judging it.

A dummy token in a test file is not a leaked credential, and a server that
binds 0.0.0.0 in a fixture is not a deployed server. Rules that describe the
deployed artifact have to know which files make it up.
"""

import pytest

from mcp_auditor.rules import load_signatures, run_rules
from mcp_auditor.source_roles import DEPLOYED_ROLES, classify, role_counts


@pytest.mark.parametrize("path,role", [
    ("src/server.ts", "production"),
    ("index.js", "production"),
    ("__tests__/tools.test.ts", "test"),
    ("tests/test_server.py", "test"),
    ("src/server_test.py", "test"),
    ("app/handlers.spec.js", "test"),
    ("tests/fixtures/poisoned.json", "fixture"),
    ("testdata/sample.json", "fixture"),
    ("examples/quickstart.py", "example"),
    ("demo/run.js", "example"),
    ("src/schema.generated.ts", "generated"),
    ("proto/messages_pb2.py", "generated"),
    ("docs/usage.md", "documentation"),
    ("README.md", "documentation"),
])
def test_paths_are_classified_by_role(path, role):
    assert classify(path) == role


def test_a_test_path_wins_over_a_documentation_extension():
    """`tests/README.md` documents the tests; it is not the deployed artifact."""
    assert classify("tests/README.md") == "test"


def test_only_test_and_fixture_sources_are_excluded_from_deployed_rules():
    """Examples and docs stay in scope on purpose.

    A real credential committed to a README leaks exactly as hard as one in
    src/, and an example script is code a user is invited to run.
    """
    assert "production" in DEPLOYED_ROLES
    assert "example" in DEPLOYED_ROLES
    assert "documentation" in DEPLOYED_ROLES
    assert "test" not in DEPLOYED_ROLES
    assert "fixture" not in DEPLOYED_ROLES


def test_role_counts_report_the_whole_audited_surface():
    counts = role_counts({
        "index.ts": "",
        "src/lib.ts": "",
        "__tests__/a.test.ts": "",
        "README.md": "",
    })

    assert counts == {"production": 2, "test": 1, "documentation": 1}


CREDENTIAL = 'const token = "sk-live-ab12cd34ef56gh78ij90kl12mn34op56";\n'


def _findings(files):
    return run_rules([], load_signatures(None), has_auth_signal=True, files=files)


def test_a_credential_in_production_source_is_reported():
    ids = {f.id for f in _findings({"src/server.ts": CREDENTIAL})}

    assert "CR-001" in ids


def test_the_same_credential_in_a_test_file_is_not():
    ids = {f.id for f in _findings({"__tests__/tools.test.ts": CREDENTIAL})}

    assert "CR-001" not in ids


def test_a_credential_in_a_readme_is_still_reported():
    ids = {f.id for f in _findings({"README.md": CREDENTIAL})}

    assert "CR-001" in ids


def test_repository_level_rules_still_see_every_file():
    """RP-001 judges the manifest, not a runtime behavior, so test-tree
    manifests must not silently drop out of its view."""
    files = {"tests/fixtures/app/package.json": '{"dependencies": {"left-pad": "^1.0.0"}}'}
    ids = {f.id for f in _findings(files)}

    assert "RP-001" in ids


TOOL_SOURCE = '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
server.registerTool("read_report", { description: "Read it." }, async () => ({}));
'''


def test_tools_declared_in_a_test_file_are_not_part_of_the_surface():
    """A registration inside a test exercises the SDK; it is not a deployed
    tool, and counting it inflates the approval matrix with a phantom."""
    from mcp_auditor.extractor import extract

    production = extract({"src/index.ts": TOOL_SOURCE})
    from_tests = extract({"__tests__/index.test.ts": TOOL_SOURCE})
    from_fixtures = extract({"tests/fixtures/index.ts": TOOL_SOURCE})

    assert [tool.name for tool in production.tools] == ["read_report"]
    assert from_tests.tools == []
    assert from_fixtures.tools == []
