"""What a source file *is*, decided before any rule judges it (spec P1).

Several rules describe the deployed server: it binds an address, it publishes a
cacheable result, it holds a credential. A test that constructs a server to
assert on it, or a fixture that exists to be scanned, is not that server. Ruling
on those files produces findings a reviewer has to dismiss one by one, which is
the fastest way to make a report unread.

The classification is deliberately conservative in what it removes. Examples and
documentation stay in scope: a credential committed to a README leaks exactly as
hard as one in `src/`, and an example script is code the project invites a user
to run. Only `test` and `fixture` are excluded, and the counts are reported so
the reviewer can see how much of the tree was set aside and why.
"""

from __future__ import annotations

import re

PRODUCTION = "production"
TEST = "test"
FIXTURE = "fixture"
EXAMPLE = "example"
GENERATED = "generated"
DOCUMENTATION = "documentation"

ROLES = (PRODUCTION, TEST, FIXTURE, EXAMPLE, GENERATED, DOCUMENTATION)

# Roles whose files make up the artifact a reviewer is approving.
DEPLOYED_ROLES = frozenset({PRODUCTION, EXAMPLE, GENERATED, DOCUMENTATION})

_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e"}
_FIXTURE_DIRS = {"fixture", "fixtures", "testdata", "__mocks__", "mocks", "snapshots"}
_EXAMPLE_DIRS = {"example", "examples", "sample", "samples", "demo", "demos"}
_GENERATED_DIRS = {"generated", "__generated__", "codegen"}
_DOC_DIRS = {"doc", "docs", "documentation"}

_TEST_FILE = re.compile(
    r"(?:^|[/\\])test_[^/\\]+\.py$"
    r"|_test\.py$"
    r"|[._](?:test|spec)\.[cm]?[jt]sx?$"
    r"|(?:^|[/\\])conftest\.py$",
    re.IGNORECASE,
)
_GENERATED_FILE = re.compile(
    r"\.generated\.[^/\\]+$|_pb2(?:_grpc)?\.py$|\.g\.[cm]?[jt]s$|\.min\.[cm]?js$",
    re.IGNORECASE,
)
_DOC_FILE = re.compile(r"\.mdx?$", re.IGNORECASE)


def classify(path: str) -> str:
    """Return the role of one audited path.

    Order matters: a file under `tests/` is a test whatever its extension, so a
    `tests/README.md` documents the tests rather than the product.
    """
    normalized = path.replace("\\", "/")
    segments = {segment.lower() for segment in normalized.split("/")[:-1]}

    # Fixture is checked first: `tests/fixtures/x.json` is both, and the more
    # specific label is the more useful one to show a reviewer.
    if segments & _FIXTURE_DIRS:
        return FIXTURE
    if segments & _TEST_DIRS or _TEST_FILE.search(normalized):
        return TEST
    if segments & _GENERATED_DIRS or _GENERATED_FILE.search(normalized):
        return GENERATED
    if segments & _EXAMPLE_DIRS:
        return EXAMPLE
    if segments & _DOC_DIRS or _DOC_FILE.search(normalized):
        return DOCUMENTATION
    return PRODUCTION


def deployed_files(files: dict[str, str]) -> dict[str, str]:
    """Narrow a file map to the sources that make up the deployed artifact."""
    return {path: text for path, text in files.items() if classify(path) in DEPLOYED_ROLES}


def role_counts(files: dict[str, str]) -> dict[str, int]:
    """Count files per role, omitting roles with no files."""
    counts: dict[str, int] = {}
    for path in files:
        role = classify(path)
        counts[role] = counts.get(role, 0) + 1
    return counts
