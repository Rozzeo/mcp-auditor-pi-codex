"""P2 sink-table gaps the validation corpus named.

Both were found by labelling the reference filesystem server tool by tool: an
API called directly in the handler that the table did not map to the capability
a reviewer would assign it.
"""

from mcp_auditor.capabilities import infer_all
from mcp_auditor.types import Tool


def _capabilities(body: str, location: str = "index.ts:1") -> set[str]:
    tool = Tool(name="t", description="", location=location, body=body)
    infer_all([tool])
    return {evidence.capability for evidence in tool.capabilities}


def test_creating_a_directory_is_a_filesystem_write():
    assert "filesystem.write" in _capabilities('await fs.mkdir(validPath, { recursive: true });')


def test_python_directory_creation_is_a_filesystem_write():
    assert "filesystem.write" in _capabilities("os.makedirs(path, exist_ok=True)", "server.py:1")


def test_renaming_writes_the_destination_as_well_as_removing_the_source():
    capabilities = _capabilities("await fs.rename(validSourcePath, validDestPath);")

    assert "filesystem.delete" in capabilities
    assert "filesystem.write" in capabilities


def test_copying_a_file_writes_the_destination():
    assert "filesystem.write" in _capabilities("await fs.copyFile(src, dest);")


def test_a_plain_read_still_claims_no_write():
    capabilities = _capabilities('const data = await fs.readFile(p, "utf-8");')

    assert capabilities == {"filesystem.read"}


def test_a_collection_removal_is_not_a_filesystem_delete():
    """`sessions.remove(id)` deletes a map entry, not a file. Matching a bare
    `remove(` put a destructive capability on tools that never touch disk."""
    assert _capabilities("sessionResources.remove(uri);") == set()


def test_a_list_removal_in_python_is_not_a_filesystem_delete():
    assert _capabilities("items.remove(name)", "server.py:1") == set()


def test_the_qualified_python_delete_is_still_caught():
    assert "filesystem.delete" in _capabilities("os.remove(path)", "server.py:1")
    assert "filesystem.delete" in _capabilities("os.unlink(path)", "server.py:1")


def test_the_node_delete_apis_are_still_caught():
    assert "filesystem.delete" in _capabilities("await fs.rm(p);")
    assert "filesystem.delete" in _capabilities("await fs.unlink(p);")


def test_a_pathlib_unlink_is_still_caught():
    assert "filesystem.delete" in _capabilities("Path(target).unlink()", "server.py:1")
