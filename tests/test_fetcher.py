import base64

import pytest

from mcp_auditor.fetcher import parse_repo, fetch_github


def test_parse_repo_from_various_urls():
    assert parse_repo("https://github.com/owner/repo") == ("owner", "repo")
    assert parse_repo("https://github.com/owner/repo/") == ("owner", "repo")
    assert parse_repo("https://github.com/owner/repo.git") == ("owner", "repo")
    assert parse_repo("https://github.com/owner/repo/tree/main/sub") == ("owner", "repo")


def test_parse_repo_rejects_non_repo_url():
    with pytest.raises(ValueError):
        parse_repo("https://github.com/owner")


class FakeResponse:
    def __init__(self, *, json_data=None, status=200):
        self._json = json_data
        self.status_code = status

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Minimal stand-in for requests.Session that serves canned API responses."""

    def __init__(self, routes):
        self.routes = routes
        self.requested = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.requested.append(url)
        # Match the most specific (longest) route key, mirroring real routing.
        for key in sorted(self.routes, key=len, reverse=True):
            if key in url:
                return self.routes[key]
        return FakeResponse(status=404)


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def _make_session():
    server_py = 'from mcp.server.fastmcp import FastMCP\n@mcp.tool()\ndef get_x(a: str) -> str:\n    """x"""\n    return a\n'
    routes = {
        "/repos/owner/repo/git/trees/": FakeResponse(json_data={
            "tree": [
                {"path": "server.py", "type": "blob", "size": len(server_py), "sha": "sha1"},
                {"path": "README.md", "type": "blob", "size": 10, "sha": "sha2"},
                {"path": "node_modules/x.js", "type": "blob", "size": 5, "sha": "sha3"},
            ]
        }),
        "/repos/owner/repo": FakeResponse(json_data={"default_branch": "main"}),
        "/repos/owner/repo/git/blobs/sha1": FakeResponse(json_data={"content": _b64(server_py), "encoding": "base64"}),
    }
    return FakeSession(routes), server_py


def _make_tarball(files):
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name=f"owner-repo-abc123/{path}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeTarResponse:
    def __init__(self, content):
        self.content = content
        self.status_code = 200

    def raise_for_status(self):
        pass


def test_fetch_github_uses_single_tarball_request():
    server_py = "from mcp.server.fastmcp import FastMCP\n"
    tar = _make_tarball({
        "server.py": server_py,
        "README.md": "docs",
        "node_modules/x.js": "skip me",
    })
    session = FakeSession({"/repos/owner/repo/tarball": FakeTarResponse(tar)})
    files = fetch_github("https://github.com/owner/repo", session=session)
    assert files == {"server.py": server_py}
    # The whole repo came down in exactly one HTTP request.
    assert session.requested == ["https://api.github.com/repos/owner/repo/tarball"]


def test_fetch_github_falls_back_to_blobs_when_tarball_unavailable():
    session, server_py = _make_session()
    files = fetch_github("https://github.com/owner/repo", session=session)
    assert files["server.py"] == server_py


def test_fetch_github_downloads_relevant_files_only():
    session, server_py = _make_session()
    files = fetch_github("https://github.com/owner/repo", session=session)
    assert "server.py" in files
    assert files["server.py"] == server_py
    # README.md and node_modules content are not code-relevant / are skipped.
    assert "node_modules/x.js" not in files


def test_fetch_github_never_requests_blob_for_skipped_dirs():
    session, _ = _make_session()
    fetch_github("https://github.com/owner/repo", session=session)
    assert not any("sha3" in u for u in session.requested)
