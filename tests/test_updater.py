"""Tests for the definition updater (offline, via a fake session)."""

from mcp_auditor import updater


class _Resp:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


class _Session:
    """A minimal stand-in for requests.Session that serves canned files."""

    def __init__(self, files):
        self.files = files

    def get(self, url, **kwargs):
        name = url.rsplit("/", 1)[-1]
        return _Resp(self.files[name])


def test_update_writes_definitions_to_dest(tmp_path):
    files = {
        "signatures.yaml": "version: 7\nrules: {}\n",
        "threats.yaml": "version: 7\nthreats: []\n",
    }
    result = updater.update(base_url="http://example/defs", session=_Session(files), dest=tmp_path)
    assert (tmp_path / "signatures.yaml").exists()
    assert (tmp_path / "threats.yaml").exists()
    assert result["version"] == 7
    assert result["dest"] == str(tmp_path)


def test_effective_signatures_path_prefers_explicit():
    assert updater.effective_signatures_path("/custom/sig.yaml") == "/custom/sig.yaml"


def test_cache_dir_is_under_home():
    # The cache lives in the per-user home, not the repo.
    assert ".mcp-audit" in str(updater.cache_dir())
