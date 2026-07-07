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


def test_stale_cache_loses_to_newer_bundled(tmp_path, monkeypatch):
    # A cache older than the bundled definitions must be ignored.
    (tmp_path / "signatures.yaml").write_text("version: 1\nrules: {}\n")
    monkeypatch.setattr(updater, "cache_dir", lambda: tmp_path)
    assert updater.effective_signatures_path(None) is None


def test_fresher_cache_wins_over_bundled(tmp_path, monkeypatch):
    (tmp_path / "signatures.yaml").write_text("version: 999\nrules: {}\n")
    monkeypatch.setattr(updater, "cache_dir", lambda: tmp_path)
    assert updater.effective_signatures_path(None) == str(tmp_path / "signatures.yaml")


def test_update_rejects_malformed_download(tmp_path):
    import pytest

    files = {
        "signatures.yaml": "not: a\nvalid: definition\n",  # no `rules` key
        "threats.yaml": "version: 7\nthreats: []\n",
    }
    with pytest.raises(ValueError):
        updater.update(base_url="http://example/defs", session=_Session(files), dest=tmp_path)
    # Nothing was written — the working set is untouched.
    assert not (tmp_path / "signatures.yaml").exists()


def test_cache_dir_is_under_home():
    # The cache lives in the per-user home, not the repo.
    assert ".mcp-audit" in str(updater.cache_dir())
