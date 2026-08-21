import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from mcp_auditor.cli import main
from mcp_auditor.wordpress_runtime import (
    WordPressRuntimeError,
    _parse_json_stream,
    capture_wordpress_runtime,
)


def _ready_project(tmp_path: Path) -> Path:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "node_modules" / ".bin").mkdir(parents=True)
    (tmp_path / "node_modules" / ".bin" / "wp-env").write_text("", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "autoload.php").write_text("<?php", encoding="utf-8")
    return tmp_path


def _rpc(response_id, result):
    return json.dumps({"jsonrpc": "2.0", "id": response_id, "result": result})


def test_parse_json_stream_ignores_wp_env_noise():
    text = "Starting container...\n" + _rpc(1, {"tools": []}) + "\nDone\n"
    assert _parse_json_stream(text)[0]["id"] == 1


def test_runtime_capture_discovers_and_describes_real_abilities(tmp_path, monkeypatch):
    project = _ready_project(tmp_path)
    commands = []

    base = "\n".join([
        _rpc(1, {"tools": [{"name": "mcp-adapter-discover-abilities"}]}),
        _rpc(2, {"resources": [{"uri": "wordpress://site"}]}),
        _rpc(3, {"prompts": []}),
        _rpc(4, {"structuredContent": {"abilities": [{
            "name": "my-plugin/get-posts", "description": "Get posts."
        }]}}),
    ])
    details = _rpc(100, {"structuredContent": {
        "name": "my-plugin/get-posts",
        "description": "Get posts.",
        "input_schema": {"type": "object", "properties": {"limit": {"type": "integer"}}},
        "meta": {"annotations": {"readonly": True, "destructive": False}},
    }})

    def fake_run(args, *, cwd, input_text=None, timeout=120):
        commands.append(args)
        if args[:2] == ["npm", "run"] and "serve" in args:
            return SimpleNamespace(returncode=0, stdout=details if '"id":100' in input_text else base, stderr="")
        return SimpleNamespace(returncode=0, stdout="29.6.1", stderr="")

    monkeypatch.setattr("mcp_auditor.wordpress_runtime._run", fake_run)
    capture = capture_wordpress_runtime(project)

    assert capture["capture_kind"] == "wordpress-runtime"
    assert capture["evidence_type"] == "runtime"
    assert capture["tools"] == [{
        "name": "my-plugin/get-posts",
        "description": "Get posts.",
        "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}},
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    }]
    assert any(command[-1] == "start" for command in commands)
    assert any(command[-1] == "stop" for command in commands)


def test_runtime_requires_preinstalled_wp_env_and_composer_dependencies(tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    with pytest.raises(WordPressRuntimeError, match="npm install"):
        capture_wordpress_runtime(tmp_path)


def test_cli_writes_runtime_capture_and_labels_evidence(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    out = tmp_path / "capture.json"
    monkeypatch.setattr(
        "mcp_auditor.wordpress_runtime.capture_wordpress_runtime",
        lambda *args, **kwargs: {
            "capture_kind": "wordpress-runtime",
            "tools": [{"name": "my-plugin/get-posts", "description": "Get posts."}],
        },
    )

    result = CliRunner().invoke(main, ["wordpress-runtime", str(project), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text(encoding="utf-8"))["capture_kind"] == "wordpress-runtime"
    assert "Evidence: runtime" in result.output
