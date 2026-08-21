"""Opt-in runtime capture for the official WordPress MCP Adapter.

Unlike the normal auditor this module deliberately executes Docker/wp-env. It
is only reached through the explicit ``wordpress-runtime`` CLI command. The
captured JSON is normalized into the same ``tools`` manifest accepted by the
static audit and matrix commands.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class WordPressRuntimeError(RuntimeError):
    """A prerequisite, wp-env command, or MCP response was invalid."""


def _run(
    args: list[str],
    *,
    cwd: Path,
    input_text: str | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd),
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            check=False,
        )
    except FileNotFoundError as exc:
        raise WordPressRuntimeError(
            f"Required command not found: {args[0]}. Install it and try again."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise WordPressRuntimeError(
            f"Command timed out after {timeout}s: {' '.join(args[:4])}"
        ) from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no diagnostic output").strip()
        if len(detail) > 2000:
            detail = detail[-2000:]
        raise WordPressRuntimeError(
            f"Command failed ({result.returncode}): {' '.join(args[:4])}\n{detail}"
        )
    return result


def _json_rpc(request_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    request: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        request["params"] = params
    return request


def _parse_json_stream(text: str) -> list[dict[str, Any]]:
    """Read JSON objects even when wp-env prints non-JSON status lines around them."""
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    pos = 0
    while pos < len(text):
        start = text.find("{", pos)
        if start == -1:
            break
        try:
            value, end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            pos = start + 1
            continue
        if isinstance(value, dict) and value.get("jsonrpc") == "2.0":
            objects.append(value)
        pos = end
    return objects


def _serve(
    project: Path,
    requests: list[dict[str, Any]],
    *,
    user: str,
    server: str,
) -> list[dict[str, Any]]:
    payload = "\n".join(json.dumps(request, separators=(",", ":")) for request in requests) + "\n"
    command = [
        "npm", "run", "wp-env", "--", "run", "cli", "wp",
        "mcp-adapter", "serve", f"--user={user}", f"--server={server}",
    ]
    result = _run(command, cwd=project, input_text=payload, timeout=180)
    responses = _parse_json_stream(result.stdout)
    if not responses:
        detail = (result.stderr or result.stdout or "empty output").strip()
        raise WordPressRuntimeError(f"wp-env returned no JSON-RPC responses: {detail[-1200:]}")
    errors = [response["error"] for response in responses if "error" in response]
    if errors:
        raise WordPressRuntimeError(f"WordPress MCP returned JSON-RPC error: {errors[0]}")
    return responses


def _by_id(responses: list[dict[str, Any]], request_id: int) -> dict[str, Any]:
    for response in responses:
        if response.get("id") == request_id:
            return response
    raise WordPressRuntimeError(f"WordPress MCP did not return response id {request_id}")


def _tool_payload(response: dict[str, Any]) -> dict[str, Any]:
    result = response.get("result")
    if not isinstance(result, dict):
        return {}
    for key in ("structuredContent", "structured_content", "data"):
        value = result.get(key)
        if isinstance(value, dict):
            return value
    content = result.get("content")
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            value = block.get("text")
            if not isinstance(value, str):
                continue
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return result


def _mcp_annotations(meta: Any) -> dict[str, bool]:
    if not isinstance(meta, dict):
        return {}
    source = meta.get("annotations")
    if not isinstance(source, dict):
        return {}
    mapping = {
        "readonly": "readOnlyHint",
        "readOnlyHint": "readOnlyHint",
        "destructive": "destructiveHint",
        "destructiveHint": "destructiveHint",
        "idempotent": "idempotentHint",
        "idempotentHint": "idempotentHint",
        "open_world": "openWorldHint",
        "openWorldHint": "openWorldHint",
    }
    return {
        target: value
        for source_name, target in mapping.items()
        if isinstance((value := source.get(source_name)), bool)
    }


def _ability_tool(info: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    name = info.get("name") or fallback.get("name")
    description = info.get("description") or fallback.get("description") or ""
    schema = info.get("input_schema") or info.get("inputSchema") or {}
    tool: dict[str, Any] = {
        "name": str(name),
        "description": str(description),
        "inputSchema": schema if isinstance(schema, dict) else {},
    }
    annotations = _mcp_annotations(info.get("meta"))
    if annotations:
        tool["annotations"] = annotations
    return tool


def _ensure_project_ready(project: Path) -> None:
    if not project.is_dir():
        raise WordPressRuntimeError(f"Project directory does not exist: {project}")
    if not (project / "package.json").is_file():
        raise WordPressRuntimeError(
            "The project has no package.json; clone the WordPress MCP Adapter repository first."
        )
    if not (project / "node_modules" / ".bin" / "wp-env").exists():
        raise WordPressRuntimeError("wp-env is not installed. Run `npm install` in the adapter repository.")
    if not (project / "vendor" / "autoload.php").is_file():
        raise WordPressRuntimeError("PHP dependencies are missing. Run `composer install` in the adapter repository.")


def capture_wordpress_runtime(
    project: str | Path,
    *,
    user: str = "admin",
    server: str = "mcp-adapter-default-server",
    start: bool = True,
    keep: bool = False,
) -> dict[str, Any]:
    """Capture the deployed WordPress MCP surface through read-only discovery calls.

    Docker Desktop/Engine must already be running. The function never starts the
    desktop application and never invokes an exposed business ability.
    """
    root = Path(project).resolve()
    _ensure_project_ready(root)
    _run(["docker", "info", "--format", "{{.ServerVersion}}"], cwd=root, timeout=30)

    started = False
    cleanup_warning: str | None = None
    try:
        if start:
            _run(["npm", "run", "wp-env", "--", "start"], cwd=root, timeout=600)
            started = True

        base_requests = [
            _json_rpc(1, "tools/list", {}),
            _json_rpc(2, "resources/list", {}),
            _json_rpc(3, "prompts/list", {}),
            _json_rpc(4, "tools/call", {
                "name": "mcp-adapter-discover-abilities",
                "arguments": {},
            }),
        ]
        base_responses = _serve(root, base_requests, user=user, server=server)
        mcp_tools = _by_id(base_responses, 1).get("result", {}).get("tools", [])
        resources = _by_id(base_responses, 2).get("result", {}).get("resources", [])
        prompts = _by_id(base_responses, 3).get("result", {}).get("prompts", [])
        discovery = _tool_payload(_by_id(base_responses, 4))
        abilities = discovery.get("abilities", []) if isinstance(discovery, dict) else []
        abilities = [item for item in abilities if isinstance(item, dict) and item.get("name")]

        details: dict[str, dict[str, Any]] = {}
        detail_responses: list[dict[str, Any]] = []
        if abilities:
            detail_requests = [
                _json_rpc(100 + index, "tools/call", {
                    "name": "mcp-adapter-get-ability-info",
                    "arguments": {"ability_name": ability["name"]},
                })
                for index, ability in enumerate(abilities)
            ]
            detail_responses = _serve(root, detail_requests, user=user, server=server)
            for index, ability in enumerate(abilities):
                details[str(ability["name"])] = _tool_payload(_by_id(detail_responses, 100 + index))

        normalized = [
            _ability_tool(details.get(str(ability["name"]), {}), ability)
            for ability in abilities
        ]
        if not normalized and isinstance(mcp_tools, list):
            normalized = [tool for tool in mcp_tools if isinstance(tool, dict) and tool.get("name")]

        capture: dict[str, Any] = {
            "capture_kind": "wordpress-runtime",
            "evidence_type": "runtime",
            "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "server": server,
            "user": user,
            "tools": normalized,
            "mcp_tools": mcp_tools if isinstance(mcp_tools, list) else [],
            "resources": resources if isinstance(resources, list) else [],
            "prompts": prompts if isinstance(prompts, list) else [],
            "discovered_abilities": abilities,
            "responses": [*base_responses, *detail_responses],
        }
        return capture
    finally:
        if started and not keep:
            try:
                _run(["npm", "run", "wp-env", "--", "stop"], cwd=root, timeout=180)
            except WordPressRuntimeError as exc:
                cleanup_warning = str(exc)
        # A cleanup failure must never silently look successful. The capture is
        # not yet returned when finally runs, so surface the remaining state.
        if cleanup_warning:
            raise WordPressRuntimeError(
                "Runtime capture finished, but wp-env cleanup failed. " + cleanup_warning
            )
