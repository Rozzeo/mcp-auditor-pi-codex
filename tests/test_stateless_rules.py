"""SL-001/002/003 — rules for the stateless protocol revision 2026-07-28.

The shapes below were taken from the installed SDK 2.0.0 source, not from prose:
`CacheHint(ttl_ms=..., scope="public"|"private")` in mcp/server/caching.py, and
`RequestStateBoundary` in mcp/server/request_state.py, whose docstring states the
spec requires servers to treat client-echoed `requestState` as attacker-controlled.
"""

from mcp_auditor.rules import load_signatures, run_rules
from mcp_auditor.types import Tool

SIGS = load_signatures()


def ids(findings):
    return {f.id for f in findings}


def run_tool(body):
    tool = Tool("lookup", "Look something up.", {}, "server.py:1", body=body)
    return ids(run_rules([tool], SIGS, has_auth_signal=True))


def run_files(files):
    return ids(run_rules([], SIGS, has_auth_signal=True, files=files))


# --- SL-001: authorization from client-supplied per-request metadata ---------


def test_sl001_flags_role_read_from_meta():
    assert "SL-001" in run_tool(
        'if _meta.get("client", {}).get("role") == "admin":\n    return secrets()\n'
    )


def test_sl001_flags_permission_read_from_ctx_meta():
    assert "SL-001" in run_tool(
        'perms = ctx.meta["permissions"]\nif "write" in perms:\n    save()\n'
    )


def test_sl001_flags_privilege_read_from_request_state():
    assert "SL-001" in run_tool('if requestState["scope"] == "admin":\n    drop_all()\n')


def test_sl001_quiet_when_metadata_is_only_logged():
    """Reading per-request metadata is normal; deciding privilege on it is not."""
    assert "SL-001" not in run_tool('log.info("request", extra={"trace": ctx.meta})\n')


def test_sl001_quiet_for_token_derived_identity():
    """The documented correct path must never be flagged."""
    assert "SL-001" not in run_tool(
        'principal = authenticated_principal(ctx)\nif principal is None:\n    raise Denied()\n'
    )


# --- SL-002: cross-context cache scope --------------------------------------


def test_sl002_flags_public_cache_scope_on_cache_hint():
    assert "SL-002" in run_files(
        {"app.py": 'Server(cache_hints={"tools/list": CacheHint(ttl_ms=86400000, scope="public")})\n'}
    )


def test_sl002_flags_public_cache_scope_field():
    assert "SL-002" in run_files({"app.py": 'result.cache_scope = "public"\n'})


def test_sl002_flags_wire_form_in_typescript():
    assert "SL-002" in run_files({"app.ts": 'return { tools, ttlMs: 3600000, cacheScope: "public" };\n'})


def test_sl002_quiet_for_private_scope():
    assert "SL-002" not in run_files(
        {"app.py": 'Server(cache_hints={"tools/list": CacheHint(ttl_ms=5000, scope="private")})\n'}
    )


# --- SL-003: multi-round-trip state without an integrity boundary -----------

LOWLEVEL_MRTR = '''
from mcp.server.lowlevel import Server

app = Server("helper")

@app.call_tool()
async def handle(name, args, requestState):
    if requestState.get("stage") == "confirmed":
        return do_it(args)
    return {"resultType": "input_required"}
'''


def test_sl003_flags_lowlevel_mrtr_without_boundary():
    assert "SL-003" in run_files({"server.py": LOWLEVEL_MRTR})


def test_sl003_quiet_when_boundary_is_installed():
    source = LOWLEVEL_MRTR + (
        "\nfrom mcp.server.request_state import RequestStateBoundary\n"
        "app.middleware.append(RequestStateBoundary(security))\n"
    )
    assert "SL-003" not in run_files({"server.py": source})


def test_sl003_quiet_for_high_level_mcpserver():
    """MCPServer appends RequestStateBoundary unconditionally (SDK 2.0.0,
    mcp/server/mcpserver/server.py), so firing on it would be a false positive."""
    source = '''
from mcp.server import MCPServer

app = MCPServer("helper")

@app.tool()
async def handle(name: str, requestState: dict) -> str:
    """Handle."""
    return "input_required"
'''
    assert "SL-003" not in run_files({"server.py": source})


def test_sl003_quiet_without_multi_round_trip_usage():
    assert "SL-003" not in run_files(
        {"server.py": "from mcp.server.lowlevel import Server\napp = Server('helper')\n"}
    )
