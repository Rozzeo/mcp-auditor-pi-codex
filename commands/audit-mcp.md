---
description: Audit an MCP server (local path or GitHub URL) for tool poisoning and over-privilege before trusting it
argument-hint: <path-or-github-url>
---

Audit the MCP server at target: $ARGUMENTS

1. If no target was given, ask the user for a local path or github.com URL of the MCP server to audit.
2. Call the `audit_mcp_server` tool from the mcp-auditor MCP server with that target. Do not run, install, or import the target yourself — the auditor is static-only by design.
3. Present the result:
   - Lead with the verdict: the 0-100 score and whether the target was recognized as an MCP server at all (`is_mcp_server`).
   - List each finding with its rule id, severity, affected tool, location, and recommendation, ordered most severe first.
   - For any finding that carries a `threat_id`, call `explain_threat` with that id and add one sentence of background with its cited sources.
4. Close with a plain-language recommendation: safe to connect, connect with caution (name the specific risks), or do not connect.
