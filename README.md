# mcp-audit — MCP Server Auditor

Static security auditor for [Model Context Protocol](https://modelcontextprotocol.io)
servers. It **reads** an MCP server's tool definitions (it never runs them),
applies a small set of explainable rules to detect **tool poisoning** and
**over-privileged tools**, and prints a **0–100 security score** plus findings —
as human-readable text or JSON for CI.

> Safety first: the auditor never executes, imports, installs, or evals the
> target. Target files are read as text only. This is deliberate — a malicious
> MCP server is exactly the thing you point this tool at.

## Why

In 2026 the MCP ecosystem's defining new risk is **tool poisoning**: instructions
hidden in the metadata an agent reads at boot — tool descriptions and JSON Schema
fields — rather than in user input. Combined with over-privileged tools and
unauthenticated exposure, a single poisoned tool description can redirect an
agent into exfiltrating secrets. `mcp-audit` catches the common shapes of this
statically, before you connect the server to an agent.

## Install

```bash
pip install mcp-auditor      # provides the `mcp-audit` command
```

From source:

```bash
git clone <repo> && cd mcp-auditor
pip install -e .
```

## Usage

```bash
mcp-audit <github-url | path> [--json] [--fail-on <severity>]
```

Examples:

```bash
mcp-audit ./my-server                 # audit a local directory
mcp-audit ./server.py                 # audit a single file
mcp-audit https://github.com/owner/repo
mcp-audit ./my-server --json          # machine-readable AuditReport on stdout
mcp-audit ./my-server --fail-on high  # exit non-zero if any high+ finding exists (CI gate)
```

- **Default (human):** colored terminal output — score, per-severity counts, and
  each finding with its tool, location, message, and recommendation.
- **`--json`:** prints the full `AuditReport` JSON to stdout and nothing else
  (all progress/logging goes to stderr), so it pipes cleanly into other tools.
- **`--fail-on <severity>`:** exits non-zero if any finding at or above that
  severity exists. Severities: `critical`, `high`, `medium`, `low`, `info`.

For GitHub URLs, set `GITHUB_TOKEN` to raise the API rate limit (optional).

## MCP plugin — the tool that audits the tools

The auditor is itself available over the Model Context Protocol, so an agent
can vet an MCP server *before* connecting to it. Same pure `audit()` core,
static-only guarantee unchanged.

```bash
pip install "mcp-auditor[mcp]"
mcp-audit-server                  # stdio MCP server
```

Tools exposed:

| Tool | Purpose |
|------|---------|
| `audit_mcp_server` | Audit a local path or GitHub URL; returns the full `AuditReport` |
| `list_rules` | Active signature set: rule ids, severities, messages |
| `list_threats` | Summary of every threat class in the MCP Threat Atlas |
| `explain_threat` | Full atlas record for one threat id, with cited sources |

**Claude Code:** this repo is also a Claude Code plugin
([.claude-plugin/plugin.json](.claude-plugin/plugin.json)). Installing it
registers the MCP server plus an `/audit-mcp <path-or-url>` command that runs
an audit and explains the findings. For ad-hoc use without the plugin:

```bash
claude mcp add mcp-auditor -- python3 -m mcp_auditor.mcp_server
```

Dogfood note: `audit_mcp_server` pointed at its own server module scores
100/100 (one info-level ME-001, expected for a stdio server).

## False positives: confidence + suppressions + agent triage

Pattern rules can misfire (a README that *quotes* an attack phrase is not an
attack). Three layers keep that honest without touching the deterministic core:

1. **Confidence per finding.** Every rule declares `confidence` in
   `signatures.yaml` and each finding carries it: structural checks (hidden
   characters, hardcoded credentials, typosquats) are `high`; wording/heuristic
   rules are honest `medium`/`low`. Use it to rank review priority.
2. **Suppression file** — reviewed false positives, with justification:

   ```yaml
   # mcp-audit-suppressions.yaml
   suppress:
     - rule: TP-001
       tool: read_file            # omit to match any tool
       reason: "docstring quotes an attack example; not agent-directed"
   ```

   ```bash
   mcp-audit ./my-server --suppress mcp-audit-suppressions.yaml
   ```

   `reason` is mandatory. Suppressed findings stay visible in the report
   (flagged `suppressed`) but stop affecting the score, summary, and
   `--fail-on`. Security property: the file is only ever taken from the
   auditor's side — a `.mcp-audit.yaml` *inside the audited target* is
   deliberately ignored, so a malicious server cannot vouch for itself.
3. **Agent triage skill.** The Claude Code plugin ships a
   [`mcp-audit-triage`](skills/mcp-audit-triage/SKILL.md) skill: the agent
   re-reads each medium/low-confidence finding in its source context, judges
   true vs false positive, and drafts the suppression file for human approval —
   the roadmap's "LLM second opinion", implemented for free by the host agent.

## What it detects

| ID | Severity | Category | Detects |
|----|----------|----------|---------|
| TP-001 | critical | tool poisoning | Imperative / instruction-like phrasing aimed at the agent in tool metadata |
| TP-002 | high | tool poisoning | Hidden / non-printing characters (zero-width, bidi overrides, control chars) |
| TP-003 | high | tool poisoning | References to secrets, env vars, system prompts, or other tools' internals |
| TP-004 | critical | tool poisoning | Tool name that doesn't match its described behavior (disguised capability) |
| OP-001 | high | over-privilege | Capability broader than the name implies (read-named tool that writes/sends/deletes) |
| OP-002 | medium | over-privilege | Schema accepting unconstrained dangerous input (raw path / command / URL) |
| ME-001 | info | meta | Tools defined but no authentication signal detected |

## Scoring formula

The score is **deterministic** and starts at **100**. Each finding subtracts a
fixed weight by severity, and the result is floored at 0:

```
score = max(0, 100 − Σ weight(severity_of_finding))

weight: critical = 40, high = 20, medium = 10, low = 5, info = 0
```

Higher is safer. Because info-level findings subtract 0, an otherwise clean
server with only ME-001 still scores 100. The formula lives in
[`scorer.py`](src/mcp_auditor/scorer.py) and is covered by tests.

## The `AuditReport` contract

`audit(target)` returns one stable, JSON-serializable shape (the only place
detection logic lives — CLI and JSON are thin wrappers):

```jsonc
{
  "target": "https://github.com/owner/repo",
  "is_mcp_server": true,
  "tools_analyzed": 7,
  "score": 42,                     // null when is_mcp_server is false
  "findings": [
    {
      "id": "TP-001",
      "category": "tool_poisoning",
      "severity": "critical",
      "tool_name": "send_email",
      "location": "server.py:42",
      "message": "Instruction-like / imperative phrasing aimed at the agent ...",
      "evidence": "ignore all previous instructions ...",  // redacted if it contains a secret
      "recommendation": "Remove instruction-like text from tool descriptions."
    }
  ],
  "summary": { "critical": 1, "high": 2, "medium": 0, "low": 1, "info": 3 },
  "generated_at": "2026-06-26T00:00:00Z"
}
```

When the target is not an MCP server, `is_mcp_server` is `false`, `score` is
`null`, and a human-readable `message` explains why — no misleading score.

## How to add a signature

Detection patterns live in
[`src/mcp_auditor/signatures.yaml`](src/mcp_auditor/signatures.yaml) so you can
extend rules **without touching code**. Each rule has a `category`, `severity`,
`message`, `recommendation`, and rule-specific pattern lists.

To extend a pattern-based rule (TP-001, TP-003), add a case-insensitive Python
regex to its `patterns:` list. For example, to flag a new tool-poisoning phrase:

```yaml
rules:
  TP-001:
    patterns:
      - "ignore (all )?(previous|prior|above)"
      - "override your guidelines"      # <- new pattern
```

- **TP-004 / OP-001** compare name hints against action patterns — add to
  `benign_name_hints` / `read_name_hints` or the action pattern lists.
- **OP-002** uses `dangerous_param_names` and `constraint_keys`.
- Bump the top-level `version:` whenever you change the set, so audits stay
  reproducible against a known signature version.

## Supported MCP server shapes

- **Python:** MCP SDK usage (`from mcp...`, `FastMCP`, `@server.tool` /
  `@mcp.tool` decorators). Parsed with the `ast` module.
- **TypeScript / JavaScript:** `@modelcontextprotocol/sdk` imports and
  `server.tool(...)` / `registerTool(...)` registrations.
- **Manifest:** any JSON listing tools with `name` + `description` + `inputSchema`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
