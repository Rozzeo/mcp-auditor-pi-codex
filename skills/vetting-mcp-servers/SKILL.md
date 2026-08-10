---
name: vetting-mcp-servers
description: Use when deciding whether an MCP server or agent skill is safe to install, approve, or keep — a colleague asks to enable one, a mcp.json or claude_desktop_config.json change needs review, an approved server ships a new version, or someone asks what an agent is already wired to call.
---

# Vetting MCP servers

## Overview

Decide whether to trust a server **without running it**. `mcp-audit` reads the target as text and never executes it; the judgment layer on top works the same way.

A server is not just a dependency. Its tool descriptions are read by the model as instructions at selection time, and its handlers run with the agent's privileges. Agent skills (`SKILL.md`) are the same trust surface and audit the same way.

Not for: writing a server (ordinary development), or deciding whether one already-surfaced finding is real (that is triage).

## Quick reference

| Question | Command |
|---|---|
| What is already installed? | `mcp-audit installed --json` |
| Is this server safe? | `mcp-audit <path-or-github-url> --json` |
| Did it change since approval? | `mcp-audit diff <old-report.json> <new-target>` |
| May *this person* run it? | `mcp-audit <target> --policy dept.yaml --employee alice` |
| Need a per-operation review table? | `mcp-audit matrix <target> --connector "<name>" --out matrix.xlsx` |
| What does a rule/threat mean? | `list_rules`, `explain_threat` (plugin MCP tools) |
| Gate a pipeline | `--fail-on high` (exit 1 at or above that severity) |

## The vetting recipe

A verdict has these parts, in this order:

1. **Inventory** — `mcp-audit installed`, before judging anything new. Risk is a property of the *set*: if the agent already has a filesystem-read tool, adding a network-send tool completes an exfiltration chain neither server shows alone.
2. **Audit** — `mcp-audit <target> --json`.
3. **Rank by confidence, then severity.**
4. **Apply policy** when one exists. `--policy` with `--employee` / `--agent` answers "may this identity hold these privileges" — a different question from "is this code dangerous".
5. **State a verdict** — allow / allow-with-suppressions / deny, naming the finding ids that drove it and the capabilities the server gains.

When the decision goes to a review board rather than stopping with you, the
verdict is a table, not a paragraph: `mcp-audit matrix` emits one row per
operation with its access type, so each one is approved or refused
individually instead of the connector being waved through as a whole. A hosted
connector has no source to read — save its `tools/list` response and pass that
file as the target.

## Severity is impact; confidence is how sure the pattern is

Every finding carries both, and sorting by severity alone wastes review time.

- **High confidence** — structural facts: hidden characters, duplicate names, a declared `readOnlyHint` contradicted by a write in the body. Treat as true unless you can show otherwise.
- **Medium confidence** — heuristics over prose or code shape. Real false positives live here; read `evidence` and `location` before believing or dismissing.

Confidence ranks review order. It is never a verdict on its own.

## `is_mcp_server: false` means unscanned, not clean

No score is computed and no rules run. Report it as "could not analyze", never as "no issues found". Usual causes: an aliased or vendored SDK, or a language the extractor does not parse.

## Suppressions carry a reason

Record a reviewed false positive auditor-side, never inside the target:

```yaml
suppress:
  - rule: TP-001
    tool: get_weather
    reason: "docstring quotes an attack example; not agent-directed"
```

Pass with `--suppress`. The finding stays in the report flagged `suppressed: true` and drops out of the score and `--fail-on`. `reason` is required — a suppression nobody can justify is itself a smell.

## Never run the target to find out what it does

Installing it, starting it, or calling `tools/list` against it hands control to the thing under review — the exact moment a poisoned description reaches the model or an install hook fires.

**Red flags — stop:**

- "I'll just start it and see what tools it registers"
- "Installing locally is safer than reading it"
- "The audit found nothing, let me confirm by running it"

| Rationalization | Reality |
|---|---|
| "I need the real tool list" | A launch spec that fetches its package at run time means the code you would run is not the code you read. Read the source or manifest. |
| "It's sandboxed" | The agent's credentials and the model's attention are inside the sandbox with it. |
| "It's a known vendor" | Rug-pull (MCP-T05) is the attack where a trusted server changes *after* approval. |

## Approve a version, not a name

Save the `--json` report as the baseline and re-run `mcp-audit diff` on updates. A launch spec pinned to a floating tag re-downloads and executes new code on every start, so the approval never covers what actually runs — flag it and ask for a pinned version.
