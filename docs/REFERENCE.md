# mcp-audit — MCP Server Auditor

Evidence-backed review engine for [Model Context Protocol](https://modelcontextprotocol.io)
servers and Codex/Claude agent-skill packages. It **reads** definitions,
instructions, scripts, references, and package assets (it never runs them),
applies explainable rules, maps possible sensitive-data flows, and produces a
**0–100 static risk indicator** plus evidence and reviewer questions. The number
is a triage aid, never a universal `SAFE` verdict.

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

Use the tested GitHub installation commands in the
[root README](../README.md#install). The distribution is named
`mcp-auditor-static`; the unqualified `mcp-auditor` name on PyPI belongs to an
unrelated project. On Windows, `py -m mcp_auditor` avoids console-script `PATH`
problems and invokes the same CLI as `mcp-audit`.

## Threat Intel -> Atlas -> Encyclopedia

The knowledge system has three layers. They are deliberately separate so that
fresh links from the internet cannot silently become executable detection
rules:

```text
arXiv + OSV/CVE + researcher RSS + Hacker News
                         |
                         v
              mcp-audit intel fetch
                         |
                         v
       ~/.mcp-audit/intel/queue.jsonl     (candidates only)
                         |
              human review / curation
                         |
                         v
   threats.yaml (Atlas) + signatures.yaml (detectors)
                         |
              mcp-audit intel build-docs
                         |
                         v
            mcp-threat-encyclopedia.html
```

### Where the knowledge comes from

| Source | What it contributes | Trust level |
|---|---|---|
| [arXiv Atom API](https://export.arxiv.org/api/help/api/index.html) | Recent MCP-security papers matching the built-in security query | Preprint unless a reviewed venue is recorded |
| [OSV.dev](https://osv.dev/) | Published advisories/CVEs for `mcp`, `fastmcp`, and `@modelcontextprotocol/sdk` | Advisory |
| Researcher RSS/Atom feeds | Embrace The Red, Simon Willison, Invariant Labs, Trail of Bits, and Snyk Labs | Community signal; requires review |
| [Hacker News Algolia API](https://hn.algolia.com/api) | Very recent MCP-security discussions and research announcements | Community signal; requires review |
| MCP specification and cited research | Stable definitions, expected protocol behavior, and primary citations | Primary reference |

`mcp-audit intel fetch` performs read-only requests and stores deduplicated
candidates in the local queue. A candidate is not a rule and does not affect an
audit until it is reviewed and deliberately merged.

```bash
mcp-audit intel fetch                 # collect candidates from all sources
mcp-audit intel review                # inspect the queue without changing Atlas
mcp-audit intel curate                # interactively approve/reject candidates
mcp-audit intel build-docs \
  --out mcp-threat-encyclopedia.html  # render the human-facing encyclopedia
```

The versioned source of truth is
[`src/mcp_auditor/threats.yaml`](../src/mcp_auditor/threats.yaml). It records each
`MCP-T##` threat, aliases, lifecycle phase, attacker model, severity, static
detectability, mitigations, detecting rule IDs, and citations. Detection logic
lives separately in
[`src/mcp_auditor/signatures.yaml`](../src/mcp_auditor/signatures.yaml). Atlas and
signature versions move in lockstep so an audit can state exactly which
knowledge version produced it.

`mcp-audit update` is the distribution path, not the research pipeline. It
downloads only `threats.yaml` and `signatures.yaml` from the canonical
repository, validates both files, and places them in the per-user cache. It
never downloads or executes code.

## How an audit is built

Give `mcp-audit` an open-source MCP repository, local source tree, single file,
agent skill, or repository of skills. The target is downloaded/read as text and
is never installed, imported, or executed.

```text
path / file / GitHub URL
          |
          v
 safe fetch -> package inventory -> extraction -> rules -> Atlas lessons
          |              |                         |
          |       coverage + data flows            |
          +--------- indicator + evidence ----------+
                                 |
                 terminal / JSON / styled HTML report
```

Examples:

```bash
# Open-source MCP repository -> terminal report + shareable HTML dossier
mcp-audit https://github.com/owner/open-source-mcp \
  --html mcp-audit-report.html

# One agent skill, or a whole skills repository
mcp-audit ./path/to/skill --html skill-audit.html
mcp-audit ./my-skills-repo --html skills-audit.html

# Machine-readable output or a CI gate
mcp-audit ./my-server --json
mcp-audit ./my-server --fail-on high
```

The HTML report contains the score, severity totals, capability observations,
evidence, rule IDs, Atlas threat IDs and citations, and prioritized fixes. It
is a presentation of the same deterministic `AuditReport` returned by the core;
no second analysis path is involved.

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
mcp-audit ./my-server --html report.html   # also write a shareable HTML dashboard
mcp-audit review ./my-server               # the evidence-backed review packet
mcp-audit review ./my-server --baseline prev.json   # ...plus what changed since
mcp-audit playground                  # generate the interactive MCP Security Playground
mcp-audit diff ./server-v1 ./server-v2     # what changed between two versions (rug pulls)
mcp-audit ./my-server --policy examples/department-policy.yaml --agent alice-helper
mcp-audit installed                   # what MCP servers this machine is already wired to
mcp-audit matrix ./my-server --out matrix.xlsx   # per-operation table for InfoSec review
mcp-audit wordpress-runtime ./mcp-adapter         # opt-in real WordPress runtime capture
```

- **Default (human):** colored terminal output — score, per-severity counts, and
  each finding with its tool, location, message, and recommendation.
- **`--json`:** prints the full `AuditReport` JSON to stdout and nothing else
  (all progress/logging goes to stderr), so it pipes cleanly into other tools.
- **`--fail-on <severity>`:** exits non-zero if any finding at or above that
  severity exists. Severities: `critical`, `high`, `medium`, `low`, `info`.

For GitHub URLs, set `GITHUB_TOKEN` to raise the API rate limit (optional).

### Three evidence levels — do not confuse them

No single input can prove everything about an MCP server. Every JSON and human
report therefore carries an explicit `evidence_type`:

| evidence | What it proves | What it cannot prove |
|---|---|---|
| `source` | Potential tools, implementation sinks, credentials, annotations and supply-chain signals visible in code | Which tools a deployed server exposes to a particular identity |
| `declared` | Exact operation names claimed by vendor documentation and verified back against its `_source` page | That the deployed server matches the documentation |
| `runtime` | Tools, resources, prompts and dynamic WordPress abilities actually visible to the selected account | Hidden implementation code and behavior that discovery metadata does not reveal |

A serious review combines the available layers. Closed-source MCP servers can
still be reviewed from documentation (`declared`) and a live endpoint
(`runtime`); they simply cannot receive source-code findings.

## Connector approval matrix — `mcp-audit matrix`

An audit answers *"is this server dangerous?"*. A review board asks something
else: enumerate every operation the connector exposes, say what kind of access
each one is, and approve them **individually**. That is what `matrix` produces —
the spreadsheet security teams were building by hand.

```bash
mcp-audit matrix ./my-server        --connector "My MCP"    --out matrix.xlsx
mcp-audit matrix tools.json         --connector "Google MCP" --out matrix.xlsx
mcp-audit matrix https://github.com/owner/repo --format csv --out matrix.csv
```

### Getting the table — pick your starting point

| You have | Do this |
|---|---|
| A repo in Python, TS/JS, or a WordPress Adapter PHP project | `mcp-audit matrix <path-or-github-url> --out matrix.xlsx` |
| A **running** server | Save its `tools/list` response → `mcp-audit matrix tools.json …` |
| Only a **docs page** | Turn the docs into `tools.json` (below); each name is then checked back against the page |
| Another PHP framework, Go, Rust, Java… | Not statically parseable yet — use the runtime or docs route |

**1 — from a repo.** Works when the tools are declared in code the extractor
reads:

```bash
mcp-audit matrix https://github.com/owner/repo --connector "Their MCP" --out matrix.xlsx
```

If the repo is in a language that is not parsed, the audit says so explicitly
and tells you it was **not analyzed** — it never reports an unscanned target as
clean.

The WordPress extractor recognizes `wp_register_ability(...)` only when the
repository uses the official MCP Adapter or the ability explicitly opts into
MCP exposure. It ignores PHPUnit fixtures and normalizes WordPress names such as
`mcp-adapter/execute-ability` to the observable MCP name
`mcp-adapter-execute-ability`.

For the official adapter this works without Docker:

```bash
mcp-audit matrix https://github.com/wordpress/mcp-adapter \
  --connector "WordPress MCP Adapter (source)" \
  --format csv --out matrix.csv
```

At the reviewed upstream revision this calculates three default façade tools:
`mcp-adapter-discover-abilities`, `mcp-adapter-get-ability-info`, and
`mcp-adapter-execute-ability`. That is source evidence, not a claim about every
ability installed on a particular WordPress site.

**2 — from a running server.** The most reliable source, because it is the tool
list the agent actually sees. Save the `tools/list` JSON-RPC response (or write
it by hand) as:

```json
{"tools": [
  {"name": "posts.list",   "description": "List posts."},
  {"name": "posts.delete", "description": "Move a post to trash."}
]}
```

```bash
mcp-audit matrix tools.json --connector "WordPress.com MCP" --out matrix.xlsx
```

**3 — from a documentation page.** Hosted connectors often have no public source
at all; their tool reference page is the only catalogue. Reading that page is a
model's job, not the CLI's — `mcp-audit` is deterministic and makes no LLM calls,
which is what makes its output reproducible. So ask an agent to do the reading
step and hand the result back to the CLI:

> Read `<docs URL>` and list every tool and operation with its exact name and
> one-line description. Write them to `tools.json` in the shape above, with the
> page URL in `_source`, then run
> `mcp-audit matrix tools.json --connector "<name>" --out matrix.xlsx`.

The `vetting-mcp-servers` skill in `skills/` carries this workflow.

Concrete closed-source example: `examples/gainsight-cs-docs.json` transcribes
the supported capability tables from Gainsight's MCP admin guide while keeping
the guide URL in `_source`:

```bash
mcp-audit matrix examples/gainsight-cs-docs.json \
  --connector "Gainsight CS MCP (declared)" \
  --format csv --out gainsight-matrix.csv
```

The checked example produces 18 vendor-declared operations (11 read, 7 write),
with 18/18 labels confirmed on the source page. Four capabilities that the
guide explicitly marks unsupported are retained in `not_supported` and are not
presented as callable operations. The page does not publish exact `tools/list`
names or JSON Schemas, so this remains `declared` evidence until a live OAuth
session supplies runtime evidence.

#### Every transcribed name is checked against its page

A tool list read out of prose is a model's reading until something confirms it.
So when `tools.json` names where it came from:

```json
{
  "_source": "https://developer.wordpress.com/docs/mcp/tools-reference/",
  "tools": [{"name": "wpcom-user-sites", "description": "List sites."}]
}
```

…`matrix` refetches that page, reduces it to text, and asserts every operation
name actually occurs there. The verdict travels with the sheet in a `source`
column, one cell per row:

```
verified: 83/83 names confirmed on developer.wordpress.com
```

| action | … | source |
|---|---|---|
| `wpcom-user-sites` | … | on page · 2026-08-11 · https://developer.wordpress.com/… |
| `wpcom-delete-site` | … | **NOT ON PAGE** · 2026-08-11 · https://developer.wordpress.com/… |

A name the model invented is not on the vendor's page, so it reaches the review
board labelled instead of sitting there looking exactly like the real rows. The
check is deterministic — no LLM call is involved, and the audited connector is
still never started or contacted; only the vendor's documentation is fetched,
the same class of network access as reading a GitHub repo.

Matching is per name-part, so facade rows work: `content-authoring -> posts.list`
needs **both** halves on the page, which is what catches a real facade with an
invented operation hung off it. Separator spelling (`-`, `_`, `.`) and case are
ignored; a fragment that is a bare generic word (`list`, `get`, `describe`)
never confirms a row on its own.

The column appears only for a transcribed list — a repo or a captured
`tools/list` response is first-hand already. Use `--no-verify` offline; the
source is still recorded, marked unchecked. A page that cannot be fetched
downgrades to `UNCHECKED` rather than losing the matrix.

Note what this does and does not prove: it confirms the transcription matches
the page, not that the page matches the deployed server. A docs page can lag,
and a tool the vendor forgot to document is invisible to both.

**The `audit` and `matrix` commands never start the connector.** Facade tools that hide
many operations behind one MCP tool expand to one row each, but only from a
literal `enum` in the schema — inventing operations a schema does not list would
put unverifiable rows in front of a review board.

### Real WordPress runtime audit — explicit Docker mode

Use this only when you need the effective surface after WordPress, plugins,
filters, authentication and `mcp.public` rules have loaded. It is deliberately a
separate command because it starts code. Docker Desktop/Engine must already be
running; the command never starts Docker Desktop and never installs dependencies
silently.

```bash
git clone https://github.com/wordpress/mcp-adapter
cd mcp-adapter
npm install
composer install

mcp-audit wordpress-runtime . --user admin --out wordpress-runtime.json
mcp-audit matrix wordpress-runtime.json \
  --connector "WordPress MCP Adapter (runtime/admin)" \
  --format csv --out runtime-matrix.csv
```

The command uses the repository's official `wp-env`, captures `tools/list`,
`resources/list`, and `prompts/list`, calls the read-only
`mcp-adapter-discover-abilities` façade, and requests schema metadata through
`mcp-adapter-get-ability-info`. It never calls the discovered business
abilities. By default, an environment started by the command is stopped again;
use `--keep` to leave it running or `--no-start` to inspect an existing wp-env.

The resulting `wordpress-runtime.json` is reusable by both `audit` and `matrix`
and is labelled `evidence_type: runtime`. Because exposure is identity-dependent,
repeat the capture for every role whose permissions you intend to approve.

### The three labels

| type | meaning | default recommendation |
|---|---|---|
| `Read` | observes state and returns it — includes search and catalog/describe calls | Approved |
| `Write` | changes state — includes sending, which leaves the change visible to someone else | Approved (with confirmation) |
| `Delete` | destructive write: the one form that cannot be undone by writing again | No |

Three labels because that is the question actually being answered. Finer
distinctions a given connector cares about — `Scheduling`, `Mailbox settings`,
`Write (destructive)` — come from an overrides file (see
`examples/connector-types.yaml`), so matrices stay comparable between connectors:

```bash
mcp-audit matrix tools.json --types examples/connector-types.yaml --out matrix.xlsx
```

An override label is **cosmetic**. The prefilled recommendation still follows the
core type, so relabelling a write cannot quietly turn it into a plain "Approved".

### Columns

| columns | who owns them |
|---|---|
| connector, action, type, description | **generated** — regenerate, don't hand-edit |
| AI team recomends, InfoSec status | seeded with a default, meant to be overridden |
| Comments | left for the reviewer |
| platform | optional, added by `--platform "Claude, Base44"` |
| source | automatic, only for a list transcribed from a docs page (above) |

`--no-prefill` leaves the two judgment columns empty. `--status` sets the InfoSec
column's constant (default `Pending InfoSec review`).

Output is a single flat `.xlsx` sheet — amber for writes, red for destructive and
for any row whose name is not on its source page — or CSV. **`.xlsx` needs
`openpyxl`**. The exact GitHub command is in the
[installation guide](../README.md#excel-output). CSV has no extra dependency.

### Accuracy

The classifier is measured against hand-labelled review matrices rather than
asserted: **78/83 (94%)** on a WordPress.com MCP matrix and **30/30 (100%)** on a
Google/Microsoft 365 one. The remaining disagreements are the `Write (destructive)`
escalation (an overrides-file judgment) and one row where the spreadsheet labels a
domain *purchase* as a search.

## Department and main/helper privilege policies

An MCP server does not have one universal risk level: the same tool may be
acceptable for a builder and forbidden for a read-only helper. An explicit
auditor-side policy resolves privileges through a narrowing-only hierarchy:

```
department ceiling -> employee role -> employee -> parent/main agent -> helper profile -> agent
```

Every allow layer intersects the previous one and every deny wins. A helper can
never gain a capability unavailable to its employee or parent agent. Policies
are never auto-loaded from the audited repository.

```bash
mcp-audit ./server \
  --policy examples/department-policy.yaml \
  --agent alice-helper
```

The report lists statically observed capabilities (`filesystem.read/write`,
`database.read/write/raw-query/destructive`, `network.outbound`,
`process.execute`, `environment.read`, `secrets.read`), the effective privilege list, policy
violations, and analysis coverage. See
[`PRIVILEGE-POLICY.md`](PRIVILEGE-POLICY.md) for the complete model.

JavaScript/TypeScript extraction recognizes current
`registerTool(name, config, handler)`, legacy `server.tool(...)`, and low-level
`setRequestHandler("tools/list", ...)` definitions. MCP annotations such as
`readOnlyHint` and `destructiveHint` are retained but treated as untrusted hints:
the auditor compares them with capabilities observed in the handler and reports
contradictions.

## Visual reports & playground

Two presentation surfaces over the same pure `audit()` core — made for showing
non-CLI people (reviewers, coworkers installing MCPs) what the auditor found:

- **`--html report.html`** — writes a self-contained HTML dashboard: score
  meter, per-severity tiles, findings-by-category bars, and one card per finding
  with evidence, threat id, citation, and fix. No external assets; attach it to
  a ticket or open from CI artifacts. Suppressed findings stay visible,
  struck-through with their justification.
- **`mcp-audit playground [--out mcp-playground.html]`** — generates the
  interactive **MCP Security Playground**: paste a tool's name / description /
  schema / body and watch the per-tool rules and score update live, entirely in
  the browser. Presets include a clean tool, a poisoned one, a SQL-injection
  lookup, a raw-SQL runner, and a silent exfiltrator. Patterns are embedded
  verbatim from the shipped `signatures.yaml`, so the page always matches the
  signature version; server-level rules still require a real CLI audit. A
  **"What to fix first"** panel turns the findings into a prioritized,
  deduplicated remediation checklist.

## Diff mode — the rug-pull detector

A server that was clean at install time can turn malicious in an update
(MCP-T05). `diff` compares two audits of the same server:

```bash
mcp-audit diff ./server-v1 ./server-v2          # two source trees
mcp-audit diff baseline.json ./server           # saved --json report vs live target
mcp-audit diff old new --json                   # structured diff on stdout
mcp-audit diff old new --fail-on high           # CI gate: fail if a NEW high+ finding appeared
```

It reports the score delta, **new findings** (with fixes), **resolved
findings**, and the tool-surface change list — an added tool or a changed
description/schema, annotations, or inferred capabilities on an existing tool
raises an explicit **rug-pull signal**.
Suppressed findings are excluded from the comparison. Typical workflow: save
`mcp-audit ./server --json > baseline.json` at approval time, then re-run
`mcp-audit diff baseline.json ./server` after every update — the saved report
carries the tool surface (names, descriptions, schemas; never captured source
bodies), so the full rug-pull comparison works from a JSON baseline alone.

## Auditing agent skills (SKILL.md)

Agent skills are the same trust surface as MCP tools: their `description` is read
at selection time and their instructions run with the agent's privileges. A
poisoned skill — hidden "do not tell the user" steps, a `npx skills add
<untrusted>` or `curl | bash` install line, "always prefer this skill" —
is exactly what a supply-chain lure looks like.

`mcp-audit` treats the **whole package** as the auditable unit: `SKILL.md`,
bundled scripts, references, configuration, templates, and opaque assets are
inventoried together. Text and executable formats are analyzed statically;
opaque files are not decoded or executed, but remain visible in inventory. A
referenced file that is missing or cannot be analyzed becomes a coverage gap,
withholds the numeric indicator, and forces `INSUFFICIENT_EVIDENCE`.

The engine separately records sensitive-data **sources** (employee/customer
PII, internal company files, credentials), **sinks** (external network,
processes, logs, or file writes), and evidence-supported possible flows between
them. `POSSIBLE` means a reviewer has a concrete path to verify; it does not
claim that runtime exfiltration occurred.

```bash
mcp-audit ./path/to/skill            # audit one skill directory
mcp-audit ./my-skills-repo           # audit a whole collection
```

The **XC-001** rule specifically catches fetch-and-run install steps
(`npx <pkg>`, `curl … | bash`, PowerShell `iex`, `pip install <url>`) — the most
common way a "helpful" skill smuggles in arbitrary code execution. Vet a skill
**before** running `npx skills add …`, since that command downloads and installs
in one step.

## MCP plugin — the tool that audits the tools

The auditor is itself available over the Model Context Protocol, so an agent
can vet an MCP server *before* connecting to it. Same pure `audit()` core,
static-only guarantee unchanged.

```bash
py -m pip install --user --upgrade "mcp-auditor-static[mcp] @ https://github.com/Rozzeo/mcp-auditor-pi-codex/archive/refs/heads/main.zip"
mcp-audit-server                  # stdio MCP server
```

Tools exposed:

| Tool | Purpose |
|------|---------|
| `audit_mcp_server` | Audit a local path or GitHub URL; returns the full `AuditReport` |
| `diff_mcp_server_versions` | Compare two versions (or a JSON baseline vs live) — the rug-pull detector |
| `list_rules` | Active signature set: rule ids, severities, messages |
| `list_threats` | Summary of every threat class in the MCP Threat Atlas |
| `explain_threat` | Full atlas record for one threat id, with cited sources |

**Claude Code:** this repo is also a Claude Code plugin
([.claude-plugin/plugin.json](../.claude-plugin/plugin.json)). Installing it
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
   [`vetting-mcp-servers`](../skills/vetting-mcp-servers/SKILL.md) skill: the agent
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
| OP-003 | medium | over-privilege | Non-localhost network bind with no authentication signal |
| PM-001 | high | preference manipulation | Self-promoting phrasing that biases the model's tool selection |
| NC-001 | high | name collision | Duplicate tool names / shadowing of a common sensitive tool |
| TS-001 | high | supply chain | Server/tool name typosquatting a well-known MCP name |
| RP-001 | info | supply chain | Unpinned dependencies with no lockfile (rug-pull precondition) |
| CI-001 | critical | command injection | Dangerous execution sink (`os.system`, `eval`, `shell=True`, …) in a tool body |
| XC-001 | critical | command injection | Fetch-and-run / remote code execution (`npx <pkg>`, `curl \| bash`, `iex`) in an instruction or script |
| CR-001 | high | credential exposure | Hardcoded secret literals in source/config |
| AT-001 | critical | over-privilege | Inbound caller token forwarded downstream without scope/audience narrowing (confused deputy / token relay) |
| TC-001 | medium | tool chaining | Local-read + outbound-send capability combination (exfiltration chain) |
| SQ-001 | critical | command injection | SQL built by f-string / concat / `%` / `.format()` / template literal (SQL injection) |
| DB-001 | high | over-privilege | Caller-supplied raw SQL reaching an execute call (arbitrary DB access) |
| DB-002 | high | over-privilege | Destructive/admin SQL capability (`DROP`, `TRUNCATE`, `GRANT`, `ALTER`) |
| DE-001 | critical | data exfiltration | Data sent to a hardcoded external endpoint or known callback host |
| DL-001 | medium | data leakage | Sensitive PII/credential tables and columns (`SELECT * FROM users`, SSN, card numbers) |
| SP-001 | critical | data leakage | Sensitive personal information embedded directly in a skill package |
| SF-001 | high | data exfiltration | Evidence-supported possible flow from sensitive package data to an external network sink |
| CP-001 | high | capability mismatch | `readOnlyHint=true` contradicts a mutating handler capability |
| CP-002 | high | capability mismatch | `destructiveHint=false` contradicts a destructive handler operation |
| CP-003 | medium | capability mismatch | `openWorldHint=false` contradicts outbound network access |
| PV-001 | high | policy violation | Inferred capability exceeds the selected department/employee/agent privilege list |
| ME-001 | info | meta | Tools defined but no authentication signal detected |

The `SQ/DB/DE/DL` block exists for the headline corporate risk: employees
installing MCP servers that talk to internal databases. It answers, statically,
"can this server leak our data?" — injection sinks, arbitrary-SQL passthrough,
destructive capability, hardcoded exfiltration endpoints, and PII exposure.

## Scoring formula

The score is **deterministic** and starts at **100**. Each finding subtracts a
fixed weight by severity, and the result is floored at 0:

```
score = max(0, 100 − Σ weight(severity_of_finding))

weight: critical = 40, high = 20, medium = 10, low = 5, info = 0
```

Higher means fewer weighted findings among the supported patterns on the
analyzed surface. It does **not** mean universally safer. Because info-level
findings subtract 0, an otherwise clean server with only ME-001 still scores 100. The formula lives in
[`scorer.py`](../src/mcp_auditor/scorer.py) and is covered by tests.

The score is a **risk-prioritization heuristic**, not a probability that a
server is safe and not a measurement of detector accuracy. It does not use
confidence, code coverage, precision, or recall. Multiple findings can also
refer to the same underlying behavior, so do not compare the score with a
machine-learning confidence score.

## Detection benchmark: coverage, capabilities, and error rates

Unit tests prove individual behavior, but they do not measure the auditor's
overall error rate — and an error rate computed over tools the extractor never
found is not a safety result at all. The repository therefore ships two labelled
datasets, split by how they may be used:

| Dataset | Split | Used for |
|---|---|---|
| [`benchmarks/capability-attribution-v1.yaml`](../benchmarks/capability-attribution-v1.yaml) | `development` | Fast regression set debugged against. Never quote it as accuracy. |
| [`benchmarks/official-inventory-v1.yaml`](../benchmarks/official-inventory-v1.yaml) | `validation` | 58 reviewed tools across seven official servers at a pinned commit. Chooses extractor and rule changes. |

```bash
mcp-audit benchmark benchmarks/capability-attribution-v1.yaml
mcp-audit benchmark benchmarks/official-inventory-v1.yaml --corpus-root ../servers
mcp-audit benchmark benchmarks/official-inventory-v1.yaml --json
```

The validation corpus is referenced, not vendored — see
[`benchmarks/README.md`](../benchmarks/README.md) for the four commands that
materialize the pinned checkout. Without it those cases report `unavailable`
and the run fails, so a missing corpus can never read as a passing benchmark.

Each dataset carries three kinds of human-reviewed label, and the evaluator
reports each as its own view:

- **discovery** — `expected_tools` per server: coverage, plus the tools that
  were missed and the ones that were extracted without a label;
- **capability** — one `(tool, capability, expected)` decision each, positive
  *and* negative, so a handler that must not inherit a sibling's sink is
  measured as explicitly as one that must;
- **findings** — one `(rule, tool, expected)` decision each.

For every view the report gives TP / FP / FN / TN, precision, recall,
specificity, false-positive rate, F1, and accuracy — overall, per rule, per
capability, and per registration shape, so a coverage failure is attributed to
the shape that caused it rather than averaged away.

Anything the engine gets wrong must be written down in the dataset as a
`known_gap` (or `coverage_gaps`) with a reason. An unexplained miss fails the
run; so does a gap that no longer reproduces, because a stale excuse hides real
regressions. That makes the exit code meaningful in CI while still allowing an
honest, measured deficit to be recorded rather than hidden.

Measured baseline at commit `599dafc` of `modelcontextprotocol/servers`:

| View | Result |
|---|---|
| Tool discovery | 100% (58/58) — every registration shape in the corpus |
| Capability classification | precision 100%, recall 100% (28 TP, 0 FP, 0 FN, 51 TN) |
| Findings | precision 100%, recall 100%, FPR 0% (7 TP, 0 FP, 0 FN, 18 TN) |

That is a **validation-split** result: the corpus the engine's changes were
chosen against. A separate frozen holdout of 109 tools across three community
servers, evaluated once, says how much of it generalizes:

| View | Validation | Holdout 1 | Holdout 2 |
|---|---|---|---|
| Tool discovery | 100% (58/58) | 5.5% (6/109) | **95.8% (46/48)** |
| Finding precision | 100% | 11.1% | **78.6%** |
| Capability recall | 100% | 0% | **0%** |

Two frozen holdouts, each evaluated exactly once on servers the engine was not
built against. The first found that almost nothing generalized; three changes
followed; the second — built *before* those changes — measured them.

The honest reading:

- **Tool discovery generalizes now.** 46 of 48 on unfamiliar servers, including
  33 whose descriptors are assembled by a factory in a different module from the
  handler that returns them. One registration shape still misses, and is
  recorded rather than fixed.
- **Capability attribution still attributes nothing** on unfamiliar code. It
  under-claims rather than claiming something wrong, which is the right
  direction to fail in, but it is not evidence of anything. Read the `UNKNOWN`
  rows and the vendor questions as the real output.
- **Findings are usable but not clean.** 78.6% precision, up from 11.1%.

Treat the validation number as a regression check, not as accuracy. The holdout
numbers are the ones that describe the product.

Detection signatures have two layers. `signatures.yaml` stores versioned rule
metadata, severity, confidence, and pattern/configuration lists. `rules.py`
contains the deterministic structural logic that applies those parameters.
Changing a regex changes detector behavior and therefore requires a benchmark
label or regression fixture, not only a version bump.

## The review packet

`mcp-audit review` is the output built for a human decision. It is not a score:
it is the sheet a security specialist signs.

```bash
mcp-audit review ./my-server            # terminal
mcp-audit review ./my-server --json     # machine-readable packet
mcp-audit review ./my-server --baseline previous-audit.json
```

It contains identity and provenance, normalized tool and package inventories, a
capability matrix, sensitive-data observations and possible flows, coverage
gaps, every contradiction, Atlas explanations, reviewer/vendor questions, an
optional change report, and an empty human-decision block.

Every matrix cell carries **where the statement came from**:

| Status | Meaning |
|---|---|
| `INFERRED` | derived statically from the implementation |
| `DECLARED` | from MCP metadata, annotations, or schema |
| `CLAIMED` | documentation only |
| `OBSERVED` | seen in a controlled runtime test |
| `VERIFIED` | accepted by a human reviewer |
| `UNKNOWN` | the evidence does not answer the question |
| `CONTRADICTED` | two evidence sources disagree |

Two rules the packet follows without exception:

**It never makes the human decision.** The decision `status` remains `PENDING`
and the reviewer and notes stay empty. A separate contextual assessment ranks
the next action as `INSUFFICIENT_EVIDENCE`, `REJECT_RECOMMENDED`,
`REVIEW_REQUIRED`, `APPROVE_WITH_CONSTRAINTS`, or
`ELIGIBLE_FOR_APPROVAL`. Even the last state explicitly says it is not a
universal safety claim.

**It never overstates its input.** A tree of prose about a server reports
`evidence: documentation`, not `source`. A handler whose effects could not be
followed gets an explicit `UNKNOWN` row and a written question, never a blank
that reads as "no capabilities". And if any tool registration could not be
resolved, the 0–100 score is **withheld entirely** rather than computed over a
surface that was only partly parsed.

## The `AuditReport` contract

`audit(target)` returns one stable, JSON-serializable shape (the only place
detection logic lives — CLI and JSON are thin wrappers):

```jsonc
{
  "target": "https://github.com/owner/repo",
  "is_mcp_server": true,
  "tools_analyzed": 7,
  "score": 42,                     // null when coverage is incomplete
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
  "tools": [
    {
      "name": "send_email",
      "description": "Send an email",
      "schema": { "type": "object", "properties": {} },
      "location": "server.ts:20",
      "capabilities": [
        {
          "capability": "network.outbound", "evidence": "fetch(",
          "confidence": "high", "destructive": false, "location": "server.ts:24"
        }
      ]
    }
  ],
  "policy": {                    // only when --policy is supplied
    "department": "engineering",
    "employee": "alice",
    "agent": "alice-helper",
    "decision": "deny",
    "effective_allow": ["filesystem.read"]
  },
  "summary": { "critical": 1, "high": 2, "medium": 0, "low": 1, "info": 3 },
  "generated_at": "2026-06-26T00:00:00Z"
}
```

When the target is not an MCP server—or an MCP/skill package has unresolved
handlers, executables, or referenced files—`score` is `null` and a
human-readable `message` explains why. Incomplete evidence never becomes a
misleading number.

## How to add a signature

Detection patterns live in
[`src/mcp_auditor/signatures.yaml`](../src/mcp_auditor/signatures.yaml) so you can
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
- **TypeScript / JavaScript:** `@modelcontextprotocol/sdk` and current
  `@modelcontextprotocol/server` imports; legacy `server.tool(...)`, current
  `registerTool(name, config, handler)`, and low-level `tools/list` handlers.
  Handler capabilities use a comment-aware structural scan; dynamic imports,
  wrapper functions, and generated dispatch remain explicitly reported limits.
- **Manifest:** any JSON listing tools with `name` + `description` + `inputSchema`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
