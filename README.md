# mcp-audit

**Read an MCP server before you trust it.**

`mcp-audit` statically reviews MCP servers and AI skill packages: it inventories
the tools they expose, infers what each one can actually reach from the source,
maps possible sensitive-data flows, and hands you findings with evidence
attached — plus a browsable Threat Encyclopedia explaining every pattern it
looks for.

It never imports, installs, executes, or evaluates the thing it is reviewing.
Targets are read as text. That is deliberate: a malicious MCP server is exactly
what you point this at.

> **Alpha.** This is decision support for a human security review, not a
> `SAFE` certificate. When coverage is incomplete it withholds the numeric risk
> indicator rather than treating unread code as harmless.

---

## Install

**Pick one.** They are ordered by how few ways they can go wrong.

### 1. `uv` — recommended

```powershell
uv tool install "git+https://github.com/Rozzeo/mcp-auditor-pi-codex"
mcp-audit --help
```

`uv` gives the tool its own isolated environment, picks a compatible Python for
it, and puts `mcp-audit` somewhere already on your PATH. It does not care which
Pythons you have installed or which one is "first".

Don't have `uv`? One line, no Python needed:

```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"     # Windows
curl -LsSf https://astral.sh/uv/install.sh | sh                # macOS / Linux
```

Upgrade later with `uv tool upgrade mcp-auditor-static`, remove with
`uv tool uninstall mcp-auditor-static`.

### 2. No install at all

Clone it and run it. `uv` resolves the dependencies into a throwaway
environment; nothing lands on your system.

```powershell
git clone https://github.com/Rozzeo/mcp-auditor-pi-codex
cd mcp-auditor-pi-codex
uv run mcp-audit --help
```

### 3. `pipx`

```powershell
pipx install "git+https://github.com/Rozzeo/mcp-auditor-pi-codex"
```

### 4. Plain `pip`

Works, but this is the one that produces "command not found", because
`pip install --user` writes the executable into a `Scripts` directory that
Windows often leaves off PATH.

```powershell
py -m pip install --user --upgrade "https://github.com/Rozzeo/mcp-auditor-pi-codex/archive/refs/heads/main.zip"
py -m mcp_auditor --help
```

Use `py -m mcp_auditor` (macOS/Linux: `python3 -m mcp_auditor`) rather than
`mcp-audit`. It goes through the interpreter you just installed into, so it
cannot be shadowed by an older copy sitting earlier on PATH.

### About the name

The `mcp-auditor` project on PyPI belongs to somebody else and is a different,
runtime-testing product. **Do not `pip install mcp-auditor`.**

| | |
|---|---|
| Distribution name | `mcp-auditor-static` |
| Python import | `mcp_auditor` |
| Command | `mcp-audit`, or `python -m mcp_auditor` |

---

## Check it worked

```powershell
mcp-audit doctor
```

`doctor` answers the questions an error message never does: which interpreter is
running, whether more than one `mcp-audit` is on PATH and which one wins, which
dependencies are present, and which threat-definition version you are actually
detecting with. It exits non-zero if something is genuinely broken, so it works
as a CI check too. `mcp-audit doctor --json` gives the same thing machine-readably.

If `mcp-audit` itself is not found, run `python -m mcp_auditor doctor` — that
form never depends on PATH — and see [Troubleshooting](#troubleshooting).

## Your first audit

```powershell
mcp-audit some-mcp-server/                       # a local folder
mcp-audit https://github.com/owner/mcp-server    # a public repo, no clone
mcp-audit path/to/a/skill/                       # an agent skill package
```

Add a shareable report:

```powershell
mcp-audit some-mcp-server/ --html report.html
```

Gate CI on it:

```powershell
mcp-audit some-mcp-server/ --fail-on high     # non-zero exit if anything high+
mcp-audit some-mcp-server/ --json > audit.json
```

For GitHub targets, set `GITHUB_TOKEN` to raise the API rate limit. Optional.

---

## Commands

| Command | What it gives you |
|---|---|
| `mcp-audit <path-or-url>` | The static audit: findings, evidence, capabilities, score. |
| `mcp-audit review <target>` | The evidence packet a human approver signs off on. |
| `mcp-audit diff <old> <new>` | What changed between two versions — the rug-pull detector. |
| `mcp-audit matrix <target> --out matrix.csv` | Connector approval matrix for InfoSec review. |
| `mcp-audit installed` | Every MCP server already configured on this machine. |
| `mcp-audit playground` | The interactive teaching page — paste a tool, watch it get caught. |
| `mcp-audit intel build-docs` | Build the Threat Encyclopedia from the Atlas. |
| `mcp-audit update` | Refresh threat definitions without upgrading the package. |
| `mcp-audit benchmark` | Score the detectors against the labelled benchmark sets. |
| `mcp-audit doctor` | Diagnose this installation: interpreter, PATH, dependencies, definitions. |

`--help` works on every one of them.

---

## What it actually reports

- The tool and package inventory, and **what it could not read** — coverage
  gaps are reported, not silently skipped.
- Capabilities inferred from the implementation: filesystem read/write,
  database read/write/raw-query/destructive, network egress, process
  execution, environment and secret access.
- Contradictions between what a tool *declares* (`readOnlyHint`,
  `destructiveHint`) and what its handler actually does. Annotations are
  treated as untrusted hints, never as facts.
- Sensitive-data sources, sinks, and evidence-backed possible flows between
  them.
- Threat Atlas explanations, safer-versus-risky examples, and the questions a
  reviewer should ask.

The final decision stays `PENDING` — a person makes it. The assessment states:

| Assessment | Meaning |
|---|---|
| `INSUFFICIENT_EVIDENCE` | Handlers or package files could not be reviewed. |
| `REJECT_RECOMMENDED` | A high-confidence prohibited condition is visible. |
| `REVIEW_REQUIRED` | Safety depends on data, destinations, permissions, or deployment controls. |
| `APPROVE_WITH_CONSTRAINTS` | The supplied policy permits the observed surface under stated constraints. |
| `ELIGIBLE_FOR_APPROVAL` | No supported prohibited pattern on the fully analyzed surface. Not a universal safety claim. |

---

## The three HTML surfaces

All three are single self-contained files. Open them from disk, attach them to a
ticket, or publish them from CI. They share one visual system — see
[`skills/retro-futurist-editorial-html/`](skills/retro-futurist-editorial-html/SKILL.md),
a real agent skill you can point Claude Code at to build new pages in the same
style.

| | Built by | What it is for |
|---|---|---|
| **Audit report** | `--html report.html` | The findings, for the person deciding. |
| **Threat Encyclopedia** | `mcp-audit intel build-docs` | The research-cited catalog behind every rule. |
| **Playground** | `mcp-audit playground` | Paste a tool description, watch the rules fire live. |

---

## Department and helper-agent privilege policies

The same tool can be fine for a builder and forbidden for a read-only helper, so
privileges resolve through a **narrowing-only** hierarchy:

```
department ceiling → employee role → employee → parent agent → helper profile → agent
```

Every allow layer intersects the previous one; every deny wins. A helper can
never gain a capability its employee or parent agent lacks.

```powershell
mcp-audit ./server --policy examples/department-policy.yaml --agent alice-helper
```

Policies are **never** auto-loaded from the repository being audited. Full model:
[`docs/PRIVILEGE-POLICY.md`](docs/PRIVILEGE-POLICY.md).

---

## Diff mode — catching the rug pull

A server that was clean at install time can turn malicious in an update.

```powershell
mcp-audit ./server --json > baseline.json     # at approval time
mcp-audit diff baseline.json ./server         # after every update
mcp-audit diff old new --fail-on high         # CI gate on NEW findings only
```

It reports the score delta, new and resolved findings, and the tool-surface
change list. An added tool, or a changed description, schema, annotation, or
inferred capability on an existing one, raises an explicit **rug-pull signal**.
The saved JSON carries the tool surface, so the comparison works from a baseline
file alone.

---

## Where the knowledge comes from

```
reviewed research and advisories
              |
              v
threats.yaml (Atlas)  +  signatures.yaml (detectors)
              |
              v
evidence in audit / review  +  the generated Threat Encyclopedia
```

Fresh material from the internet enters a review queue. It never becomes an
executable detection rule automatically. Atlas and detector versions move
together, so any report can name the knowledge version that produced it.

---

## Troubleshooting

### `mcp-audit: command not found` / `The term 'mcp-audit' is not recognized`

The package installed fine; its executable just is not on PATH. Either use the
PATH-independent form:

```powershell
py -m mcp_auditor --help
```

…or reinstall with `uv tool install`, which handles PATH for you (option 1
above). You do not need to move folders or reinstall Python.

### `mcp-audit` runs, but behaves like an old version

You have more than one copy installed and an older one is earlier on PATH.
`mcp-audit doctor` says so outright; to see the list yourself:

```powershell
Get-Command mcp-audit -All | Select-Object Source     # PowerShell
which -a mcp-audit                                    # bash
```

Remove the stale ones — in particular anything still installed under the old
`mcp-auditor` distribution name:

```powershell
py -m pip uninstall mcp-auditor
```

### `No module named mcp_auditor`

You installed into one interpreter and are running another. On a machine with
several Pythons, `py`, `python`, and `python3` can all be different. Pin both
sides to the same one:

```powershell
py -m pip install --user --upgrade "https://github.com/Rozzeo/mcp-auditor-pi-codex/archive/refs/heads/main.zip"
py -m mcp_auditor --help
```

Or sidestep the whole question with `uv tool install`.

### `No installed Python found`

Install Python 3.10+ from python.org with the launcher enabled, open a **new**
terminal, and run `py --version`. Or install `uv`, which will fetch a Python for
itself.

### `.xlsx` output fails

CSV needs nothing extra. Excel output needs one optional dependency:

```powershell
uv tool install --with openpyxl "git+https://github.com/Rozzeo/mcp-auditor-pi-codex"
```

---

## Use it from Claude Code

This repository is also a Claude Code plugin. It exposes the auditor as MCP
tools (`audit_mcp_server`, `list_rules`, `list_threats`, `explain_threat`), an
`/audit-mcp` command, and two agent skills:

| Skill | For |
|---|---|
| `skills/vetting-mcp-servers/` | Running a review and interpreting the findings. |
| `skills/retro-futurist-editorial-html/` | Building HTML pages in this project's house style. |

---

## Development

```powershell
git clone https://github.com/Rozzeo/mcp-auditor-pi-codex
cd mcp-auditor-pi-codex
uv sync --extra dev
uv run pytest -q
```

Prefer a plain venv:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
```

Build the artifacts that get attached to a tagged release:

```powershell
py -m pip install build
py -m build
```

CI runs the suite on Python 3.10 and 3.12, on Windows and Linux, and smoke-tests
the built wheel in a clean environment. A `v*` tag builds, tests, and attaches
the wheel and sdist to a GitHub Release. PyPI publishing is deliberately not
configured.

### Repository map

| Path | What lives there |
|---|---|
| `mcp_auditor/` | The whole product. `signatures.yaml` = detectors, `threats.yaml` = Atlas. |
| `tests/` | Regression and detector tests. |
| `benchmarks/` | Labelled development, validation, and holdout evaluations. |
| `docs/` | Reference, evidence model, privilege policy, plans. |
| `examples/` | Example policies and captured tool inventories. |
| `skills/`, `commands/`, `.claude-plugin/` | Claude Code integration. |

The package sits at the repository root on purpose: `python -m mcp_auditor` then
works straight from a checkout, with no install step and no PATH involved.

---

## Documentation

- [Command and detector reference](docs/REFERENCE.md)
- [Review Assistant plan and evidence gates](docs/MCP_REVIEW_ASSISTANT_PLAN.md)
- [Privilege policy model](docs/PRIVILEGE-POLICY.md)
- [Benchmark methodology and split results](benchmarks/README.md)
- [MVP history](docs/MVP.md) · [roadmap history](docs/ROADMAP.md)

## License

[MIT](LICENSE)
