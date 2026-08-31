# MCP Audit

Evidence-backed static review for MCP servers and Codex/Claude skill packages.
It inventories the exposed surface, infers capabilities from source, maps
possible sensitive-data flows, and produces findings with concrete evidence and
reviewer questions.

It never imports, installs, or executes the target being reviewed.

> **Alpha:** this is decision support for a human security review, not a
> universal `SAFE` certificate. Incomplete coverage withholds the numeric risk
> indicator instead of treating unknown code as harmless.

## Install

### Windows PowerShell

Install this repository directly from GitHub:

```powershell
py -m pip install --user --upgrade "https://github.com/Rozzeo/mcp-auditor-pi-codex/archive/refs/heads/main.zip"
py -m mcp_auditor --help
```

`py -m mcp_auditor` is the reliable Windows command because it does not depend
on the Python `Scripts` directory being present in `PATH`.

The shorter command is installed too. If this works on your machine, you can
use it everywhere in the rest of the documentation:

```powershell
mcp-audit --help
```

### macOS / Linux

```bash
python3 -m pip install --user --upgrade \
  "https://github.com/Rozzeo/mcp-auditor-pi-codex/archive/refs/heads/main.zip"
python3 -m mcp_auditor --help
```

### Important package-name warning

The PyPI project named `mcp-auditor` belongs to a different author and is a
different, runtime-testing product. Do not use that name to install this
repository.

This project's distribution name is `mcp-auditor-static`; its Python import is
`mcp_auditor`; and its optional console command is `mcp-audit`.

Verify what was installed:

```powershell
py -m pip show mcp-auditor-static
```

## Quick start

Audit a local MCP server:

```powershell
py -m mcp_auditor C:\path\to\mcp-server
```

Audit a public GitHub repository without cloning it:

```powershell
py -m mcp_auditor https://github.com/owner/mcp-server
```

Audit one Codex/Claude skill package, including bundled scripts and references:

```powershell
py -m mcp_auditor C:\path\to\skill
```

Produce the evidence packet used for a human approval decision:

```powershell
py -m mcp_auditor review C:\path\to\skill
```

Write JSON or a self-contained HTML report:

```powershell
py -m mcp_auditor C:\path\to\server --json
py -m mcp_auditor C:\path\to\server --html report.html
```

On macOS/Linux, replace `py` with `python3`. If `mcp-audit` works in your
terminal, it is equivalent to `py -m mcp_auditor`.

## What the review engine returns

- tool and package inventory;
- source evidence and coverage gaps;
- inferred read, write, delete, network, process, database, and credential
  capabilities;
- contradictions between declared annotations and implementation;
- sensitive-data sources, sinks, and evidence-backed possible flows;
- Threat Atlas explanations, safer/risky examples, and reviewer questions;
- a contextual next action, while the final human decision stays `PENDING`.

Possible assessment states:

| Assessment | Meaning |
|---|---|
| `INSUFFICIENT_EVIDENCE` | Required handlers or package files could not be reviewed. |
| `REJECT_RECOMMENDED` | A high-confidence prohibited condition is visible. |
| `REVIEW_REQUIRED` | Safety depends on data, destinations, permissions, or deployment controls. |
| `APPROVE_WITH_CONSTRAINTS` | The supplied policy permits the observed surface under stated constraints. |
| `ELIGIBLE_FOR_APPROVAL` | No supported prohibited pattern was found on the fully analyzed surface; this is not a universal safety claim. |

## Common commands

| Command | Purpose |
|---|---|
| `py -m mcp_auditor <path-or-github-url>` | Static audit. |
| `py -m mcp_auditor review <target>` | Human-readable evidence packet. |
| `py -m mcp_auditor diff <old> <new>` | Detect surface changes and rug pulls. |
| `py -m mcp_auditor matrix <target> --out matrix.csv` | Connector approval matrix. |
| `py -m mcp_auditor installed` | List MCP servers configured on this machine. |
| `py -m mcp_auditor playground` | Generate the local educational playground. |
| `py -m mcp_auditor intel build-docs` | Build the Threat Encyclopedia from the Atlas. |
| `py -m mcp_auditor update` | Refresh signed-off Atlas and detector definitions. |

Run `py -m mcp_auditor --help` or append `--help` to any command for the full
option list.

## Troubleshooting

### `The term 'mcp-audit' is not recognized`

The package may be installed correctly while Python's `Scripts` directory is
not in PowerShell's `PATH`. Use the PATH-independent command:

```powershell
py -m mcp_auditor --help
```

You do not need to move project folders or reinstall the package merely to use
this form.

### `No module named mcp_auditor`

Confirm that installation and execution use the same Python interpreter:

```powershell
py -m pip show mcp-auditor-static
py -m pip install --user --upgrade "https://github.com/Rozzeo/mcp-auditor-pi-codex/archive/refs/heads/main.zip"
py -m mcp_auditor --help
```

### `No installed Python found`

Install Python 3.10 or newer from python.org, enable the Python launcher during
installation, open a new PowerShell window, and run `py --version`.

### Excel output

CSV needs no optional dependency. For `.xlsx` output, install the `xlsx` extra:

```powershell
py -m pip install --user --upgrade "mcp-auditor-static[xlsx] @ https://github.com/Rozzeo/mcp-auditor-pi-codex/archive/refs/heads/main.zip"
```

## Threat Atlas and Encyclopedia

The educational layer remains part of the product:

```text
reviewed research and advisories
              |
              v
 threats.yaml (Atlas) + signatures.yaml (detectors)
              |
              v
 evidence in audit/review + generated Threat Encyclopedia
```

Fresh internet results enter a review queue; they never become executable
detection rules automatically. Atlas and detector versions move together so a
report can identify the knowledge version that produced it.

## Repository map

End users do **not** need to understand or copy these folders. Installation uses
the GitHub archive or a wheel from GitHub Releases.

| Path | Why it exists |
|---|---|
| `mcp_auditor/` | The complete Python product. |
| `tests/` | Regression and security-detector tests. |
| `benchmarks/` | Labelled development, validation, and holdout evaluations. |
| `docs/` | Detailed reference, evidence model, plans, and policies. |
| `examples/` | Example policies and captured tool inventories. |
| `.claude-plugin/`, `commands/`, `skills/` | Optional Claude Code integration. |

The `src/` layout is intentional Python packaging structure. It prevents the
repository checkout from being imported accidentally and is not part of the
user installation workflow.

## Development

```powershell
git clone https://github.com/Rozzeo/mcp-auditor-pi-codex.git
cd mcp-auditor-pi-codex
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
```

Build the same artifacts attached to tagged GitHub Releases:

```powershell
py -m pip install build
py -m build
```

CI tests Python 3.10 and 3.12 on Windows and Linux. A version tag such as
`v0.2.0` builds, smoke-tests, and attaches the wheel and source distribution to
a GitHub Release. PyPI publishing is intentionally not claimed or configured.

## Documentation

- [Detailed command and detector reference](docs/REFERENCE.md)
- [Review Assistant plan and evidence gates](docs/MCP_REVIEW_ASSISTANT_PLAN.md)
- [Privilege policy](docs/PRIVILEGE-POLICY.md)
- [Benchmark methodology and honest split results](benchmarks/README.md)
- [MVP history](docs/MVP.md) and [roadmap history](docs/ROADMAP.md)

## License

[MIT](LICENSE)
