# Benchmarks

Labelled ground truth for the static engine. Every number the project publishes
about coverage, precision, or recall has to come from here.

## Splits

A split is a promise about how a dataset may be used. It is recorded in the file
and travels with every result, so a tiny regression set can never be quoted as
production accuracy.

| Split | Dataset | Rule |
|---|---|---|
| `development` | `capability-attribution-v1.yaml` | Small, fast, debugged against. A change detector only. |
| `validation` | `official-inventory-v1.yaml` | Reviewed corpus at a pinned commit. Chooses extractor and rule changes. |
| `holdout` | `external-holdout-v1.yaml` | Frozen before its first evaluation. Never tuned on. |

Repository families, generated variants, and near-duplicate tools must stay in
the same split, or the result leaks.

## Running

```bash
mcp-audit benchmark benchmarks/capability-attribution-v1.yaml
mcp-audit benchmark benchmarks/official-inventory-v1.yaml --corpus-root ../servers
mcp-audit benchmark benchmarks/external-holdout-v1.yaml --corpus-root ../external-holdout
mcp-audit benchmark benchmarks/official-inventory-v1.yaml --json
```

Exit code `0` means every labelled decision either held or was already recorded
as a known gap. Exit `1` means something is unaccounted for: an unexplained
miss, a gap whose excuse has gone stale, or a referenced corpus that is not on
disk.

## Materializing the pinned corpus

`official-inventory-v1.yaml` references upstream source rather than vendoring
it. The labels are pinned to one commit, so the checkout must be too:

```bash
git init servers && cd servers
git remote add origin https://github.com/modelcontextprotocol/servers.git
git fetch --depth 1 origin 599dafc1054550a6eeb87a6545c1e1b03b3ca827
git checkout FETCH_HEAD
```

Then pass `--corpus-root <path>`, or export `MCP_AUDITOR_CORPUS_ROOT` once. When
the checkout is absent the cases are reported `unavailable` and the run fails —
they are never silently skipped.

The external holdout uses a composite corpus. Materialize the three repositories
listed under `corpus.repositories` as sibling directories beneath one root. The
benchmark reads each `.git/HEAD` and refuses to evaluate if a checkout is absent
or differs from its pinned commit. `external-holdout-v1.sha256` freezes the
reviewed labels themselves; any later label change creates a new dataset version,
not a retroactive correction to the one-shot result.

## Dataset shape

```yaml
version: 2
name: official-inventory-v1
split: validation
purpose: >-
  What this dataset is allowed to prove.
corpus:                       # optional; omit for datasets with local fixtures
  repo: https://github.com/modelcontextprotocol/servers
  commit: 599dafc1054550a6eeb87a6545c1e1b03b3ca827

cases:
  - id: filesystem
    target: src/filesystem    # relative to the corpus root, else to this file
    shape: ts-register-tool-literal
    expected_tools: [read_file, write_file, ...]
    capabilities:
      - {tool: write_file, capability: filesystem.write, expected: true}
      - {tool: write_file, capability: network.outbound, expected: false}
    labels:
      - {rule: OP-002, tool: write_file, expected: false}
    coverage_gaps:
      some_tool: Why this tool is not extracted yet.
```

For large fully labelled cases, `capability_defaults` applies a boolean label to
every `expected_tools` entry and explicit `capabilities` rows override individual
tool/capability pairs. This keeps a complete positive/negative matrix reviewable
without weakening what is measured.

`shape` names the registration form the extractor has to handle. Metrics are
grouped by it, so a coverage failure is attributed to the construct that caused
it instead of being averaged across the corpus.

Label both directions. A dataset holding only positives can measure recall but
says nothing about false positives, and the negatives are what prove a handler
did not inherit the sink of the tool registered next to it.

## Known gaps

Anything the engine currently gets wrong is written down where it happens:

```yaml
- tool: read_media_file
  capability: filesystem.read
  expected: true
  known_gap: >-
    P2: the read happens in a helper the handler calls.
```

The label still counts as a false negative in the metrics — the deficit stays
visible. What the gap changes is the exit code: a recorded miss is a measured
result, an unrecorded one is a failure.

A gap that stops reproducing also fails the run. When a phase closes one, delete
the `known_gap` entry in the same change; otherwise a stale excuse would go on
absorbing a real regression.

## The holdout, and what it cost to learn

`external-holdout-v1` holds 109 tools across three community servers by three
authors, labelled from source and evaluated **once**. Its frozen first-run
result is in `external-holdout-v1-result.md`.

| View | Validation | Holdout |
|---|---|---|
| Tool discovery | 100% (58/58) | **5.5% (6/109)** |
| Capability recall | 100% | **0%** (0 TP, 116 FN) |
| Capability precision | 100% | 0 false positives |
| Finding precision | 100% | **11.1%** (1 TP, 8 FP) |

Discovery does not generalize: 6 of 109. Capability attribution attributes
nothing at all, though it claims nothing wrong either. Finding precision
collapses.

Two lessons are worth stating separately, because they cost real effort to
learn:

**A tool's registered name is not always the name a client sees.**
`mcp-atlassian` composes its Jira and Confluence toolsets with
`main_mcp.mount(jira_mcp, namespace="jira")`, so the wire names are
`jira_get_issue` and `confluence_get_page`. The extractor reports the
unprefixed function names. A labeller reading decorator sites will produce the
same unprefixed names, agree with the engine, and measure 98/98 where the true
answer is 0/98. That mistake was made here and caught only because a second,
independently built holdout used the documented wire names. **Label a tool by
what a client would call, not by what the source calls it.**

**Two labellers on one corpus is worth the duplication.** The disagreement
between the two datasets is what surfaced the error at all.

## The second holdout, and what the fixes were worth

`external-holdout-v2` was built before the fixes that followed the first holdout,
and evaluated once after them — 48 tools across `GLips/Figma-Context-MCP`,
`chroma-core/chroma-mcp` and `executeautomation/mcp-playwright`:

| View | Holdout 1 (before fixes) | Holdout 2 (after) |
|---|---|---|
| Tool discovery | 5.5% (6/109) | **95.8% (46/48)** |
| Finding precision | 11.1% | **78.6%** |
| Capability recall | 0% | 0% (unaddressed) |

Three changes were made: namespace mounts (`mount(server, namespace="jira")`
means the wire name is `jira_get_issue`), `TP-003`'s case sensitivity, and
descriptor arrays a ListTools handler reaches through a const or a factory.

This is the only evidence any of that works on code it was not written against.
`mcp-playwright`'s 33 tools resolve through a factory in a different module from
its handler, and `TP-003` fires zero times where it previously supplied 48 false
positives.

One shape still misses — Figma takes its tool name from a property of an
imported object — and it is recorded rather than fixed, because fixing it now
would fit the engine to this corpus. `RP-001`'s pnpm blind spot reproduced here
on a second repository, and is likewise left alone.

Both holdouts are spent. A third is needed before the next round of work can
claim to generalize.

## Current measured baseline

`official-inventory-v1` at commit `599dafc`:

| View | Result |
|---|---|
| Tool discovery | **100% (58/58)** |
| — `ts-register-tool-literal` | 100% (24/24) |
| — `ts-register-tool-variable` | 100% (19/19) |
| — `py-lowlevel-list-tools` | 100% (15/15) |
| Capability classification | precision 100%, recall 100% (28 TP, 0 FP, 0 FN, 51 TN) |
| Findings | precision 100%, recall 100%, FPR 0% (7 TP, 0 FP, 0 FN, 18 TN) |

Every labelled decision holds and no `known_gap` remains.

Read it for what it is: a **validation-split** result. This is the corpus that
extractor and rule changes were chosen against, so it measures that the engine
does what a reviewer said it should on these seven servers — not that it will
generalize. `external-holdout-v1` is the separate frozen generalization check;
its result must be reported independently and must never be folded back into
detector tuning.

## Frozen external holdout result

`external-holdout-v1` was labelled before its first run and evaluated once. Its
dataset hash and full report are recorded in `external-holdout-v1.sha256` and
`external-holdout-v1-result.md`.

| View | First-run result |
|---|---|
| Tool discovery | **5.5% (6/109)** |
| Capability classification | recall **0%** (0 TP, 0 FP, 116 FN, 1083 TN) |
| Findings | precision **11.1%**, recall **20%**, FPR **80%** (1 TP, 8 FP, 4 FN, 2 TN) |

These figures supersede no validation result: the splits answer different
questions. The holdout shows that the validation-perfect detector does not yet
generalize to these external registration and call-boundary shapes.

Six defects were caught by running against this corpus that reading the code did
not: a bare `remove(` counted as a file deletion, `async (args) =>` indexed as a
function named `async`, a `pyproject.toml` the loader never actually read, a path
validator handing every guarded tool a read, `destructiveHint: true` read as a
claim of harmlessness, and an indented multi-line call indexed as a definition.
That is what the corpus is for.
