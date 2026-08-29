# MCP Review Assistant: Product Scope, Research Summary, and Engine Plan

**Status:** working product direction  
**Date:** 2026-08-25  
**Decision model:** advisory. A security specialist makes the final decision.

## 1. Product in one sentence

MCP Auditor is an evidence-backed review assistant that turns MCP documentation,
`tools/list` metadata, and source code into a normalized capability matrix,
highlights contradictions and unknowns, and preserves a review trail for a human
security specialist.

It is not an automatic MCP allow/deny gate and it must not claim assurance that
its input cannot support.

## 2. The narrow, useful job

The reviewer needs reliable answers to five questions:

1. What tools does this MCP expose?
2. What objects can each tool read, create, update, delete, or send externally?
3. Which identity, credentials, scopes, paths, endpoints, and other boundaries
   constrain those actions?
4. What evidence supports each statement, and where do the sources disagree?
5. What changed since the previous review?

A generic LLM can summarize a page once. This product must add repeatability:

- a stable capability ontology;
- evidence provenance down to a URL, file, line, or schema field;
- completeness and coverage reporting;
- explicit unknowns rather than guessed answers;
- contradictions between claims, declarations, implementation, and observations;
- version-pinned results and diffs;
- a reviewer decision record.

## 3. Supported evidence, without pretending

The engine should accept three primary input forms and one optional future form.

| Input | What it can establish | What it cannot establish |
|---|---|---|
| Vendor documentation or saved HTML | Published tool names, described operations, documented auth and limits | Actual implementation, complete inventory, runtime enforcement |
| `tools/list` JSON | Declared tool inventory, descriptions, annotations, and input schemas for one captured endpoint/version | Hidden implementation effects or whether runtime policy enforces the declaration |
| Source repository or directory | Registered tools, code paths, capability sinks, validators, and configuration clues | Deployed configuration, effective credentials, network policy, or runtime behavior |
| Controlled runtime observation, optional and later | Behavior exercised by specific test cases in a specific environment | Exhaustive absence of untested behavior |

Every matrix cell should carry one evidence status:

- `CLAIMED`: found only in documentation;
- `DECLARED`: found in MCP metadata or schema;
- `INFERRED`: derived statically from source;
- `OBSERVED`: seen in a controlled runtime test;
- `VERIFIED`: accepted by a human reviewer;
- `UNKNOWN`: the available evidence does not answer the question;
- `CONTRADICTED`: two or more evidence sources disagree.

Documentation-only analysis is useful, but its result must be labelled
`documentation-only`. It should produce a review matrix and evidence requests,
not a synthetic security score.

## 4. Primary output: the review packet

The main artifact is not a score. It is a review packet with:

1. **Identity and provenance** - server/vendor, source URL, version or commit,
   capture time, and evidence types supplied.
2. **Normalized tool inventory** - every discovered tool and its source.
3. **Capability matrix** - object plus read/create/update/delete/external-send
   actions, authentication, scope, and supporting evidence.
4. **Contradictions and gaps** - mismatched annotations, undocumented tools,
   implementation effects absent from descriptions, and unresolved unknowns.
5. **Focused findings** - only evidence-backed security concerns, each with a
   confidence level and a concrete manual check.
6. **Vendor questions** - missing evidence converted into an actionable
   questionnaire.
7. **Change report** - additions, removals, and capability or permission changes
   relative to the last pinned review.
8. **Human decision** - `APPROVE`, `APPROVE WITH CONSTRAINTS`, `NEEDS EVIDENCE`,
   `REJECT`, or `RE-REVIEW REQUIRED`, with reviewer notes.

Minimum capability-row shape:

```text
tool | object | read | create | update | delete | external_send
     | identity/scope | evidence_status | evidence_reference | confidence
```

Coverage and assurance are separate dimensions. A clean result with 40% tool
extraction coverage is not a safe result; it is an incomplete result.

## 5. What the three papers contribute

### 5.1 MCP landscape and security lifecycle

Paper: [Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions](https://arxiv.org/abs/2503.23278v3)

The paper organizes an MCP server into four lifecycle phases and 16 activities:

- **Creation:** metadata definition, capability declaration, code implementation,
  and slash-command definition.
- **Deployment:** release, installer deployment, environment setup, and tool
  registration.
- **Operation:** intent analysis, external resource access, tool invocation, and
  session management.
- **Maintenance:** version control, configuration change, access audit, and log
  audit.

Its threat taxonomy has four attacker classes and 16 scenarios:

- malicious developer: namespace typosquatting, tool-name conflict, preference
  manipulation, tool poisoning, rug pulls, cross-server shadowing, and command
  injection;
- external attacker: installer spoofing and indirect prompt injection;
- malicious user: credential theft, sandbox escape, tool-chaining abuse, and
  unauthorized access;
- security flaws: vulnerable versions, post-update privilege persistence, and
  configuration drift.

**Use in this product:** this is the Atlas taxonomy and the review-checklist
backbone. It also supports the core declared-versus-implemented capability check.
The paper explicitly recommends validating capability declarations before
release and checking that, for example, a read capability does not silently
include write access.

**Do not overclaim:** most deployment, operation, and maintenance controls cannot
be verified from tool metadata alone. Authentication enforcement, sandboxing,
session revocation, tenant isolation, live configuration, and audit logging need
runtime or administrator evidence. Static analysis should request that evidence,
not mark the control as present or absent without proof.

### 5.2 MCPTox

Paper: [MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers](https://arxiv.org/abs/2508.14925)

MCPTox contains 45 live MCP servers, 353 authentic tools, and 1,312 malicious
cases across three attack paradigms: explicit-trigger function hijacking,
implicit-trigger function hijacking, and implicit-trigger parameter tampering.

**Use in this product:** candidate positive cases for tool-metadata poisoning,
attack-template taxonomy, and adversarial mutations of benign descriptions.

**Do not overclaim:** MCPTox measures an agent's attack success rate. It does not
measure static-auditor precision, capability extraction coverage, or
declared-versus-implemented behavior. Its examples must be independently labelled
for this engine before they become benchmark ground truth.

### 5.3 MCP-Bench

Paper: [MCP-Bench: Benchmarking Tool-Using LLM Agents with Complex Real-World Tasks via MCP Servers](https://arxiv.org/abs/2508.20453)  
Repository: [Accenture/mcp-bench](https://github.com/Accenture/mcp-bench)

MCP-Bench evaluates agents on 28 real-world MCP servers, about 250 tools, and
104 tasks. It measures valid tool selection, schema compliance, execution
success, dependency compliance, task fulfillment, parameter accuracy, and
planning across single- and multi-server workflows.

**Use in this product:** a source of realistic benign tool inventories, schemas,
dependencies, and multi-tool relationships. These are valuable hard negatives
and coverage fixtures for the extractor.

**Do not overclaim:** MCP-Bench evaluates tool-using agents, not MCP server
security. Running the full benchmark requires live servers and external API
credentials, which is outside the static engine's immediate scope. Before copying
source or datasets into this repository, licensing must be verified; pinned
upstream references are the safe default.

### 5.4 Combined research role

The papers complement one another but do not form a ready-made auditor benchmark:

```text
Landscape paper -> threat and lifecycle taxonomy + review questions
MCPTox          -> malicious metadata candidates + poisoning transformations
MCP-Bench       -> realistic benign tools + schemas + dependency patterns
Our labels      -> capability ground truth + evidence boundaries + FP/FN metrics
```

The missing asset is our own independently reviewed, version-pinned ground-truth
corpus.

## 6. Current engine evidence

The first official-server calibration already exposed the main engineering
problem: extraction coverage is more important than adding wrappers.

At pinned commit `599dafc1054550a6eeb87a6545c1e1b03b3ca827` of
`modelcontextprotocol/servers`:

- the TypeScript filesystem handler-boundary bug was reproduced and fixed;
- `read_media_file` no longer inherits `fs.rename` from `move_file`;
- filesystem still produces path-related findings that need validator-aware
  analysis rather than broader suppression;
- memory registers tools but hides mutating effects behind helper-manager calls,
  exposing a bounded call-graph gap;
- low-level Python `list_tools`/`call_tool` servers are not extracted;
- TypeScript registrations using variable names, config objects, or named
  handlers remain coverage gaps;
- tests and fixtures can be mistaken for production code unless source role is
  classified.

The approximate official extraction coverage observed so far was 24 of 58 tools,
about 41%. That number is a diagnostic snapshot, not a product-quality metric.
Until coverage is high and measured, a low finding count must never be presented
as strong assurance.

### 6.1 Measured baseline at P0 (2026-08-28)

The estimate above is now a measured, reproducible result. `official-inventory-v1`
labels all 58 registered tools across the seven reference servers at commit
`599dafc1054550a6eeb87a6545c1e1b03b3ca827`, tool by tool, with per-tool positive
and negative capability labels and a decision for every finding the engine emits:

| View | Result |
|---|---|
| Tool discovery | 41.4% (24/58) |
| — `ts-register-tool-literal` (filesystem, memory, sequentialthinking) | 100% (24/24) |
| — `ts-register-tool-variable` (everything) | 0% (0/19) |
| — `py-lowlevel-list-tools` (git, fetch, time) | 0% (0/15) |
| Capability classification | precision 100%, recall 16.7% (4 TP, 0 FP, 20 FN) |
| Findings | precision 26.7%, recall 57.1%, FPR 73.3% (4 TP, 11 FP, 3 FN) |

Four error sources account for the whole deficit, and each is recorded against
the phase that closes it:

1. **Unsupported registration shapes (P1)** - 34 of the 34 missed tools. The
   `everything` server binds `registerTool(name, config, handler)` to variables,
   and one tool registers through `server.experimental.tasks.registerToolTask`.
   The Python servers declare tools in a `list_tools()` return value, twice via a
   `str`-Enum member rather than a literal.
2. **Sinks behind helpers (P2)** - 18 of the 20 capability false negatives. Both
   the filesystem helpers (`readFileContent`, `writeFileContent`,
   `applyFileEdits`, `getFileStats`, `searchFilesWithValidation`) and the whole
   `memory` server, whose nine tools all delegate to `KnowledgeGraphManager`.
3. **Sink-table gaps** - the remaining two: `fs.mkdir` maps to no capability, and
   `fs.rename` is classified as a delete without the destination write.
4. **Validator-blind path rules (P3)** - 10 of the 11 finding false positives.
   `OP-002` reports schema breadth on `filesystem` tools whose handlers resolve
   every path through `validatePath()` against the allowed-directory list with
   realpath symlink checks.

Two findings the earlier estimate did not cover:

- `CR-001` fires on a dummy `'token-123'` literal in
  `src/everything/__tests__/tools.test.ts`. Source-role classification (P1) is
  what removes it, not a broader credential-pattern suppression.
- `RP-001` inspects `package.json` only, so the equally unpinned `pyproject.toml`
  ranges in `git`, `fetch`, and `time` go unreported - three false negatives that
  static-only analysis should be catching today. This was not previously known.

Reproduce with:

```bash
mcp-audit benchmark benchmarks/official-inventory-v1.yaml --corpus-root <checkout>
```

### 6.2 After P1 (2026-08-28)

| View | P0 | P1 |
|---|---|---|
| Tool discovery | 41.4% (24/58) | **100% (58/58)** |
| — `ts-register-tool-variable` | 0% (0/19) | 100% (19/19) |
| — `py-lowlevel-list-tools` | 0% (0/15) | 100% (15/15) |
| Capability precision | 100% (0 FP / 20 TN) | 100% (**0 FP / 51 TN**) |
| Capability recall | 16.7% | 17.9% |
| Finding precision | 26.7% | 41.2% |
| Finding FPR | 73.3% | 66.7% |

Both P1 exit criteria are met and measured. Discovery is complete, and across 51
negative capability labels there is not one false positive — including the 19
`everything` tools registered from a single module tree and the 12 git tools
that share one `call_tool()` dispatcher. No handler inherited a sibling's sink.

Capability recall barely moved on purpose. The 34 newly discovered tools were
added to the inventory without inventing effects for them: the low-level shape
implements each tool in a branch of a shared dispatcher, so the declarations
carry no body until P2 can resolve the branch. Guessing here would have produced
exactly the cross-tool leakage the exit criterion forbids.

Finding quality improved because source-role classification removed the `CR-001`
false positive: the only credential-shaped literal in the reference corpus is a
dummy token in `__tests__/tools.test.ts`, which is not part of the deployed
artifact. Three findings on the newly discovered `everything` tools were labelled
and are all true positives (`TP-003` on `get-env`, `OP-002` on the unvalidated
`trigger-url-elicitation` URL, and the `TC-001` pairing of the two).

`OP-002` now supplies all 10 remaining false positives, which makes P3 the single
highest-value change left.

### 6.3 After P2 and P3 (2026-08-28)

| View | P0 | P1 | P2+P3 |
|---|---|---|---|
| Tool discovery | 41.4% (24/58) | 100% (58/58) | **100% (58/58)** |
| Capability precision | 100% | 100% | **100%** (0 FP / 51 TN) |
| Capability recall | 16.7% | 17.9% | **100%** (28 TP / 0 FN) |
| Finding precision | 26.7% | 41.2% | **100%** (7 TP / 0 FP) |
| Finding recall | 57.1% | 70.0% | **100%** (0 FN) |
| Finding FPR | 73.3% | 66.7% | **0%** |

Every labelled decision on the validation corpus now holds, and no `known_gap`
remains. Measured against §7.4:

| Gate | Target | Measured |
|---|---|---|
| Tool-discovery coverage on supported forms | ≥ 95% | 100% |
| Handler-boundary accuracy | 100% | 100% (0 FP across 51 negatives) |
| Precision for high/critical findings | ≥ 95% | 100% |
| Recall for supported threat patterns | ≥ 90% | 100% |
| False-positive rate on the clean official corpus | ≤ 2% | 0% |
| No safety score without coverage | required | score withheld when a registration is unresolved |
| Every finding carries evidence and a manual check | required | yes |

Six defects were found by running against the corpus rather than by reading the
code, which is the point of building the measurement first:

1. **A bare `remove(` counted as a file deletion.** Once P2 reached further into
   the tree, `sessionResources.remove(uri)` gave `gzip-file-as-resource` a
   destructive capability and a high-severity `CP-002`. The delete pattern is now
   qualified (`fs.rm`, `os.remove`, `Path(...).unlink`, `shutil.rmtree`).
2. **`async (args) => {` indexed as a function named `async`.** Two multi-line
   registrations in one file then made that name ambiguous, and every tool in
   the file reported an unresolved call it did not have.
3. **`pyproject.toml` was listed as a manifest the loader never read.** `.toml`
   and `.lock` were missing from the collected extensions, so `RP-001`'s Python
   support had never once executed.
4. **A path validator handed every guarded tool a `filesystem.read`.**
   `validatePath()` calls `realpath` to enforce its allow-list; attributing that
   to the caller was P2's only capability false positive. Read-only effects from
   a guard are now dropped, mutating ones still propagate.
5. **`destructiveHint: true` was read as a claim of harmlessness.** The review
   packet flagged three filesystem tools for accurately declaring themselves
   destructive. It is `destructiveHint: FALSE` that makes the promise - the rules
   already had this right, and the packet had drifted from them.
6. **An indented multi-line call was indexed as a definition.**
   `runResearchProcess(\n ...\n).catch(err => {` had its callback read as the
   function body, creating a second definition of a name that exists once. The
   real one became "ambiguous" and a plainly readable tool reported `UNKNOWN`.

Numbers 4, 5 and 6 were found by running `mcp-audit review` across all seven
servers and reading the result, which is worth doing after every phase: the
benchmark only measures what someone thought to label.

One earlier claim in §6.1 was wrong and is corrected here: `RP-001` was reported
as having a Python blind spot worth three false negatives on `git`, `fetch` and
`time`. Those three servers each ship their own `uv.lock`, so the rule was right
to stay silent and the labels were the error. The loader fix above is still a
real fix - without it the rule could not see a `pyproject.toml` at all - but it
changed nothing on this corpus.

### 6.4 Holdout result (2026-08-29)

`external-holdout-v1` pins 109 tools across three community servers by three
different authors, none from the `modelcontextprotocol/servers` family the
validation split is drawn from: `zcaceres/fetch-mcp` (6 tools),
`tavily-ai/tavily-mcp` (5), and `sooperset/mcp-atlassian` (98). Labels were
written from source before the engine was run against the corpus, once. The
frozen first-run record is `benchmarks/external-holdout-v1-result.md`.

It does not confirm the validation number. It contradicts it.

| View | Validation | Holdout |
|---|---|---|
| Tool discovery | 100% (58/58) | **5.5% (6/109)** |
| — low-level TS ListTools dispatch | n/a | 100% (6/6) |
| — TS SDK server tool array | n/a | 0% (0/5) |
| — Python FastMCP, mounted namespaces | n/a | 0% (0/98) |
| Capability recall | 100% | **0%** (0 TP, 116 FN) |
| Capability precision | 100% | 0 false positives |
| Finding precision | 100% | **11.1%** (1 TP, 8 FP) |

The one shape that carried over is the one the engine was built against. Every
other registration form in the corpus produced nothing.

**Capability precision held**, in the only sense available: the engine claimed
nothing rather than claiming something wrong. That is the right direction to
fail in for an advisory tool, and it is not evidence of capability.

#### A labelling error worth recording

Two holdouts were built independently over the same three repositories, and they
disagreed: one measured `mcp-atlassian` at 98/98, the other at 0/98. The 98/98
was wrong, and the way it was wrong is the useful part.

`mcp-atlassian` composes its toolsets with
`main_mcp.mount(jira_mcp, namespace="jira")`. The names an MCP client sees are
therefore `jira_get_issue` and `confluence_get_page` — as the project's own
README documents. A labeller reading decorator sites writes down `get_issue`.
The extractor also reports `get_issue`, because it does not model `mount`. So
the labels and the engine agreed with each other while both disagreed with the
deployed reality, and the benchmark reported a perfect score for a server whose
entire tool surface it had misnamed.

Two consequences, both now written into the method:

1. **Label a tool by the name a client would call, not the name the source gives
   it.** Composition — mounts, namespaces, prefixes, routers — happens between
   the two.
2. **A benchmark cannot detect a labeller who shares the engine's blind spot.**
   Only the second, independently produced dataset surfaced this. Where a result
   matters, the duplication is worth its cost.

The earlier prediction in this document — that the per-file SDK gate would reject
`mcp-atlassian`'s server modules and yield 0 of 98 — reached the right number
through the wrong reasoning, and was then "corrected" against a mismeasurement.
Both the prediction and its retraction were unreliable; the measurement that
stands is the one from the independently labelled dataset.

**This corpus is now spent for tuning.** Any change made to improve these
numbers fits the engine to it. `external-holdout-v2` was built for that reason
and has not been run.

### 6.5 Second holdout, after the fixes (2026-08-29)

Three changes were made against what the first holdout exposed, and then
`external-holdout-v2` - 48 tools across `GLips/Figma-Context-MCP`,
`chroma-core/chroma-mcp` and `executeautomation/mcp-playwright`, built before
those changes and never run - was evaluated once.

| View | Holdout 1 (before) | Holdout 2 (after) |
|---|---|---|
| Tool discovery | 5.5% (6/109) | **95.8% (46/48)** |
| Finding precision | 11.1% (1 TP, 8 FP) | **78.6% (11 TP, 3 FP)** |
| Capability recall | 0% | **0%** (unchanged, unaddressed) |

The changes:

1. **Namespace mounts.** A FastMCP parent mounting sub-servers with
   `mount(server, namespace="jira")` exposes `jira_get_issue`, not `get_issue`.
   The extractor now resolves mounts across the tree and reports the wire name.
2. **`TP-003` case sensitivity.** The `_KEY`/`_TOKEN` alternative is scoped
   `(?-i:...)` so it matches `AWS_SECRET_KEY` and no longer `issue_key`.
3. **Indirect tool arrays.** A ListTools handler that binds its descriptor array
   to a `const`, or returns a factory call defined in another module, is now
   read - accepting only arrays whose every object carries both a name and an
   inputSchema.

What generalized, and what did not:

- **Discovery did.** `mcp-playwright` builds its 33 descriptors in a factory in
  a different module from the handler; all 33 resolve. `chroma-mcp` is 13/13.
  Neither server was looked at while making the changes.
- **One shape still misses.** Figma writes `registerTool(getFigmaDataTool.name,
  ...)`, taking the name from a property of an imported object. Nothing targeted
  that, and it is 0/2. It is recorded rather than fixed: fixing it now would be
  fitting the engine to this corpus.
- **`TP-003` fired zero times** on 48 unfamiliar tools, against 48 false
  positives on 109 before.
- **Capability attribution is unchanged at 0%.** It was not addressed, and the
  result confirms the first holdout rather than adding to it.
- **A known defect reproduced independently.** `RP-001` fires on Figma because
  it ships a `pnpm-lock.yaml`, exactly as it did on `fetch-mcp`. Two holdouts,
  two repositories, one unfixed lockfile list.

The one adjudication worth naming: `CR-001` fires on a real embedded key in
Figma's `src/telemetry/client.ts`, next to a comment explaining it is a
write-only public ingest key. That is recorded as a **true positive**. It may
well be harmless, but deciding so is the reviewer's job, and a scanner that goes
quiet because a comment reassures it is a scanner a malicious package can write
its way past.

**This corpus is now spent too.** A third is needed before the next round -
Figma's property-access shape, the capability boundary at third-party packages,
and the pnpm lockfile - can be claimed to generalize.

## 7. Benchmark strategy

### 7.1 Three separate corpora

1. **Development corpus** - small, readable fixtures for rapid debugging. The
   existing `capability-attribution-v1` belongs here.
2. **Validation corpus** - pinned official and popular MCP implementations,
   labelled tool by tool by a reviewer. Use it to choose extraction and rule
   changes.
3. **Holdout corpus** - unseen repositories and metadata snapshots, frozen before
   evaluation. Do not tune on this set.

Repository families, generated variants, and near-duplicate tools must stay in
the same split to prevent leakage.

### 7.2 Ground truth unit

The unit is not only "finding present". Each labelled row should record:

```text
server_version | source_role | tool | handler_boundary | capability
object | annotation | expected_finding | evidence | reviewer | rationale
```

For every tool, label both positive and negative capabilities. A benchmark that
contains only attacks can measure recall but cannot measure false positives.

### 7.3 Required evaluation views

- **Tool discovery:** extracted tools / labelled tools.
- **Handler attribution:** capability sinks assigned to the correct tool.
- **Capability classification:** micro and macro precision, recall, and F1.
- **Finding quality:** precision, recall, false-positive rate, and false-negative
  rate per rule and severity.
- **Evidence quality:** percentage of findings with correct file/line or source
  references.
- **Abstention quality:** unknowns reported when evidence is insufficient instead
  of guessed classifications.
- **Mutation resistance:** harmless renames and formatting changes preserve the
  result; real capability changes alter it.

### 7.4 Initial quality gates

These are targets to validate, not claims about the current implementation:

- at least 95% tool-discovery coverage on supported SDK registration forms;
- 100% handler-boundary accuracy on the labelled boundary suite;
- at least 95% precision for high/critical findings;
- at least 90% recall for the explicitly supported threat patterns;
- at most 2% false-positive rate on the clean official corpus;
- no safety score when no tools were extracted or coverage is unknown;
- every finding includes evidence and a manual verification instruction.

## 8. Engine-first implementation plan

### P0 - Freeze truth before more heuristics — **done (2026-08-28)**

- [x] Pin a small official corpus by commit and record the expected tool
  inventory — `benchmarks/official-inventory-v1.yaml`, 58 tools across seven
  servers at `599dafc`, referenced rather than vendored and reported
  `unavailable` (not skipped) when the checkout is absent.
- [x] Turn the filesystem `read_media_file`/`move_file` case into permanent
  boundary ground truth — negative capability labels in both datasets.
- [x] Add per-tool positive and negative capability labels — 96 decisions over
  the 24 extracted tools.
- [x] Make benchmark reports show TP, FP, FN, TN, precision, recall, F1, and
  coverage per extractor shape and per rule — plus per capability, as three
  separate views with discovery reported first.
- [x] Keep the current tiny benchmark labelled as a development regression set —
  `split: development` with a stated purpose, carried into every result.

**Exit:** met. See §6.1. Every missed tool, unattributed capability, and
mis-fired finding is recorded as a `known_gap` naming the phase that closes it;
an unexplained miss fails the run, and so does a gap that no longer reproduces.

### P1 - Raise extraction coverage

- Support low-level Python `list_tools` plus `call_tool` dispatch patterns.
- Support TypeScript tool names/configs stored in variables and named handlers.
- Preserve exact handler ranges and evidence lines.
- Classify production, test, fixture, example, generated, and documentation
  sources before running security rules.
- Report unsupported registration constructs as coverage gaps.

**Exit:** at least 95% discovery on the supported, pinned official corpus, with
no cross-tool capability leakage.

### P2 - Attribute effects through helpers — **done (2026-08-28)**

- [x] Build a bounded, intra-repository call graph from each registered handler
  — `callgraph.py`, indexing Python functions by AST and TS/JS functions,
  arrows and class methods by balanced-delimiter scanning.
- [x] Propagate capabilities only through statically resolved calls — a name
  resolves to exactly one definition or to none; an ambiguous name is never
  arbitrated.
- [x] Preserve the evidence chain — each inferred capability carries the helper
  it was found in, its location, and the call chain that reached it, and drops
  to `medium` confidence when it is indirect.
- [x] Stop at dynamic dispatch, reflection, unresolved imports, or configured
  depth — recorded in `Tool.unresolved_calls` and surfaced as an `UNKNOWN` row
  in the review packet.

Two refinements the corpus forced:

- **Guards contribute their mutations, not their checks.** `validatePath()`
  resolves a realpath to enforce an allow-list; charging every guarded tool with
  `filesystem.read` for it produced the only capability false positive P2 ever
  had. Read-only effects from a guard are dropped, mutating and outbound ones
  still propagate — a `checkAndPurge` that deletes is exactly what must not be
  lost.
- **The low-level dispatcher is split per branch.** A tool declared in
  `list_tools()` gets its own `match`/`if` branch out of `call_tool`, plus the
  shared prologue, and never a sibling's branch.

**Exit:** met. All nine memory-server tools resolve through
`KnowledgeGraphManager` to their read and write sinks, with zero false positives
across 51 negative labels — including 19 tools registered from one module tree
and 12 sharing a single dispatcher.

### P3 - Make rules context-aware — **done (2026-08-28)**

- [x] Teach arbitrary-path checks about explicit path validators — a guard is
  credited only when its body both canonicalizes (`realpath`, `path.resolve`,
  `os.path.abspath`) and bounds (`startsWith`, `commonpath`, `is_relative_to`,
  an allowed-directory list). Either half alone proves nothing.
- [x] Separate schema breadth from effective implementation constraints — the
  schema still says "any string"; the matrix now also says which guard bounds
  it, and `OP-002` reads that instead of assuming the worst.
- [x] Compare name, description, annotation, schema, and inferred capabilities
  as distinct evidence sources — the review packet's capability matrix carries
  an evidence status per cell and lists every contradiction with both sides.
- [x] Make suppressions structural and explainable — the exemption is scoped by
  parameter kind (a path guard does not excuse a URL) and is only ever granted
  on evidence found in the source. There is no way to allowlist a server, a
  package, or a tool name.

**Exit:** met. All ten guarded filesystem tools stopped firing `OP-002`, the one
genuinely unguarded input in the corpus (`trigger-url-elicitation`) still fires,
and a guarded tool whose `readOnlyHint` lies is still caught by `CP-001`.

### P4 - Build the review packet and diff — **done (2026-08-28)**

- [x] Emit the normalized capability matrix and evidence statuses — `review.py`,
  one row per tool/capability carrying `INFERRED`, `CONTRADICTED` or `UNKNOWN`,
  its evidence reference, and the guard constraining it.
- [x] Generate missing-evidence questions from `UNKNOWN` fields — each
  unresolved registration and unfollowed handler becomes a written question
  naming the tool, the location, and the evidence being requested.
- [x] Add version-to-version inventory and capability diffs — `mcp-audit review
  --baseline <saved.json>` reports added, removed, and capability-changed tools.
- [x] Keep CLI and JSON as thin renderers of the same engine result — the packet
  is a pure function of `AuditReport`; nothing is recomputed in a renderer.

Two guarantees the packet makes:

- **It never decides.** `status` is always `PENDING`, `reviewer` and `notes` are
  always empty, and the recommendation is one of the five §4 values.
  Incompleteness outranks a clean finding list, so anything unresolved
  recommends `NEEDS EVIDENCE`.
- **It never overstates its input.** `documentation` joined the evidence
  vocabulary, so a tree of prose about a server is labelled as such instead of
  being called `source`, and the score is withheld outright whenever a
  registration could not be resolved.

**Exit:** met. A documentation-only target reports `evidence: documentation`,
zero tools, and `NEEDS EVIDENCE`; a source-backed target with a lying
`readOnlyHint` reports the contradiction in the matrix and recommends
`RE-REVIEW REQUIRED`.

## 9. Explicitly deferred

Until P0-P3 meet their quality gates, do not prioritize:

- additional HTML themes or report animations;
- more CLI convenience commands;
- a universal security score;
- automatic blocking or CI policy gates;
- mandatory Docker execution of audited servers;
- broad CVE scanning that duplicates established dependency scanners;
- unconstrained LLM judgment as ground truth.

Runtime auditing can later be a separate, explicitly opt-in mode. It will need a
controlled sandbox, credentials, test cases, side-effect containment, and clear
statements that observed behavior is not exhaustive.

## 10. Next three reviewable changes (P0-P4 complete)

1. ~~**Official inventory benchmark:** pin selected official servers, label every
   registered tool, and expose discovery coverage failures.~~ Done — see §6.1.
2. ~~**Extractor coverage:** implement low-level Python dispatch and variable/named
   TypeScript registrations with regression fixtures.~~ Done — see §6.2.
3. ~~**Evidence-aware capability propagation:** add the bounded helper call
   graph, then make path findings validator-aware.~~ Done — see §6.3.

That holdout now exists and has been evaluated once - see §6.4. It found what a
validation split structurally cannot: discovery does not generalize (5.5%),
capability attribution produces nothing (0% recall), and finding precision
collapses (11.1%). It also caught a labelling error that a single dataset could
not have caught.

The next honest step follows from that result, and it is **not** to fix the gaps
it exposed. Fixing them against this corpus fits the engine to it. The order
is: build a second holdout first, then close the low-level TypeScript body gap,
decide what a capability claim should mean when the effect lives in a
third-party package, and re-examine every metadata-matching rule - starting with
TP-003's case sensitivity - then measure on the corpus that was never used to
choose.

It is worth stating plainly what §6.3's six-defect list and this section add up
to. The engine reached 100% on all three views of the validation split, and that
number turned out to describe the corpus rather than the engine. The measurement
apparatus was the thing worth building; the score it produced on the set it was
tuned against was not evidence of anything.

Both smaller items surfaced by the P0 labelling are also done: `fs.mkdir` maps
to `filesystem.write` and `fs.rename` to write plus delete, and the loader now
collects `.toml`/`.lock` so `RP-001` can actually read a `pyproject.toml`.

Each change should improve measured coverage or precision on the validation set.
No change should be justified only by a prettier report or a higher aggregate
score.

## 11. Research-handling rule

New papers should enter the project through a short evidence record:

- bibliographic identity and local source;
- dataset or implementation availability and license;
- threat or capability taxonomy contributed;
- what the experiment actually measures;
- which benchmark split or review question it can support;
- explicit limitations and claims the project must not inherit.

Articles are useful when they change a label schema, test case, evidence boundary,
or review question. Otherwise they belong in the Atlas as context, not in the
detection engine as another unvalidated signature.
