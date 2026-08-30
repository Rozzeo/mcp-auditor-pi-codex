# Roadmap — MCP Server Auditor (full vision)

**For:** Claude Code (context) / project planning
**Date:** 2026-06-26
**Relationship to MVP:** This file is the long-term plan. The vertical slice in
`MVP.md` is phase 1. Do NOT build anything here until the MVP
passes its acceptance criteria. This file exists so architectural decisions in
the MVP don't paint us into a corner.

---

## Threat landscape (why this product, grounded in 2026 reality)

The MCP ecosystem in 2026 is, in practitioner terms, a **supply-chain problem
first and a prompt-injection problem second.** Concrete signals shaping this tool:

- **Tool poisoning is the defining new category.** Prompt injection rides in
  user input; tool poisoning rides in the *metadata that arrives at boot* — tool
  descriptions and JSON Schema fields the model reads as instructions. Landmark
  CVEs: **MCPoison (CVE-2025-54136)** and **CurXecute (CVE-2025-54135)**.
- **Over-privileged tools** are a recognized audit target (academic work in 2026
  on auditing MCP servers for over-privileged tool capabilities).
- **Unauthenticated exposure at scale:** security researchers found hundreds of
  MCP servers exposed to the internet with zero authentication.
- **Ecosystem / supply-chain attacks:** poisoned config files enabling RCE in
  agent tooling, and large numbers of malicious "skills" in agent marketplaces.
- **Parasitic toolchain / implicit tool poisoning** are emerging research
  directions — attacks that chain through tool outputs, not just descriptions.

Implication for the product: the **signature set must stay fresh.** A static
checklist rots. The roadmap therefore includes a threat-intelligence feed.

## Architectural through-line (keep true across all phases)

One pure core, many thin surfaces:

```
audit(target) -> AuditReport     <-- the only place logic lives
   |-- CLI        (phase 1)
   |-- JSON out   (phase 1)
   |-- Web        (phase 3)
   |-- PDF report (phase 3)
   |-- CI badge   (phase 4)
```

Every phase must preserve: **static-only analysis (never execute targets)**,
explainable rule-based detection as the primary mechanism, and the stable
`AuditReport` data contract.

---

## Phase 1 — MVP (see `MVP.md`)

CLI. Local-path + GitHub-URL input. Static extractor for Python/JS/TS/manifest
MCP servers. Rule-based detection of tool poisoning + over-privilege. Score +
findings as terminal text and JSON. `--fail-on` for CI gating. Hand-maintained
`signatures.yaml`.

**Exit criterion:** all MVP acceptance criteria pass.

---

## Phase 2 — depth & dependency layer

- **Dependency-CVE layer.** Parse `package.json` / `requirements.txt` /
  `pyproject.toml`, query **GitHub Advisory API** and/or **OSV.dev** (both free,
  JSON, public). Add findings in a new `category: "dependency"`. This is a bonus
  layer, explicitly NOT the moat — keep it secondary to the MCP-specific rules.
- **LLM second-opinion layer (optional, gated).** For borderline TP-001 / TP-004
  cases only, send the suspicious description to an LLM for a yes/no judgment.
  Cache by content hash so repeated audits cost ~0 tokens. Must be optional and
  off by default; rules remain primary and explainable.
- **Expanded rule set:** parasitic-toolchain / implicit tool-poisoning patterns
  (instructions that arrive via tool *outputs* and chained calls), prompt-leak
  patterns, and broader over-privilege schema heuristics.
- **Confidence per finding:** add a `confidence` field so rule hits and
  LLM-assisted hits are distinguishable.

## Phase 3 — surfaces for humans

- **Web surface** (Cloudflare Pages + a serverless function calling the same
  `audit()` core): paste a URL, see score + findings. Thin wrapper only — no
  logic duplication.
- **Downloadable report:** PDF + JSON export of an `AuditReport`, suitable for
  compliance / sharing.
- **Diff mode:** compare two audits of the same server over time (did a new
  release introduce a poisoned tool?). This leans on the temporal-analysis angle.

## Phase 4 — automation & ecosystem

- **CI/CD recipe + "MCP-audited" badge.** A GitHub Action that runs the CLI with
  `--fail-on` and publishes a status badge. Turns one-off visits into a standing
  integration.
- **Agent-native invocation.** Document and harden the CLI/JSON contract so other
  agents can call it as a tool in their own pipelines (the tool auditing the
  tools).

## Phase 5 — living threat intelligence (the anti-rot system)

Goal: signatures update themselves; a human curates quality (human-in-the-loop).

- **Automated feeds (machine):**
  - **arXiv API** — fresh academic papers on MCP attacks (tool poisoning,
    over-privilege auditing, parasitic toolchains). Pull, filter by keywords,
    surface candidate new patterns.
  - **GitHub Advisory API / NVD API / OSV.dev** — new CVEs touching MCP SDKs and
    common dependencies.
- **Curation (human):** **ResearchRabbit has no public API and is not part of the
  automated pipeline.** Use it manually as a personal literature-mapping tool:
  review new papers weekly, decide which patterns are worth encoding, then add
  them to `signatures.yaml`. Machine fetches; human approves what becomes a rule.
- **Signature versioning:** version the signature set (like antivirus
  definitions) so audits are reproducible against a known rule version, and so
  users can pin or update.

---

## Non-negotiables across the whole roadmap

- Static analysis only — never execute, import, install, or eval a target.
- Rule-based detection stays the primary, explainable mechanism; LLM is always
  secondary, optional, cached.
- The `AuditReport` contract is stable; new data is additive (new fields/
  categories), never breaking.
- Free-tier, solo-dev economics: managed services, generous free tiers, real
  cost limited to a domain and any optional LLM tokens.

## Explicitly deferred / not planned

- Running or sandboxing target servers to observe runtime behavior (large scope,
  real infra cost — only consider far past phase 5, if ever).
- Accounts/multi-tenant SaaS billing — not until there's demand evidence.
- Anything that duplicates Dependabot as a primary feature.
