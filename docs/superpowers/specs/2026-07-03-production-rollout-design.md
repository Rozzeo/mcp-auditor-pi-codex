# mcp-auditor: Production Rollout Design

**Date:** 2026-07-03
**Goal:** office coworkers install mcp-auditor locally and vet MCP servers before connecting them.

## Locked Decisions

| Decision | Choice |
|---|---|
| Usage model | Local CLI per coworker (no central auditor, no CI gate) |
| Distribution | `pipx install git+https://github.com/Rozzeo/mcp-auditor` (private repo; coworkers need repo access + git auth) |
| Verdict semantics | Advisory report: findings + explanation + risk level; human decides. No binary SAFE/UNSAFE |
| Quality bar | Calibration benchmark on real servers before release; every FP on a legit server is a rule bug |
| Dev environment | Local `.venv` on Python 3.14 (`py -3.14`). Devcontainer (python:3.12) kept for VS Code work and one clean-room install test at release. System Python 3.9 untouched (275 packages in active use) |
| Repo | github.com/Rozzeo/mcp-auditor, private, branch `main` |

## Phase 1 — Foundation

Exit criterion: `pytest` fully green on 3.14, working tree clean.

1. Move `updater.py` (repo root) → `src/mcp_auditor/updater.py`; fix imports. This alone fixes all 9 test-collection errors.
2. Commit WIP in logical commits:
   - Threat Atlas: `atlas.py`, `encyclopedia.py`, `threats.yaml` + their tests
   - Intel pipeline: `intel/` + `test_intel.py`
   - New rules + malicious fixtures: modified `rules.py`/`signatures.yaml` + `tests/fixtures/*-server/` + `test_new_rules.py`
   - Updater + tests
   - Devcontainer config
3. `.gitignore` the SLR paper HTML (+ `_files/` dir) and local artifacts (`visual-plan.html`, `mcp-threat-encyclopedia.html`); delete stray root `SKILL.md` (misplaced find-skills meta-skill, non-functional at repo root). README cites arXiv 2503.23278 instead of committing the paper.

## Phase 2 — Calibration Benchmark

Exit criterion: zero unexplained findings on the legit corpus; benchmark frozen as regression tests.

1. Corpus: 10–15 real servers — official `modelcontextprotocol/servers` (filesystem, github, slack, memory, puppeteer, fetch…) + 3–5 popular community servers; plus the 5 malicious fixtures as true-positive controls.
2. Run audit on each; triage every finding: **TP** → keep; **FP** → fix rule/signature (never per-server hacks).
3. Freeze extracted tool-metadata snapshots (not full repos) into `tests/benchmark/` — offline, fast regression corpus. Future rule edits cannot silently break calibration.
4. **Report-quality caveat (from approach B):** during triage, read each report as a non-security coworker. Where "why dangerous / what to check manually" is weak, patch `encyclopedia.py`/`threats.yaml` entries pointwise. No wholesale report redesign.

## Phase 3 — Release

Exit criterion: coworker-ready install path proven from a clean environment.

1. README rewritten in clean UTF-8 (English): one-command install, quickstart (`mcp-audit <github-url>`), how to read the report, how to upgrade.
2. Clean-room test: fresh `python:3.12` container, `pipx install git+…`, audit one real server, confirm sane output.
3. Tag `v0.1.0`.

## Out of Scope (YAGNI)

PyPI publication, CI gate for company repos, shared office allow-list, HTML report export, runtime/dynamic analysis. Revisit after coworkers use v0.1.0.

## Risks

- **Private-repo install friction:** coworkers need GitHub accounts with repo access and local git auth. Mitigation: README covers auth setup; if friction proves high, revisit PyPI or a public repo later.
- **Benchmark drift:** real servers change upstream. Mitigation: frozen metadata snapshots keep tests deterministic; refresh deliberately, not implicitly.
