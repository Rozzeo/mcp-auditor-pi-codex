# External holdout v1 — frozen first-run result

Evaluation date: 2026-08-29  
Dataset SHA-256: `2332ad7d11c68c9527c6c98d28611d2457778c5832e18391f25e70cc600e9989`  
Protocol: source labels frozen before the first auditor run; no detector tuning
or label correction was performed after evaluation.

## Pinned corpus

| Repository | Commit |
|---|---|
| `sooperset/mcp-atlassian` | `04511d24ac792db240fc105e5ed0759ec82f4df8` |
| `tavily-ai/tavily-mcp` | `248dc9e3e385305ad3281120284ff662af4b5940` |
| `zcaceres/fetch-mcp` | `1ddb1a59cb09a2d38e759f2d7a97829680cbe514` |

The benchmark runner verified all three checkout HEADs before analysis.

## Result

| View | First-run result |
|---|---|
| Tool discovery | **5.5% (6/109)** |
| Capability classification | precision n/a, recall **0%** (0 TP, 0 FP, 116 FN, 1083 TN) |
| Findings | precision **11.1%**, recall **20%**, FPR **80%** (1 TP, 8 FP, 4 FN, 2 TN) |

Discovery by registration shape:

| Shape | Coverage |
|---|---|
| `py-fastmcp-mounted-namespaces` | 0/98 (0%) |
| `ts-sdk-server-tool-array` | 0/5 (0%) |
| `ts-lowlevel-list-tools-dispatch` | 6/6 (100%) |

Capability false negatives comprise 109 outbound-network decisions and seven
filesystem/process decisions. The six discovered Fetch tools were assigned no
labelled positive capability.

Finding outcomes:

| Rule | TP | FP | FN | TN |
|---|---:|---:|---:|---:|
| `CI-001` | 0 | 0 | 1 | 0 |
| `CR-001` | 0 | 1 | 0 | 0 |
| `ME-001` | 1 | 0 | 0 | 1 |
| `OP-002` | 0 | 6 | 3 | 0 |
| `RP-001` | 0 | 1 | 0 | 1 |

## What failed

- FastMCP child mounts were extracted under raw decorator names rather than the
  observable `jira_*` / `confluence_*` namespaces. Two raw `search` tools also
  collide when reduced to a name-keyed inventory.
- Tavily's typed `Tool[]` registration array was not discovered.
- The low-level Fetch inventory was discovered, but dispatcher-to-helper
  capability attribution found none of the labelled network, filesystem, or
  process behavior.
- Six Fetch URL findings were false positives because effective runtime URL
  validation was not carried through the handler/helper boundary.
- Tavily's three caller-controlled URL surfaces were false negatives.
- The YouTube `yt-dlp` process sink was a `CI-001` false negative.
- A documented placeholder API key caused a `CR-001` false positive.
- `pnpm-lock.yaml` was not recognized, causing an `RP-001` false positive.

This result is immutable evidence for v1. Any future fixes are measured against
a separate regression/validation dataset; they do not rewrite this holdout run.
