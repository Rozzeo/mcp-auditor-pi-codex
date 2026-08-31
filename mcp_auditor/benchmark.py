"""Ground-truth evaluation for the static detection pipeline.

Risk scoring and detector quality answer different questions.  The report score
weights observed findings by severity; this module instead compares explicitly
labelled decisions against what the engine actually produced.

Three independent views are measured, because a clean finding count on a corpus
the extractor never parsed is an incomplete result, not a safe one:

* **discovery**   - did the extractor find the tools a reviewer labelled?
* **capability**  - was each tool given the right capabilities, and denied the
  ones it must not inherit from a sibling handler?
* **findings**    - did the rules fire where a reviewer said they should?

Every known shortcoming has to be written down as a ``known_gap`` with a reason.
An unexplained miss fails the run, and so does a gap whose excuse has gone stale
because the engine now handles it.
"""

from __future__ import annotations

import os
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from .capabilities import CAPABILITIES, infer_all
from .extractor import extract
from .loader import load_local
from .rules import load_signatures, run_rules
from .scorer import score_findings


# A benchmark split is a promise about how the data may be used: development
# sets are debugged against, validation sets choose changes, and the holdout is
# frozen.  Recording it stops a tiny regression set from being quoted as
# production accuracy.
SPLITS = ("development", "validation", "holdout")

_OUTCOME_NAMES = ("tp", "fp", "fn", "tn")


class BenchmarkError(ValueError):
    """Raised when a benchmark dataset is malformed."""


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _metrics(counts: dict[str, int]) -> dict[str, int | float | None]:
    tp, fp = counts["tp"], counts["fp"]
    fn, tn = counts["fn"], counts["tn"]
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "specificity": _ratio(tn, tn + fp),
        "false_positive_rate": _ratio(fp, fp + tn),
        "f1": (
            round(2 * precision * recall / (precision + recall), 6)
            if precision is not None and recall is not None and precision + recall
            else None
        ),
        "accuracy": _ratio(tp + tn, tp + fp + fn + tn),
    }


def _discovery_metrics(counts: dict[str, Any]) -> dict[str, Any]:
    expected = counts["expected"]
    matched = counts["matched"]
    return {
        "expected": expected,
        "extracted": counts["extracted"],
        "matched": matched,
        "missing": sorted(counts["missing"]),
        "unexpected": sorted(counts["unexpected"]),
        "coverage": _ratio(matched, expected),
    }


def _new_counts() -> dict[str, int]:
    return {name: 0 for name in _OUTCOME_NAMES}


def _new_discovery() -> dict[str, Any]:
    return {"expected": 0, "extracted": 0, "matched": 0, "missing": set(), "unexpected": set()}


def _read_dataset(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise BenchmarkError(f"Cannot read benchmark dataset {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise BenchmarkError("Benchmark dataset must contain a 'cases' list")
    split = data.get("split", "development")
    if split not in SPLITS:
        raise BenchmarkError(f"Unknown benchmark split {split!r}; use one of {', '.join(SPLITS)}")
    return data


def _resolve_corpus(
    dataset: dict[str, Any],
    dataset_file: Path,
    corpus_root: str | Path | None,
) -> dict[str, Any] | None:
    """Locate the pinned upstream checkout a validation dataset points at.

    The corpus is referenced, never vendored: a dataset records the repository
    and commit, and the reviewer materializes that checkout locally.  When it is
    absent the cases are reported unavailable rather than quietly skipped, so a
    missing corpus can never read as a passing benchmark.
    """
    corpus = dataset.get("corpus")
    if corpus is None:
        return None
    if not isinstance(corpus, dict):
        raise BenchmarkError("Dataset 'corpus' must be a mapping")

    root = corpus_root or os.environ.get("MCP_AUDITOR_CORPUS_ROOT") or corpus.get("root")
    resolved = (dataset_file.parent / Path(root)).resolve() if root else None
    repositories = corpus.get("repositories")
    if repositories is not None:
        if not isinstance(repositories, list) or not repositories:
            raise BenchmarkError("Dataset corpus.repositories must be a non-empty list")
        resolved_repositories = []
        for repository in repositories:
            if not isinstance(repository, dict):
                raise BenchmarkError("Each corpus repository must be a mapping")
            path = repository.get("path")
            repo = repository.get("repo")
            commit = repository.get("commit")
            if not all(isinstance(value, str) and value for value in (path, repo, commit)):
                raise BenchmarkError("Each corpus repository needs path, repo, and commit")
            checkout = (resolved / path).resolve() if resolved else None
            head = _read_git_head(checkout) if checkout and checkout.is_dir() else None
            status = (
                "missing"
                if head is None
                else "verified"
                if head.lower() == commit.lower()
                else "commit-mismatch"
            )
            resolved_repositories.append({
                "path": path,
                "repo": repo,
                "commit": commit,
                "head": head,
                "status": status,
            })
        return {
            "repo": None,
            "commit": None,
            "root": str(resolved) if resolved else None,
            "repositories": resolved_repositories,
            "available": all(item["status"] == "verified" for item in resolved_repositories),
        }
    return {
        "repo": corpus.get("repo"),
        "commit": corpus.get("commit"),
        "root": str(resolved) if resolved else None,
        "available": bool(resolved and resolved.is_dir()),
    }


def _read_git_head(checkout: Path) -> str | None:
    """Read a checkout identity without executing code from the target repo."""
    git_dir = checkout / ".git"
    try:
        head = (git_dir / "HEAD").read_text(encoding="ascii").strip()
    except OSError:
        return None
    if not head.startswith("ref: "):
        return head or None
    ref = head.removeprefix("ref: ")
    try:
        return (git_dir / Path(ref)).read_text(encoding="ascii").strip() or None
    except OSError:
        try:
            packed = (git_dir / "packed-refs").read_text(encoding="ascii").splitlines()
        except OSError:
            return None
        suffix = f" {ref}"
        return next((line.split(" ", 1)[0] for line in packed if line.endswith(suffix)), None)


def _validate_case(raw_case: Any) -> tuple[str, str]:
    if not isinstance(raw_case, dict):
        raise BenchmarkError("Each benchmark case must be a mapping")
    case_id = raw_case.get("id")
    target_value = raw_case.get("target")
    if not isinstance(case_id, str) or not case_id.strip():
        raise BenchmarkError("Each benchmark case needs a non-empty id")
    if not isinstance(target_value, str) or not target_value.strip():
        raise BenchmarkError(f"Case {case_id!r} needs a local target path")
    if not any(
        raw_case.get(key)
        for key in ("labels", "expected_tools", "capabilities", "capability_defaults")
    ):
        raise BenchmarkError(
            f"Case {case_id!r} needs at least one of expected_tools, capabilities, or labels"
        )
    return case_id, target_value


def _expected_tools(case_id: str, raw_case: dict[str, Any]) -> list[str]:
    expected = raw_case.get("expected_tools") or []
    if not isinstance(expected, list) or any(not isinstance(n, str) or not n for n in expected):
        raise BenchmarkError(f"Case {case_id!r} expected_tools must be a list of tool names")
    return expected


def _coverage_gaps(case_id: str, raw_case: dict[str, Any]) -> dict[str, str]:
    gaps = raw_case.get("coverage_gaps") or {}
    if not isinstance(gaps, dict) or any(not isinstance(v, str) or not v for v in gaps.values()):
        raise BenchmarkError(
            f"Case {case_id!r} coverage_gaps must map a tool name to a written reason"
        )
    return gaps


def _outcome(expected: bool, observed: bool) -> str:
    if expected:
        return "tp" if observed else "fn"
    return "fp" if observed else "tn"


def evaluate_benchmark(
    dataset_path: str | Path,
    signatures_path: str | Path | None = None,
    corpus_root: str | Path | None = None,
) -> dict[str, Any]:
    """Evaluate labelled discovery/capability/rule decisions without executing code."""
    dataset_file = Path(dataset_path).resolve()
    dataset = _read_dataset(dataset_file)
    signatures = load_signatures(signatures_path)
    corpus = _resolve_corpus(dataset, dataset_file, corpus_root)

    finding_counts = _new_counts()
    capability_counts = _new_counts()
    discovery = _new_discovery()
    per_rule: dict[str, dict[str, int]] = defaultdict(_new_counts)
    per_capability: dict[str, dict[str, int]] = defaultdict(_new_counts)
    per_shape: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"findings": _new_counts(), "capabilities": _new_counts(), "discovery": _new_discovery()}
    )
    gaps: list[dict[str, Any]] = []
    unexplained = {"discovery": 0, "capabilities": 0, "findings": 0, "unlabelled": 0}
    unlabelled: list[dict[str, Any]] = []
    case_results: list[dict[str, Any]] = []
    unavailable = 0

    for raw_case in dataset["cases"]:
        case_id, target_value = _validate_case(raw_case)
        shape = raw_case.get("shape") or "unspecified"
        shape_bucket = per_shape[shape]

        base = Path(corpus["root"]) if corpus and corpus["root"] else dataset_file.parent
        target = (base / target_value).resolve()
        if corpus is not None and not corpus["available"]:
            unavailable += 1
            case_results.append({
                "id": case_id,
                "target": target_value,
                "shape": shape,
                "status": "unavailable",
                "message": "Pinned corpus checkout not found; nothing was evaluated.",
            })
            continue

        files = load_local(str(target))
        extraction = extract(files)
        infer_all(extraction.tools, files=files)
        findings = run_rules(
            extraction.tools,
            signatures,
            has_auth_signal=bool(raw_case.get("has_auth_signal", True)),
            files=files,
        )

        by_name = {tool.name: tool for tool in extraction.tools}
        expected_tools = _expected_tools(case_id, raw_case)
        coverage_gaps = _coverage_gaps(case_id, raw_case)
        case_discovery = None

        if expected_tools:
            missing = [name for name in expected_tools if name not in by_name]
            unexpected = [name for name in by_name if name not in set(expected_tools)]
            case_discovery = _discovery_metrics({
                "expected": len(expected_tools),
                "extracted": len(by_name),
                "matched": len(expected_tools) - len(missing),
                "missing": missing,
                "unexpected": unexpected,
            })
            for bucket in (discovery, shape_bucket["discovery"]):
                bucket["expected"] += len(expected_tools)
                bucket["extracted"] += len(by_name)
                bucket["matched"] += len(expected_tools) - len(missing)
                bucket["missing"].update(missing)
                bucket["unexpected"].update(unexpected)

            for name in sorted(set(missing) | set(unexpected)):
                reason = coverage_gaps.get(name)
                if reason is None:
                    unexplained["discovery"] += 1
                else:
                    gaps.append({
                        "case": case_id,
                        "kind": "discovery",
                        "target": name,
                        "reason": reason,
                        "status": "open",
                    })
            for name, reason in coverage_gaps.items():
                if name not in set(missing) | set(unexpected):
                    gaps.append({
                        "case": case_id,
                        "kind": "discovery",
                        "target": name,
                        "reason": reason,
                        "status": "resolved",
                    })

        capability_decisions = _score_capabilities(
            case_id,
            raw_case,
            by_name,
            counters=(capability_counts, shape_bucket["capabilities"]),
            per_capability=per_capability,
            gaps=gaps,
            unexplained=unexplained,
        )
        finding_decisions = _score_findings(
            case_id,
            raw_case,
            findings,
            counters=(finding_counts, shape_bucket["findings"]),
            per_rule=per_rule,
            gaps=gaps,
            unexplained=unexplained,
            unlabelled=unlabelled,
        )

        case_results.append({
            "id": case_id,
            "target": target_value,
            "shape": shape,
            "status": "evaluated",
            "tools_analyzed": len(extraction.tools),
            "risk_score": score_findings(findings),
            "discovery": case_discovery,
            "capabilities": capability_decisions,
            "labels": finding_decisions,
        })

    return {
        "dataset": dataset.get("name", dataset_file.stem),
        "dataset_version": dataset.get("version"),
        "split": dataset.get("split", "development"),
        "purpose": dataset.get("purpose"),
        "signature_version": signatures.get("version"),
        "corpus": corpus,
        "metrics": _metrics(finding_counts),
        "per_rule": {rule: _metrics(counts) for rule, counts in sorted(per_rule.items())},
        "discovery": _discovery_metrics(discovery),
        "capability_metrics": _metrics(capability_counts),
        "per_capability": {cap: _metrics(counts) for cap, counts in sorted(per_capability.items())},
        "per_shape": {
            shape: {
                "discovery": _discovery_metrics(buckets["discovery"]),
                "capabilities": _metrics(buckets["capabilities"]),
                "findings": _metrics(buckets["findings"]),
            }
            for shape, buckets in sorted(per_shape.items())
        },
        "gaps": gaps,
        "unlabelled_findings": unlabelled,
        "unexplained": unexplained,
        "unavailable_cases": unavailable,
        "cases": case_results,
    }


def _score_capabilities(
    case_id: str,
    raw_case: dict[str, Any],
    by_name: dict[str, Any],
    *,
    counters: tuple[dict[str, int], ...],
    per_capability: dict[str, dict[str, int]],
    gaps: list[dict[str, Any]],
    unexplained: dict[str, int],
) -> list[dict[str, Any]]:
    """Score per-tool positive AND negative capability labels.

    Negative labels carry the weight here: they are what proves a handler did
    not inherit a sibling's sink.  A benchmark holding only positives can
    measure recall but says nothing about false positives.
    """
    labels = raw_case.get("capabilities") or []
    if not isinstance(labels, list):
        raise BenchmarkError(f"Case {case_id!r} capabilities must be a list")

    defaults = raw_case.get("capability_defaults") or {}
    if not isinstance(defaults, dict):
        raise BenchmarkError(f"Case {case_id!r} capability_defaults must be a mapping")
    if defaults and not raw_case.get("expected_tools"):
        raise BenchmarkError(f"Case {case_id!r} capability_defaults require expected_tools")
    for capability, expected in defaults.items():
        if capability not in CAPABILITIES:
            raise BenchmarkError(
                f"Case {case_id!r} default uses unknown capability {capability!r}; "
                f"the policy vocabulary is {', '.join(sorted(CAPABILITIES))}"
            )
        if not isinstance(expected, bool):
            raise BenchmarkError(
                f"Case {case_id!r} capability_defaults values must be true or false"
            )

    explicit_keys = {
        (label.get("tool"), label.get("capability"))
        for label in labels
        if isinstance(label, dict)
    }
    expanded = [
        {"tool": tool, "capability": capability, "expected": expected}
        for tool in raw_case.get("expected_tools", [])
        for capability, expected in defaults.items()
        if (tool, capability) not in explicit_keys
    ]
    labels = [*expanded, *labels]

    seen: set[tuple[str, str]] = set()
    decisions: list[dict[str, Any]] = []
    for label in labels:
        if not isinstance(label, dict):
            raise BenchmarkError(f"Case {case_id!r} contains a non-mapping capability label")
        tool = label.get("tool")
        capability = label.get("capability")
        expected = label.get("expected")
        if not isinstance(tool, str) or not tool:
            raise BenchmarkError(f"Case {case_id!r} capability label needs a tool")
        if capability not in CAPABILITIES:
            raise BenchmarkError(
                f"Case {case_id!r} label uses unknown capability {capability!r}; "
                f"the policy vocabulary is {', '.join(sorted(CAPABILITIES))}"
            )
        if not isinstance(expected, bool):
            raise BenchmarkError(f"Case {case_id!r} capability label expected must be true or false")
        key = (tool, capability)
        if key in seen:
            raise BenchmarkError(f"Case {case_id!r} duplicates capability label {tool}/{capability}")
        seen.add(key)

        found = by_name.get(tool)
        observed = bool(found) and any(c.capability == capability for c in found.capabilities)
        outcome = _outcome(expected, observed)
        for counter in counters:
            counter[outcome] += 1
        per_capability[capability][outcome] += 1

        reason = label.get("known_gap")
        if reason is not None:
            gaps.append({
                "case": case_id,
                "kind": "capability",
                "target": f"{tool}:{capability}",
                "reason": reason,
                "status": "open" if outcome in ("fp", "fn") else "resolved",
            })
        elif outcome in ("fp", "fn"):
            unexplained["capabilities"] += 1

        decisions.append({
            "tool": tool,
            "capability": capability,
            "expected": expected,
            "observed": observed,
            "outcome": outcome,
        })
    return decisions


def _score_findings(
    case_id: str,
    raw_case: dict[str, Any],
    findings: list[Any],
    *,
    counters: tuple[dict[str, int], ...],
    per_rule: dict[str, dict[str, int]],
    gaps: list[dict[str, Any]],
    unexplained: dict[str, int],
    unlabelled: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    labels = raw_case.get("labels") or []
    if not isinstance(labels, list):
        raise BenchmarkError(f"Case {case_id!r} labels must be a list")

    actual = {(finding.id, finding.tool_name) for finding in findings}
    seen: set[tuple[str, str | None]] = set()
    decisions: list[dict[str, Any]] = []
    for label in labels:
        if not isinstance(label, dict):
            raise BenchmarkError(f"Case {case_id!r} contains a non-mapping label")
        rule = label.get("rule")
        tool = label.get("tool")
        expected = label.get("expected")
        if not isinstance(rule, str) or not rule:
            raise BenchmarkError(f"Case {case_id!r} label needs a rule")
        if tool is not None and not isinstance(tool, str):
            raise BenchmarkError(f"Case {case_id!r} label tool must be a string or null")
        if not isinstance(expected, bool):
            raise BenchmarkError(f"Case {case_id!r} label expected must be true or false")
        key = (rule, tool)
        if key in seen:
            raise BenchmarkError(f"Case {case_id!r} duplicates label {rule}/{tool}")
        seen.add(key)

        observed = key in actual
        outcome = _outcome(expected, observed)
        for counter in counters:
            counter[outcome] += 1
        per_rule[rule][outcome] += 1

        reason = label.get("known_gap")
        if reason is not None:
            gaps.append({
                "case": case_id,
                "kind": "finding",
                "target": f"{rule}:{tool}",
                "reason": reason,
                "status": "open" if outcome in ("fp", "fn") else "resolved",
            })
        elif outcome in ("fp", "fn"):
            unexplained["findings"] += 1

        decisions.append({
            "rule": rule,
            "tool": tool,
            "expected": expected,
            "observed": observed,
            "outcome": outcome,
        })

    # Precision computed over a subset of what the engine emitted is not
    # precision. Anything it reported that nobody ruled on is surfaced rather
    # than dropped. It only *fails* the run for a case that scores findings at
    # all: a case labelling capabilities alone claims nothing about findings,
    # but one that rules on some of them has to rule on the rest.
    for rule, tool in sorted(actual - seen, key=lambda pair: (pair[0], pair[1] or "")):
        unlabelled.append({"case": case_id, "rule": rule, "tool": tool})
        if labels:
            unexplained["unlabelled"] += 1
    return decisions


def benchmark_failed(result: dict[str, Any]) -> bool:
    """True when the run should be treated as a failure.

    A miss fails unless it was written down as a ``known_gap``.  A gap that no
    longer reproduces also fails: a stale excuse hides real regressions, so it
    has to be deleted from the dataset deliberately.
    """
    if result.get("unavailable_cases"):
        return True
    if any(gap["status"] == "resolved" for gap in result.get("gaps", [])):
        return True
    return any(result.get("unexplained", {}).values())
