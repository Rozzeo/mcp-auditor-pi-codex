"""The frozen record of the second holdout.

`external-holdout-v2` was built before the namespace-mount, TP-003 and
indirect-tool-array changes, and evaluated once after them. It is the only
evidence that those changes do something on code they were not written against;
the first holdout cannot say so, because it is what they were written against.

These numbers are a record, not a target. Changing the engine to move them fits
it to this corpus, and a third holdout would be needed before the next round of
work could claim anything.
"""

import os
from pathlib import Path

import pytest
import yaml

from mcp_auditor.benchmark import evaluate_benchmark


HOLDOUT = Path(__file__).parents[1] / "benchmarks" / "external-holdout-v2.yaml"

PINNED_COMMITS = {
    "figma-context-mcp": "c083d65c7e002923e7cb98f4e3bdafb105e90f6d",
    "chroma-mcp": "98ff67589bdcc31b730a5415ff9529433f949077",
    "mcp-playwright": "2349c2891e7c499c8c07b7d78c7f3fb4c797a1da",
}

needs_corpus = pytest.mark.skipif(
    not os.environ.get("MCP_AUDITOR_HOLDOUT2_ROOT"),
    reason="holdout corpus is referenced, not vendored; set MCP_AUDITOR_HOLDOUT2_ROOT",
)


def _result():
    return evaluate_benchmark(HOLDOUT, corpus_root=os.environ["MCP_AUDITOR_HOLDOUT2_ROOT"])


def test_it_is_a_holdout_pinned_outside_the_other_splits():
    data = yaml.safe_load(HOLDOUT.read_text(encoding="utf-8"))
    text = HOLDOUT.read_text(encoding="utf-8")

    assert data["split"] == "holdout"
    assert sum(len(case["expected_tools"]) for case in data["cases"]) == 48
    for commit in PINNED_COMMITS.values():
        assert commit in text


@needs_corpus
def test_the_discovery_work_generalized():
    """95.8% on servers the changes were not written against, against 5.5% on
    the first holdout before them. `mcp-playwright` builds its descriptor array
    in a factory in another module, and all 33 of its tools resolve."""
    result = _result()
    per_case = {case["id"]: case["discovery"] for case in result["cases"]}

    assert (result["discovery"]["matched"], result["discovery"]["expected"]) == (46, 48)
    assert per_case["mcp-playwright"]["matched"] == 33
    assert per_case["chroma-mcp"]["matched"] == 13
    assert result["discovery"]["unexpected"] == []


@needs_corpus
def test_the_registration_shape_that_was_not_addressed_still_misses():
    """Figma writes `registerTool(getFigmaDataTool.name, ...)` - the name is a
    property read off an imported object. No change targeted that, and it is
    still 0/2. Recorded, not fixed: fixing it now would be fitting to this
    corpus."""
    per_case = {case["id"]: case["discovery"] for case in _result()["cases"]}

    assert per_case["figma-context-mcp"]["matched"] == 0


@needs_corpus
def test_capability_attribution_still_generalizes_to_nothing():
    """Unchanged from the first holdout, and unaddressed by this round of work.
    It claims nothing rather than claiming something wrong."""
    capability = _result()["capability_metrics"]

    assert (capability["tp"], capability["fp"]) == (0, 0)


@needs_corpus
def test_finding_precision_after_the_rule_fix():
    """78.6%, against 11.1% on the first holdout before the changes. TP-003 -
    which supplied 48 false positives there - does not fire here at all.

    Adjudicated after the run; every verdict is checkable against the source.
    """
    result = _result()
    findings = result["metrics"]

    assert (findings["tp"], findings["fp"]) == (11, 3)
    assert findings["precision"] == 0.785714
    assert "TP-003" not in result["per_rule"]
    assert result["unlabelled_findings"] == []


@needs_corpus
def test_a_known_defect_reproduced_independently():
    """RP-001 fires on Figma because it ships a pnpm-lock.yaml, which the
    lockfile list does not recognize - the same false positive the first holdout
    found on a different repository. Left unfixed on purpose."""
    per_rule = _result()["per_rule"]

    assert (per_rule["RP-001"]["tp"], per_rule["RP-001"]["fp"]) == (0, 1)
