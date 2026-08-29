"""P0 ground-truth tests: discovery coverage, capability labels, shapes, gaps.

These cover the benchmark's job of *measuring* the engine, not the accuracy of
the engine itself. Datasets are built inline so the expectations stay readable
and independent of whichever pinned corpus happens to be on disk.
"""

import os
from pathlib import Path

import pytest
import yaml

from mcp_auditor.benchmark import BenchmarkError, benchmark_failed, evaluate_benchmark
from mcp_auditor.capabilities import CAPABILITIES


FIXTURE = Path(__file__).parent / "fixtures" / "official-filesystem-register-tools.ts"


def _dataset(tmp_path: Path, cases: list, **top) -> Path:
    payload = {"version": 2, "name": "inline", "cases": cases, **top}
    path = tmp_path / "dataset.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


def test_discovery_coverage_reports_tools_the_extractor_missed(tmp_path):
    dataset = _dataset(tmp_path, [{
        "id": "filesystem-excerpt",
        "target": str(FIXTURE),
        "expected_tools": ["read_media_file", "move_file", "list_allowed_directories"],
    }])

    result = evaluate_benchmark(dataset)

    assert result["discovery"]["expected"] == 3
    assert result["discovery"]["matched"] == 2
    assert result["discovery"]["missing"] == ["list_allowed_directories"]
    assert result["discovery"]["unexpected"] == []
    assert result["discovery"]["coverage"] == pytest.approx(2 / 3)


def test_discovery_reports_tools_the_extractor_invented(tmp_path):
    dataset = _dataset(tmp_path, [{
        "id": "filesystem-excerpt",
        "target": str(FIXTURE),
        "expected_tools": ["read_media_file"],
    }])

    result = evaluate_benchmark(dataset)

    assert result["discovery"]["unexpected"] == ["move_file"]


def test_capability_labels_score_positive_and_negative_cases(tmp_path):
    dataset = _dataset(tmp_path, [{
        "id": "boundary",
        "target": str(FIXTURE),
        "expected_tools": ["read_media_file", "move_file"],
        "capabilities": [
            # move_file really does mutate the filesystem.
            {"tool": "move_file", "capability": "filesystem.delete", "expected": True},
            # The handler-boundary regression: read_media_file must not inherit it.
            {"tool": "read_media_file", "capability": "filesystem.delete", "expected": False},
        ],
    }])

    result = evaluate_benchmark(dataset)

    assert result["capability_metrics"]["tp"] == 1
    assert result["capability_metrics"]["tn"] == 1
    assert result["capability_metrics"]["fp"] == 0
    assert result["capability_metrics"]["fn"] == 0
    assert result["per_capability"]["filesystem.delete"]["tp"] == 1


def test_capability_defaults_cover_each_tool_and_explicit_labels_override(tmp_path):
    dataset = _dataset(tmp_path, [{
        "id": "boundary",
        "target": str(FIXTURE),
        "expected_tools": ["read_media_file", "move_file"],
        "capability_defaults": {
            "filesystem.read": False,
            "filesystem.delete": False,
        },
        "capabilities": [
            {"tool": "read_media_file", "capability": "filesystem.read", "expected": True},
            {"tool": "move_file", "capability": "filesystem.delete", "expected": True},
        ],
    }])

    result = evaluate_benchmark(dataset)
    decisions = {
        (item["tool"], item["capability"]): item
        for item in result["cases"][0]["capabilities"]
    }

    assert len(decisions) == 4
    assert decisions[("read_media_file", "filesystem.read")]["expected"] is True
    assert decisions[("move_file", "filesystem.read")]["expected"] is False
    assert decisions[("read_media_file", "filesystem.delete")]["expected"] is False
    assert decisions[("move_file", "filesystem.delete")]["expected"] is True
    assert result["capability_metrics"]["tp"] == 2
    assert result["capability_metrics"]["tn"] == 2


def test_capability_defaults_require_expected_tools(tmp_path):
    dataset = _dataset(tmp_path, [{
        "id": "boundary",
        "target": str(FIXTURE),
        "capability_defaults": {"filesystem.read": False},
    }])

    with pytest.raises(BenchmarkError, match="expected_tools"):
        evaluate_benchmark(dataset)


def test_capability_label_for_an_unextracted_tool_is_a_false_negative(tmp_path):
    dataset = _dataset(tmp_path, [{
        "id": "boundary",
        "target": str(FIXTURE),
        "expected_tools": ["read_media_file", "move_file", "write_file"],
        "capabilities": [
            {"tool": "write_file", "capability": "filesystem.write", "expected": True},
        ],
    }])

    result = evaluate_benchmark(dataset)

    assert result["capability_metrics"]["fn"] == 1


def test_metrics_are_broken_down_per_extractor_shape(tmp_path):
    dataset = _dataset(tmp_path, [{
        "id": "boundary",
        "target": str(FIXTURE),
        "shape": "ts-register-tool-literal",
        "expected_tools": ["read_media_file", "move_file"],
    }])

    result = evaluate_benchmark(dataset)

    shape = result["per_shape"]["ts-register-tool-literal"]
    assert shape["discovery"]["expected"] == 2
    assert shape["discovery"]["coverage"] == 1.0


def test_split_and_purpose_travel_with_the_result(tmp_path):
    dataset = _dataset(
        tmp_path,
        [{
            "id": "boundary",
            "target": str(FIXTURE),
            "expected_tools": ["read_media_file", "move_file"],
        }],
        split="development",
        purpose="Development regression set, not evidence of production accuracy.",
    )

    result = evaluate_benchmark(dataset)

    assert result["split"] == "development"
    assert result["purpose"].startswith("Development regression set")


def test_unknown_split_is_rejected(tmp_path):
    dataset = _dataset(tmp_path, [{"id": "a", "target": str(FIXTURE)}], split="production")

    with pytest.raises(BenchmarkError, match="split"):
        evaluate_benchmark(dataset)


def test_a_case_needs_labels_or_expected_tools(tmp_path):
    dataset = _dataset(tmp_path, [{"id": "empty", "target": str(FIXTURE)}])

    with pytest.raises(BenchmarkError, match="expected_tools"):
        evaluate_benchmark(dataset)


def test_missing_corpus_makes_cases_unavailable_rather_than_passing(tmp_path):
    dataset = _dataset(
        tmp_path,
        [{"id": "filesystem", "target": "src/filesystem", "expected_tools": ["read_file"]}],
        corpus={"repo": "https://example.invalid/servers", "commit": "0" * 40},
    )

    result = evaluate_benchmark(dataset, corpus_root=tmp_path / "absent")

    assert result["corpus"]["available"] is False
    assert result["cases"][0]["status"] == "unavailable"
    assert result["discovery"]["expected"] == 0
    assert benchmark_failed(result) is True


def test_corpus_root_resolves_case_targets(tmp_path):
    root = tmp_path / "corpus"
    (root / "src" / "filesystem").mkdir(parents=True)
    (root / "src" / "filesystem" / "index.ts").write_text(
        FIXTURE.read_text(encoding="utf-8"), encoding="utf-8"
    )
    dataset = _dataset(
        tmp_path,
        [{
            "id": "filesystem",
            "target": "src/filesystem",
            "expected_tools": ["read_media_file", "move_file"],
        }],
        corpus={"repo": "https://example.invalid/servers", "commit": "0" * 40},
    )

    result = evaluate_benchmark(dataset, corpus_root=root)

    assert result["corpus"]["available"] is True
    assert result["cases"][0]["status"] == "evaluated"
    assert result["discovery"]["coverage"] == 1.0


def test_composite_corpus_verifies_every_pinned_checkout(tmp_path):
    root = tmp_path / "holdout"
    for name, commit in (("one", "1" * 40), ("two", "2" * 40)):
        checkout = root / name
        (checkout / ".git").mkdir(parents=True)
        (checkout / ".git" / "HEAD").write_text(commit + "\n", encoding="ascii")
        (checkout / "server.ts").write_text(
            FIXTURE.read_text(encoding="utf-8"), encoding="utf-8"
        )
    dataset = _dataset(
        tmp_path,
        [{
            "id": "one",
            "target": "one/server.ts",
            "expected_tools": ["read_media_file", "move_file"],
        }],
        corpus={
            "repositories": [
                {"path": "one", "repo": "https://example.invalid/one", "commit": "1" * 40},
                {"path": "two", "repo": "https://example.invalid/two", "commit": "2" * 40},
            ]
        },
    )

    result = evaluate_benchmark(dataset, corpus_root=root)

    assert result["corpus"]["available"] is True
    assert [repo["head"] for repo in result["corpus"]["repositories"]] == ["1" * 40, "2" * 40]
    assert result["cases"][0]["status"] == "evaluated"


def test_composite_corpus_rejects_a_checkout_at_the_wrong_commit(tmp_path):
    root = tmp_path / "holdout"
    checkout = root / "one"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("f" * 40 + "\n", encoding="ascii")
    (checkout / "server.ts").write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    dataset = _dataset(
        tmp_path,
        [{"id": "one", "target": "one/server.ts", "expected_tools": ["read_media_file"]}],
        corpus={
            "repositories": [
                {"path": "one", "repo": "https://example.invalid/one", "commit": "1" * 40}
            ]
        },
    )

    result = evaluate_benchmark(dataset, corpus_root=root)

    assert result["corpus"]["available"] is False
    assert result["corpus"]["repositories"][0]["status"] == "commit-mismatch"
    assert result["cases"][0]["status"] == "unavailable"
    assert benchmark_failed(result) is True


def test_a_known_gap_is_recorded_and_does_not_fail_the_run(tmp_path):
    dataset = _dataset(tmp_path, [{
        "id": "boundary",
        "target": str(FIXTURE),
        "expected_tools": ["read_media_file", "move_file"],
        "capabilities": [{
            "tool": "read_media_file",
            "capability": "network.outbound",
            "expected": True,
            "known_gap": "Pretend this handler posts the file somewhere.",
        }],
    }])

    result = evaluate_benchmark(dataset)

    assert result["capability_metrics"]["fn"] == 1
    assert result["gaps"] == [{
        "case": "boundary",
        "kind": "capability",
        "target": "read_media_file:network.outbound",
        "reason": "Pretend this handler posts the file somewhere.",
        "status": "open",
    }]
    assert benchmark_failed(result) is False


def test_a_resolved_known_gap_fails_so_stale_excuses_get_removed(tmp_path):
    dataset = _dataset(tmp_path, [{
        "id": "boundary",
        "target": str(FIXTURE),
        "expected_tools": ["read_media_file", "move_file"],
        "capabilities": [{
            "tool": "move_file",
            "capability": "filesystem.delete",
            "expected": True,
            "known_gap": "Stale: this one already works.",
        }],
    }])

    result = evaluate_benchmark(dataset)

    assert result["gaps"][0]["status"] == "resolved"
    assert benchmark_failed(result) is True


def test_missing_tools_fail_the_run_unless_registered_as_a_gap(tmp_path):
    dataset = _dataset(tmp_path, [{
        "id": "boundary",
        "target": str(FIXTURE),
        "expected_tools": ["read_media_file", "move_file", "write_file"],
    }])

    assert benchmark_failed(evaluate_benchmark(dataset)) is True

    dataset = _dataset(tmp_path, [{
        "id": "boundary",
        "target": str(FIXTURE),
        "expected_tools": ["read_media_file", "move_file", "write_file"],
        "coverage_gaps": {"write_file": "Excerpt fixture omits the write handler."},
    }])
    result = evaluate_benchmark(dataset)

    assert result["gaps"][0]["kind"] == "discovery"
    assert benchmark_failed(result) is False


# --- the shipped datasets ----------------------------------------------------

BENCHMARKS = Path(__file__).parents[1] / "benchmarks"
OFFICIAL = BENCHMARKS / "official-inventory-v1.yaml"
DEVELOPMENT = BENCHMARKS / "capability-attribution-v1.yaml"
HOLDOUT = BENCHMARKS / "external-holdout-v1.yaml"
PINNED_COMMIT = "599dafc1054550a6eeb87a6545c1e1b03b3ca827"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_official_inventory_pins_the_reviewed_commit():
    data = _load(OFFICIAL)

    assert data["split"] == "validation"
    assert data["corpus"]["commit"] == PINNED_COMMIT
    assert data["corpus"]["repo"].endswith("modelcontextprotocol/servers")


def test_official_inventory_labels_every_registered_tool():
    data = _load(OFFICIAL)
    per_case = {case["id"]: case["expected_tools"] for case in data["cases"]}

    assert per_case.keys() == {
        "filesystem", "memory", "sequentialthinking", "everything", "git", "fetch", "time",
    }
    assert [len(per_case[name]) for name in ("filesystem", "memory", "sequentialthinking")] == [14, 9, 1]
    assert [len(per_case[name]) for name in ("everything", "git", "fetch", "time")] == [19, 12, 1, 2]
    assert sum(len(tools) for tools in per_case.values()) == 58


def test_official_inventory_separates_the_extractor_shapes():
    data = _load(OFFICIAL)
    shapes = {case["id"]: case["shape"] for case in data["cases"]}

    assert shapes["filesystem"] == "ts-register-tool-literal"
    assert shapes["everything"] == "ts-register-tool-variable"
    assert shapes["git"] == "py-lowlevel-list-tools"


def test_every_registration_shape_in_the_corpus_is_supported():
    """P1 closed all three. A coverage_gaps entry reappearing means a shape
    regressed, and the reason has to name the phase that will close it."""
    data = _load(OFFICIAL)

    for case in data["cases"]:
        gaps = case.get("coverage_gaps", {})
        assert set(gaps) <= set(case["expected_tools"]), case["id"]
        assert gaps == {}, case["id"]


def test_capability_attribution_is_marked_a_development_regression_set():
    data = _load(DEVELOPMENT)

    assert data["split"] == "development"
    assert "production accuracy" in data["purpose"]


def test_external_holdout_is_composite_pinned_and_outside_the_validation_family():
    data = _load(HOLDOUT)

    assert data["split"] == "holdout"
    assert data["label_protocol"] == "source-review-before-first-auditor-run"
    repositories = data["corpus"]["repositories"]
    assert len(repositories) == 3
    assert all(len(item["commit"]) == 40 for item in repositories)
    assert all("modelcontextprotocol/servers" not in item["repo"] for item in repositories)


def test_external_holdout_labels_every_tool_in_both_capability_directions():
    data = _load(HOLDOUT)
    cases = {case["id"]: case for case in data["cases"]}

    assert {name: len(case["expected_tools"]) for name, case in cases.items()} == {
        "mcp-atlassian": 98,
        "tavily-mcp": 5,
        "fetch-mcp": 6,
    }
    for case in cases.values():
        assert set(case["capability_defaults"]) == CAPABILITIES
        values = set(case["capability_defaults"].values())
        assert values <= {True, False}
        assert True in values and False in values


def test_capability_attribution_freezes_the_filesystem_handler_boundary():
    result = evaluate_benchmark(DEVELOPMENT)
    boundary = {
        (d["tool"], d["capability"]): d
        for case in result["cases"] if case["id"] == "official-filesystem-boundaries"
        for d in case["capabilities"]
    }

    assert boundary[("move_file", "filesystem.delete")]["outcome"] == "tp"
    assert boundary[("read_media_file", "filesystem.delete")]["outcome"] == "tn"
    assert boundary[("read_media_file", "filesystem.write")]["outcome"] == "tn"


def test_capability_attribution_follows_the_media_handler_into_its_helper():
    """This was an open P2 gap. The fixture now carries the helper verbatim, so
    it guards the propagation rather than documenting its absence."""
    result = evaluate_benchmark(DEVELOPMENT)

    decisions = {
        (d["tool"], d["capability"]): d
        for case in result["cases"]
        for d in case["capabilities"]
    }

    assert decisions[("read_media_file", "filesystem.read")]["outcome"] == "tp"
    assert result["capability_metrics"]["fn"] == 0
    assert result["capability_metrics"]["fp"] == 0


def test_capability_attribution_dataset_passes_as_a_regression_guard():
    assert benchmark_failed(evaluate_benchmark(DEVELOPMENT)) is False


@pytest.mark.skipif(
    not os.environ.get("MCP_AUDITOR_CORPUS_ROOT"),
    reason="pinned official corpus is referenced, not vendored; set MCP_AUDITOR_CORPUS_ROOT",
)
def test_official_inventory_discovers_every_labelled_tool():
    result = evaluate_benchmark(OFFICIAL)

    assert result["discovery"]["expected"] == 58
    assert result["discovery"]["matched"] == 58
    assert result["discovery"]["unexpected"] == []
    for shape in ("ts-register-tool-literal", "ts-register-tool-variable", "py-lowlevel-list-tools"):
        assert result["per_shape"][shape]["discovery"]["coverage"] == 1.0, shape
    # Every remaining miss is written down, so the run reports it, not fails.
    assert benchmark_failed(result) is False


@pytest.mark.skipif(
    not os.environ.get("MCP_AUDITOR_CORPUS_ROOT"),
    reason="pinned official corpus is referenced, not vendored; set MCP_AUDITOR_CORPUS_ROOT",
)
def test_no_capability_leaks_between_tools_sharing_a_file_or_dispatcher():
    """P1's other exit criterion.

    19 `everything` tools are registered from one module tree, and 12 git tools
    share a single call_tool() dispatcher. Not one false positive means no
    handler inherited a sibling's sink.
    """
    result = evaluate_benchmark(OFFICIAL)

    assert result["capability_metrics"]["fp"] == 0
    assert result["capability_metrics"]["tn"] > 50


@pytest.mark.skipif(
    not os.environ.get("MCP_AUDITOR_CORPUS_ROOT"),
    reason="pinned official corpus is referenced, not vendored; set MCP_AUDITOR_CORPUS_ROOT",
)
def test_official_baseline_is_pinned_so_progress_has_to_be_recorded():
    """The measured result on the validation corpus, frozen deliberately.

    Every labelled decision now holds and no known_gap remains, so this test
    exists to make a regression loud rather than to track progress. A change
    that moves any of these numbers has to update the ground truth in the same
    commit, with a reviewer looking at why.
    """
    result = evaluate_benchmark(OFFICIAL)

    capability = result["capability_metrics"]
    assert (capability["tp"], capability["fp"], capability["fn"]) == (28, 0, 0)
    assert capability["precision"] == 1.0
    assert capability["recall"] == 1.0

    findings = result["metrics"]
    assert (findings["tp"], findings["fp"], findings["fn"]) == (7, 0, 0)
    assert findings["false_positive_rate"] == 0.0
    # The one genuinely unguarded input in the corpus still fires.
    assert result["per_rule"]["OP-002"]["tp"] == 1
    assert result["per_rule"]["OP-002"]["tn"] == 14
    assert result["unlabelled_findings"] == []
    assert result["gaps"] == []


# --- completeness of the finding labels --------------------------------------

CONTROLS = BENCHMARKS / "fixtures" / "genuine-capability-mismatches.ts"


def test_a_finding_nobody_labelled_is_reported_as_incomplete_ground_truth(tmp_path):
    """Precision over a subset of the emitted findings is not precision.

    The fixture fires CP-001, CP-002 and CP-003 on read_only_writer. Labelling
    one of them and staying silent about the rest would quietly compute 100%.
    """
    dataset = _dataset(tmp_path, [{
        "id": "controls",
        "target": str(CONTROLS),
        "expected_tools": ["read_only_writer", "safe_reader"],
        "labels": [{"rule": "CP-001", "tool": "read_only_writer", "expected": True}],
    }])

    result = evaluate_benchmark(dataset)

    assert result["unlabelled_findings"] == [
        {"case": "controls", "rule": "CP-002", "tool": "read_only_writer"},
        {"case": "controls", "rule": "CP-003", "tool": "read_only_writer"},
        {"case": "controls", "rule": "OP-002", "tool": "read_only_writer"},
        {"case": "controls", "rule": "OP-002", "tool": "safe_reader"},
    ]
    assert result["unexplained"]["unlabelled"] == 4
    assert benchmark_failed(result) is True


def test_fully_labelled_findings_leave_nothing_unlabelled():
    result = evaluate_benchmark(DEVELOPMENT)

    assert result["unlabelled_findings"] == []
