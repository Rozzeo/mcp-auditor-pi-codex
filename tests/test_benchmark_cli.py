"""The benchmark CLI has to make an incomplete run look incomplete."""

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from mcp_auditor.cli import main


BENCHMARKS = Path(__file__).parents[1] / "benchmarks"
DEVELOPMENT = BENCHMARKS / "capability-attribution-v1.yaml"
OFFICIAL = BENCHMARKS / "official-inventory-v1.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "official-filesystem-register-tools.ts"


def _run(*args):
    return CliRunner().invoke(main, ["benchmark", *args])


def test_json_report_carries_the_three_measurement_views():
    result = _run(str(DEVELOPMENT), "--json")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["discovery"]["coverage"] == 1.0
    assert payload["capability_metrics"]["tp"] > 0
    shape = payload["per_shape"]["ts-register-tool-literal"]
    assert set(shape) == {"discovery", "capabilities", "findings"}
    assert shape["findings"]["tp"] > 0


def test_human_output_states_the_split_and_the_coverage():
    result = _run(str(DEVELOPMENT))

    assert result.exit_code == 0, result.output
    assert "development" in result.output
    assert "Coverage" in result.output


def test_open_gaps_are_printed_so_they_cannot_be_forgotten():
    result = _run(str(DEVELOPMENT))

    assert "OP-002:read_media_file" in result.output
    assert "P3" in result.output


def test_a_referenced_corpus_that_is_absent_fails_loudly():
    result = _run(str(OFFICIAL), "--corpus-root", str(Path("does") / "not" / "exist"))

    assert result.exit_code == 1
    assert "corpus" in result.output.lower()


def test_corpus_root_is_passed_through_to_the_evaluation(tmp_path):
    root = tmp_path / "corpus"
    (root / "src" / "filesystem").mkdir(parents=True)
    (root / "src" / "filesystem" / "index.ts").write_text(
        FIXTURE.read_text(encoding="utf-8"), encoding="utf-8"
    )
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text(
        yaml.safe_dump({
            "version": 2,
            "name": "inline",
            "split": "validation",
            "corpus": {"repo": "https://example.invalid/x", "commit": "0" * 40},
            "cases": [{
                "id": "filesystem",
                "target": "src/filesystem",
                "expected_tools": ["read_media_file", "move_file"],
            }],
        }),
        encoding="utf-8",
    )

    result = _run(str(dataset), "--corpus-root", str(root), "--json")

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["discovery"]["coverage"] == 1.0


def test_unexplained_misses_fail_the_run(tmp_path):
    dataset = tmp_path / "dataset.yaml"
    dataset.write_text(
        yaml.safe_dump({
            "version": 2,
            "name": "inline",
            "cases": [{
                "id": "boundary",
                "target": str(FIXTURE),
                "expected_tools": ["read_media_file", "move_file", "write_file"],
            }],
        }),
        encoding="utf-8",
    )

    result = _run(str(dataset))

    assert result.exit_code == 1
    assert "write_file" in result.output
