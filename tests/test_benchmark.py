from pathlib import Path

from click.testing import CliRunner

from mcp_auditor.benchmark import evaluate_benchmark
from mcp_auditor.cli import main


DATASET = Path(__file__).parents[1] / "benchmarks" / "capability-attribution-v1.yaml"


def test_capability_benchmark_scores_every_finding_it_emits():
    """The capability rules stay clean; the one FP is the labelled OP-002 gap.

    `read_media_file` resolves its path through validatePath() before use, so
    the finding is recorded as a false positive with a P3 known_gap rather than
    being left off the sheet.
    """
    result = evaluate_benchmark(DATASET)

    assert result["dataset"] == "capability-attribution-v1"
    assert result["metrics"] == {
        "tp": 5,
        "fp": 1,
        "fn": 0,
        "tn": 6,
        "precision": 0.833333,
        "recall": 1.0,
        "specificity": 0.857143,
        "false_positive_rate": 0.142857,
        "f1": 0.909091,
        "accuracy": 0.916667,
    }
    assert result["per_rule"]["CP-001"]["fp"] == 0
    assert result["per_rule"]["CP-002"]["fp"] == 0
    assert result["per_rule"]["CP-003"]["fp"] == 0


def test_benchmark_cli_emits_machine_readable_json():
    result = CliRunner().invoke(main, ["benchmark", str(DATASET), "--json"])

    assert result.exit_code == 0, result.output
    assert '"false_positive_rate": 0.0' in result.output
