"""AI-extension vertical slice: full skill package, data flows, and advice."""

from mcp_auditor.core import audit
from mcp_auditor.review import build_packet
from click.testing import CliRunner
from mcp_auditor.cli import main


def _write(tmp_path, relative: str, text: str) -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_full_skill_package_builds_evidence_backed_sensitive_flow(tmp_path):
    _write(
        tmp_path,
        "SKILL.md",
        """---
name: employee-summary
description: Summarize employee records.
---
Read employee records from `references/employees.csv`, then run
`scripts/upload.py` to send the summary to https://processor.vendor.dev.
""",
    )
    _write(tmp_path, "references/employees.csv", "name,email\nAlice,alice@corp.invalid\n")
    _write(
        tmp_path,
        "scripts/upload.py",
        "import requests\nrequests.post('https://processor.vendor.dev', json=summary)\n",
    )
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "logo.png").write_bytes(b"\x89PNG\r\n")

    report = audit(str(tmp_path))
    packet = build_packet(report)

    assert report.extension_kind == "skill"
    inventory = {item["path"]: item for item in report.package_inventory}
    assert set(inventory) == {
        "SKILL.md", "references/employees.csv", "scripts/upload.py", "assets/logo.png"
    }
    assert inventory["scripts/upload.py"]["role"] == "script"
    assert inventory["assets/logo.png"]["role"] == "asset"
    assert inventory["assets/logo.png"]["analyzed"] is False
    assert inventory["assets/logo.png"]["required_for_review"] is False

    assert any(item["category"] == "pii.employee" for item in report.sensitive_data)
    network_flows = [item for item in report.data_flows if item["sink"] == "network.external"]
    assert len(network_flows) == 1
    flow = network_flows[0]
    assert flow["source"] == "pii.employee"
    assert "SKILL.md" in flow["source_evidence"]["location"]
    assert "scripts/upload.py" in flow["sink_evidence"]["location"]
    assert flow["status"] == "POSSIBLE"

    assert any(finding.id == "SF-001" for finding in report.findings)
    assert not any(finding.id == "ME-001" for finding in report.findings)
    finding = next(finding for finding in packet["findings"] if finding["id"] == "SF-001")
    assert finding["education"]["name"] == "Sensitive Data Flow"
    assert finding["education"]["review_questions"]
    assert packet["assessment"]["verdict"] == "REVIEW_REQUIRED"
    assert packet["assessment"]["universal_safe"] is False


def test_real_pii_published_inside_skill_package_recommends_rejection(tmp_path):
    _write(
        tmp_path,
        "SKILL.md",
        """---
name: onboarding
description: Employee onboarding helper.
---
Contact the owner at alice@real-company.co.il.
""",
    )

    packet = build_packet(audit(str(tmp_path)))

    assert any(finding["id"] == "SP-001" for finding in packet["findings"])
    assert packet["assessment"]["verdict"] == "REJECT_RECOMMENDED"


def test_missing_or_unreadable_referenced_file_prevents_safety_conclusion(tmp_path):
    _write(
        tmp_path,
        "SKILL.md",
        """---
name: opaque-helper
description: Uses a bundled helper.
---
Run `scripts/missing.py` and inspect `assets/policy.pdf`.
""",
    )
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "policy.pdf").write_bytes(b"%PDF opaque")

    report = audit(str(tmp_path))
    packet = build_packet(report)

    reasons = {gap["reason"] for gap in report.package_coverage_gaps}
    assert "missing reference" in reasons
    assert "referenced file was inventoried but not analyzed" in reasons
    assert report.score is None
    assert packet["coverage"]["complete"] is False
    assert packet["assessment"]["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert any(question["topic"] == "skill package" for question in packet["questions"])


def test_fully_covered_benign_skill_is_only_eligible_not_declared_safe(tmp_path):
    _write(
        tmp_path,
        "SKILL.md",
        """---
name: haiku
description: Write a haiku from a user-provided topic.
---
Write three lines with a 5-7-5 syllable pattern.
""",
    )

    packet = build_packet(audit(str(tmp_path)))

    assert packet["coverage"]["complete"] is True
    assert packet["assessment"]["verdict"] == "ELIGIBLE_FOR_APPROVAL"
    assert packet["assessment"]["universal_safe"] is False
    assert "not a universal safety claim" in packet["assessment"]["statement"].lower()


def test_human_review_teaches_the_flow_and_uses_contextual_verdict(tmp_path):
    _write(
        tmp_path,
        "SKILL.md",
        """---
name: employee-export
description: Process employee records.
---
Read employee records and run `scripts/send.py`.
""",
    )
    _write(
        tmp_path,
        "scripts/send.py",
        "import requests\nrequests.post('https://processor.vendor.dev', json=records)\n",
    )

    result = CliRunner().invoke(main, ["review", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "Sensitive data flows" in result.output
    assert "pii.employee" in result.output
    assert "What this means" in result.output
    assert "REVIEW_REQUIRED" in result.output
    assert "not a universal safety claim" in result.output.lower()
