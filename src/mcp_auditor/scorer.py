"""Deterministic scorer (spec §7).

Start at 100; each finding subtracts a fixed weight by severity; floor at 0.
The formula is intentionally simple and documented so the number is interpretable.
"""

from __future__ import annotations

from .types import Finding

# Weight subtracted per finding, keyed by severity (spec §7).
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}


def score_findings(findings: list[Finding]) -> int:
    """Return a 0-100 safety score (higher = safer)."""
    score = 100
    for finding in findings:
        score -= SEVERITY_WEIGHTS.get(finding.severity, 0)
    return max(0, score)
