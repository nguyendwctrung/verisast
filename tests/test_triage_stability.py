import json
from pathlib import Path

import pytest

from stability import StabilityError
from triage_stability import aggregate_triage_runs


def test_zero_candidate_runs_are_stably_empty(tmp_path: Path) -> None:
    runs = []
    for index in (1, 2, 3):
        path = tmp_path / f"empty-{index}"
        path.mkdir()
        (path / "verdicts.jsonl").write_text("", encoding="utf-8")
        runs.append(path)
    result = aggregate_triage_runs(runs, tmp_path / "aggregate")
    assert result["candidate_count"] == 0
    assert result["gate"]["status"] == "passed"


def _run(path: Path, source_lines: list[str]) -> None:
    (path / "raw").mkdir(parents=True)
    (path / "verdicts.jsonl").write_text(json.dumps({
        "candidate_id": "candidate-1", "effective_verdict": "TRUE_POSITIVE",
        "reported_verdict": "TRUE_POSITIVE", "error": None,
    }) + "\n", encoding="utf-8")
    response = {
        "source": {"evidence_lines": source_lines},
        "sink": {"evidence_lines": ["F1:L2"]},
        "dataflow": {"evidence_lines": ["F1:L1", "F1:L2"]},
    }
    (path / "raw" / "candidate-1.json").write_text(
        json.dumps({"response": json.dumps(response)}), encoding="utf-8",
    )


def test_aggregate_triage_runs_writes_stable_result(tmp_path: Path) -> None:
    runs = [tmp_path / f"run-{index}" for index in range(3)]
    for run in runs:
        _run(run, ["F1:L1"])

    result = aggregate_triage_runs(runs, tmp_path / "aggregate")

    row = json.loads((tmp_path / "aggregate" / "verdicts.jsonl").read_text(encoding="utf-8"))
    assert result["gate"]["status"] == "passed"
    assert row["effective_verdict"] == "TRUE_POSITIVE"


def test_aggregate_triage_runs_fails_open_on_citation_variance(tmp_path: Path) -> None:
    runs = [tmp_path / f"run-{index}" for index in range(3)]
    _run(runs[0], ["F1:L1"])
    _run(runs[1], ["F1:L1"])
    _run(runs[2], ["F1:L3"])

    aggregate_triage_runs(runs, tmp_path / "aggregate")

    row = json.loads((tmp_path / "aggregate" / "verdicts.jsonl").read_text(encoding="utf-8"))
    assert row["effective_verdict"] == "UNCERTAIN"
    assert row["error"] == "non_reproducible_output"


def test_aggregate_triage_runs_requires_three_no_overwrite_runs(tmp_path: Path) -> None:
    with pytest.raises(StabilityError, match="exactly three"):
        aggregate_triage_runs([], tmp_path / "aggregate")
    runs = [tmp_path / f"run-{index}" for index in range(3)]
    for run in runs:
        _run(run, ["F1:L1"])
    (tmp_path / "aggregate").mkdir()
    with pytest.raises(StabilityError, match="already exists"):
        aggregate_triage_runs(runs, tmp_path / "aggregate")
