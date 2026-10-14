import json
from pathlib import Path

from owasp_reportable_baseline import _cohort_dir_from_inputs, evaluate_cohorts


def write_cohort(path: Path, split: str, test_id: str, vulnerable: bool) -> None:
    path.write_text(
        json.dumps({"purpose": "reportable", "reportable": True, "split": split, "units": [{"test_id": test_id, "cwe": 78, "vulnerable": vulnerable}]}),
        encoding="utf-8",
    )


def test_evaluate_cohorts_uses_one_finding_set_for_each_split(tmp_path: Path) -> None:
    cohorts = tmp_path / "cohorts"
    cohorts.mkdir()
    write_cohort(cohorts / "development.json", "development", "BenchmarkTest00001", True)
    write_cohort(cohorts / "validation.json", "validation", "BenchmarkTest00002", False)
    write_cohort(cohorts / "test.json", "test", "BenchmarkTest00003", True)
    findings = [{"candidate_id": "candidate-1", "test_id": "BenchmarkTest00001", "reviewed_cwes": [78]}]

    result = evaluate_cohorts(cohorts, findings, raw_finding_count=1)

    assert result["development"]["metrics"]["overall"]["tp"] == 1
    assert result["validation"]["metrics"]["overall"]["tn"] == 1
    assert result["test"]["metrics"]["overall"]["fn"] == 1
    assert result["development"]["metrics"]["normalized_candidate_count"] == 1
    assert result["validation"]["metrics"]["normalized_candidate_count"] == 1
    assert result["test"]["metrics"]["normalized_candidate_count"] == 1


def test_cohort_directory_is_resolved_from_manifest_string_path(tmp_path: Path) -> None:
    inputs = {"cohorts": {"development": {"path": "inputs/cohorts/development.json"}}}
    assert _cohort_dir_from_inputs(tmp_path, inputs) == tmp_path / "inputs" / "cohorts"
