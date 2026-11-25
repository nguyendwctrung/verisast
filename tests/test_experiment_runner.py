import json
from pathlib import Path

import pytest

from experiment_runner import RunnerError, allocate_run, run_mock


def test_allocate_run_generates_id_and_never_overwrites(tmp_path: Path) -> None:
    first = allocate_run(tmp_path, "sample")
    second = allocate_run(tmp_path, "sample")
    assert first != second
    assert first.name.startswith("sample-")
    assert first.is_dir() and second.is_dir()


def test_allocate_run_rejects_unsafe_result_name(tmp_path: Path) -> None:
    with pytest.raises(RunnerError, match="result name"):
        allocate_run(tmp_path, "../outside")


def test_fixture_dry_run_preserves_shared_candidates(tmp_path: Path) -> None:
    result = run_mock(tmp_path, "fixture")
    run = Path(result["run_directory"])
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "mock_completed"
    assert manifest["candidate_sha256"]["A"] == manifest["candidate_sha256"]["B"]
    assert manifest["candidate_sha256"]["B"] == manifest["candidate_sha256"]["C"]
    assert (run / "reports" / "runs.csv").is_file()
    assert (run / "reports" / "findings.csv").is_file()
    assert (run / "reports" / "units.csv").is_file()
