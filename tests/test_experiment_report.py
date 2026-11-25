import json
from pathlib import Path

from experiment_report import evaluate_variants, model_usage, write_reports


def test_verdicts_keep_uncertain_and_suppress_only_valid_fp() -> None:
    units = [
        {"test_id": "BenchmarkTest00001", "cwe": 22, "vulnerable": True},
        {"test_id": "BenchmarkTest00002", "cwe": 22, "vulnerable": False},
    ]
    findings = [
        {"id": "a", "path": "BenchmarkTest00001.java", "cwes": [22]},
        {"id": "b", "path": "BenchmarkTest00002.java", "cwes": [22]},
    ]
    verdicts = {"a": {"effective_verdict": "UNCERTAIN"},
                "b": {"effective_verdict": "FALSE_POSITIVE"}}
    results = evaluate_variants("owasp", units, findings, verdicts, verdicts)
    assert results["A"]["overall"]["fp"] == 1
    assert results["B"]["overall"]["tp"] == 1
    assert results["B"]["overall"]["fp"] == 0
    assert results["B"]["false_positives_reduced"] == 1
    assert results["B"]["recall_preservation"] == 1
    assert results["B"]["by_cwe"]["22"]["precision"] == 1
    assert results["B"]["macro"]["precision"] == 1


def test_model_usage_reports_missing_as_null(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "a.json").write_text(json.dumps({"prompt_eval_count": 15,
                                              "eval_count": 7,
                                              "total_duration": 2_000_000_000}), encoding="utf-8")
    usage = model_usage(tmp_path, ["a", "b"])
    assert usage["a"]["input_tokens"] == 15
    assert usage["a"]["output_tokens"] == 7
    assert usage["a"]["duration_seconds"] == 2
    assert usage["b"]["input_tokens"] is None
    assert usage["b"]["missing_reason"] == "raw_response_missing"


def test_csv_reports_reference_run_manifest(tmp_path: Path) -> None:
    rows = [{"variant": "A", "dataset": "owasp", "tp": 1, "fp": 0,
             "tn": 1, "fn": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0}]
    write_reports(tmp_path, "run-1", "manifest.json", rows, [], [])
    assert "manifest.json" in (tmp_path / "runs.csv").read_text(encoding="utf-8")
    assert (tmp_path / "findings.csv").is_file()
    assert (tmp_path / "units.csv").is_file()
    headers = (tmp_path / "runs.csv").read_text(encoding="utf-8").splitlines()[0]
    assert "pair_accuracy" in headers
    assert "peak_ram_mb" in headers
    assert "peak_vram_mb" in headers
    assert "retrieval_seconds" in headers
