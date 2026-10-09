import json
from pathlib import Path

import pytest

from baseline import BaselineError, run_owasp_baseline, validate_baseline_run
from semgrep_rules import sha256_file


def write_inputs(tmp_path: Path) -> dict[str, Path]:
    dataset = tmp_path / "dataset"
    source = dataset / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    source.mkdir(parents=True)
    java = source / "BenchmarkTest00001.java"
    java.write_text("class X {}\n", encoding="utf-8")
    ground_truth = dataset / "expectedresults-1.2.csv"
    ground_truth.write_text(
        "# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n"
        "BenchmarkTest00001,cmdi,true,78\n",
        encoding="utf-8",
    )
    dataset_manifest = tmp_path / "dataset-manifest.json"
    dataset_manifest.write_text(
        json.dumps(
            {
                "audit_status": "passed",
                "dataset_id": "owasp-benchmark-java-v1.2",
                "frozen_commit": "b" * 40,
                "ground_truth_path": "expectedresults-1.2.csv",
                "ground_truth_sha256": sha256_file(ground_truth),
            }
        ),
        encoding="utf-8",
    )
    rules = tmp_path / "rules"
    rule = rules / "java" / "rule.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text("rule", encoding="utf-8")
    ruleset = tmp_path / "ruleset.json"
    ruleset.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "development",
                "purpose": "development",
                "reportable": False,
                "upstream_commit": "a" * 40,
                "rule_count": 1,
                "unresolved_review_count": 1,
                "rules": [
                    {
                        "identity": "java/rule.yaml::rule",
                        "rule_id": "rule",
                        "source_path": "java/rule.yaml",
                        "source_sha256": sha256_file(rule),
                        "reviewed_cwes": [78],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    cohort = tmp_path / "cohort.json"
    cohort.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "development",
                "purpose": "development",
                "reportable": False,
                "matching_policy": "owasp-testcase-cwe-any-finding-v1",
                "dataset_id": "owasp-benchmark-java-v1.2",
                "dataset_commit": "b" * 40,
                "dataset_manifest_sha256": sha256_file(dataset_manifest),
                "ground_truth_sha256": sha256_file(ground_truth),
                "ruleset_sha256": sha256_file(ruleset),
                "unit_count": 1,
                "units": [{"test_id": "BenchmarkTest00001", "category": "cmdi", "cwe": 78, "vulnerable": True}],
            }
        ),
        encoding="utf-8",
    )
    return {"dataset": dataset, "dataset_manifest": dataset_manifest, "rules": rules, "ruleset": ruleset, "cohort": cohort, "java": java}


def test_run_and_validate_baseline(tmp_path: Path) -> None:
    inputs = write_inputs(tmp_path)

    def fake_scan(rules_dir, ruleset, source_root, raw_dir, semgrep, version):
        raw_dir.mkdir(parents=True)
        raw = raw_dir / "rule.stdout.json"
        raw.write_text(
            json.dumps(
                {
                    "version": version,
                    "errors": [],
                    "results": [{"check_id": "rule", "path": str(inputs["java"]), "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 2}, "extra": {"message": "m", "severity": "ERROR"}}],
                }
            ),
            encoding="utf-8",
        )
        stderr = raw_dir / "rule.stderr.txt"
        stderr.write_text("", encoding="utf-8")
        return [{"rule_identity": "java/rule.yaml::rule", "rule_id": "rule", "rule_path": "java/rule.yaml", "rule_sha256": sha256_file(inputs["rules"] / "java" / "rule.yaml"), "reviewed_cwes": [78], "finding_count": 1, "stdout_path": str(raw), "stdout_sha256": sha256_file(raw), "stderr_path": str(stderr), "stderr_sha256": sha256_file(stderr), "exit_code": 0}]

    run_dir = tmp_path / "run"
    result = run_owasp_baseline(
        "run-1", "development", inputs["dataset"], inputs["dataset_manifest"],
        inputs["rules"], inputs["ruleset"], inputs["cohort"], run_dir,
        "semgrep", "1.179.0", fake_scan,
    )
    validated = validate_baseline_run(run_dir, inputs["dataset"], inputs["dataset_manifest"], inputs["rules"])
    assert result.tp == 1
    assert result.reportable is False
    assert validated.status == "completed"
    metrics_path = run_dir / "evaluation" / "metrics.json"
    metrics_path.write_text("{}", encoding="utf-8")
    with pytest.raises(BaselineError, match="artifact mismatch"):
        validate_baseline_run(
            run_dir,
            inputs["dataset"],
            inputs["dataset_manifest"],
            inputs["rules"],
        )


def test_baseline_rejects_existing_run_directory(tmp_path: Path) -> None:
    inputs = write_inputs(tmp_path)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    with pytest.raises(BaselineError, match="already exists"):
        run_owasp_baseline("run-1", "development", inputs["dataset"], inputs["dataset_manifest"], inputs["rules"], inputs["ruleset"], inputs["cohort"], run_dir, "semgrep", "1.179.0")


def test_scanner_failure_writes_failed_manifest(tmp_path: Path) -> None:
    inputs = write_inputs(tmp_path)

    def fail_scan(*args, **kwargs):
        raise ValueError("scanner failed")

    run_dir = tmp_path / "failed"
    with pytest.raises(BaselineError, match="scanner failed"):
        run_owasp_baseline("run-2", "development", inputs["dataset"], inputs["dataset_manifest"], inputs["rules"], inputs["ruleset"], inputs["cohort"], run_dir, "semgrep", "1.179.0", fail_scan)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert not (run_dir / "normalized" / "findings.jsonl").exists()
