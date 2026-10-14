import json
from pathlib import Path

import pytest

from owasp_audit import sha256_tree
from owasp_reportable_inputs import ReportableInputError, freeze_reportable_inputs, validate_reportable_inputs
from owasp_split import build_split
from semgrep_rules import sha256_file


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def write_inputs(tmp_path: Path) -> dict[str, Path]:
    dataset = tmp_path / "dataset"
    source_root = dataset / "src" / "main" / "java"
    source_root.mkdir(parents=True)
    rows = []
    for number, cwe in enumerate((78, 89, 78, 89, 78), 1):
        test_id = f"BenchmarkTest{number:05d}"
        (source_root / f"{test_id}.java").write_text(
            f"class {test_id} {{ void go() {{ String text = \"{number}\"; }} }}",
            encoding="utf-8",
        )
        rows.append(f"{test_id},category,{str(number % 2 == 1).lower()},{cwe}")
    ground_truth = dataset / "expectedresults-1.2.csv"
    ground_truth.write_text(
        "# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n" + "\n".join(rows) + "\n",
        encoding="utf-8",
    )
    dataset_manifest = tmp_path / "dataset-manifest.json"
    write_json(dataset_manifest, {
        "audit_status": "passed", "dataset_id": "owasp-benchmark-java-v1.2",
        "frozen_commit": "a" * 40, "ground_truth_path": "expectedresults-1.2.csv",
        "ground_truth_sha256": sha256_file(ground_truth),
        "java_corpus_sha256": sha256_tree(dataset, list((dataset / "src").rglob("BenchmarkTest*.java"))),
    })
    split = tmp_path / "split"
    build_split(dataset, dataset_manifest, split)
    upstream = tmp_path / "upstream"
    project = tmp_path / "project"
    upstream.mkdir()
    project.mkdir()
    rule = upstream / "rule.yml"
    rule.write_text("rules: []\n", encoding="utf-8")
    catalog = tmp_path / "catalog.json"
    catalog_rule = {
        "source_path": "rule.yml", "id": "test-rule", "source_sha256": sha256_file(rule),
        "source_type": "official_upstream", "source_root": "upstream_rules", "mode": "search",
    }
    write_json(catalog, {
        "schema_version": 1, "status": "passed", "candidate_rule_count": 1,
        "upstream_commit": "b" * 40, "rules": [catalog_rule],
    })
    review = tmp_path / "review.json"
    write_json(review, {
        "schema_version": 1, "inventory_sha256": sha256_file(catalog),
        "reviews": [{**catalog_rule, "rule_id": "test-rule", "decision": "INCLUDE_DEVELOPMENT", "reviewed_cwes": [78, 89]}],
    })
    return {"dataset": dataset, "dataset_manifest": dataset_manifest, "split": split, "upstream": upstream, "project": project, "catalog": catalog, "review": review}


def test_freeze_and_validate_reportable_input_bundle(tmp_path: Path) -> None:
    values = write_inputs(tmp_path)
    output = tmp_path / "bundle"
    result = freeze_reportable_inputs(**values, output_dir=output)
    assert result.unit_count == 5
    assert result.rule_count == 1
    assert sum(result.cohort_counts.values()) == 5
    assert validate_reportable_inputs(**values, bundle_dir=output) == result


def test_validator_rejects_tampered_cohort(tmp_path: Path) -> None:
    values = write_inputs(tmp_path)
    output = tmp_path / "bundle"
    freeze_reportable_inputs(**values, output_dir=output)
    cohort = output / "cohorts" / "test.json"
    cohort.write_text("changed", encoding="utf-8")
    with pytest.raises(ReportableInputError, match="artifact hash mismatch"):
        validate_reportable_inputs(**values, bundle_dir=output)


def test_validator_rejects_changed_split_source(tmp_path: Path) -> None:
    values = write_inputs(tmp_path)
    output = tmp_path / "bundle"
    freeze_reportable_inputs(**values, output_dir=output)
    assignments = values["split"] / "assignments.jsonl"
    assignments.write_text(assignments.read_text(encoding="utf-8") + "{}\n", encoding="utf-8")
    with pytest.raises(ReportableInputError, match="split"):
        validate_reportable_inputs(**values, bundle_dir=output)
