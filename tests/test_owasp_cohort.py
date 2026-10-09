import json
from pathlib import Path

import pytest

from owasp_cohort import CohortError, build_cohort, load_cohort
from semgrep_rules import sha256_file


def write_dataset(tmp_path: Path) -> tuple[Path, Path]:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    ground_truth = dataset / "expectedresults-1.2.csv"
    ground_truth.write_text(
        "# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n"
        "BenchmarkTest00001,cmdi,true,78\n"
        "BenchmarkTest00002,cmdi,false,78\n"
        "BenchmarkTest00003,sqli,true,89\n",
        encoding="utf-8",
    )
    manifest = tmp_path / "dataset-manifest.json"
    manifest.write_text(
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
    return dataset, manifest


def write_ruleset(tmp_path: Path, reportable: bool = False) -> Path:
    path = tmp_path / "ruleset.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "purpose": "reportable" if reportable else "development",
                "status": "frozen" if reportable else "development",
                "reportable": reportable,
                "upstream_commit": "a" * 40,
                "rule_count": 1,
                "unresolved_review_count": 0 if reportable else 1,
                "rules": [
                    {"identity": "java/rule.yaml::rule", "reviewed_cwes": [78]}
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_build_development_cohort_filters_by_ruleset_cwes(tmp_path: Path) -> None:
    dataset, manifest = write_dataset(tmp_path)
    ruleset = write_ruleset(tmp_path)
    output = tmp_path / "cohort.json"
    result = build_cohort(dataset, manifest, ruleset, output, "development")
    payload = load_cohort(output, dataset, manifest, ruleset)
    assert result.unit_count == 2
    assert payload["cwes"] == [78]
    assert payload["label_counts"] == {"false": 1, "true": 1}
    assert payload["matching_policy"] == "owasp-testcase-cwe-any-finding-v1"


def test_reportable_cohort_requires_reportable_ruleset(tmp_path: Path) -> None:
    dataset, manifest = write_dataset(tmp_path)
    with pytest.raises(CohortError, match="reportable ruleset"):
        build_cohort(
            dataset,
            manifest,
            write_ruleset(tmp_path),
            tmp_path / "cohort.json",
            "reportable",
        )


def test_load_cohort_rejects_changed_ground_truth(tmp_path: Path) -> None:
    dataset, manifest = write_dataset(tmp_path)
    ruleset = write_ruleset(tmp_path)
    output = tmp_path / "cohort.json"
    build_cohort(dataset, manifest, ruleset, output, "development")
    (dataset / "expectedresults-1.2.csv").write_text("changed", encoding="utf-8")
    with pytest.raises(CohortError, match="ground-truth hash mismatch"):
        load_cohort(output, dataset, manifest, ruleset)
