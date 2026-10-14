import json
from pathlib import Path

import pytest

from owasp_audit import sha256_tree
from owasp_split import SplitError, assign_families, build_split, canonicalize_source, validate_split
from semgrep_rules import sha256_file


def write_dataset(tmp_path: Path) -> tuple[Path, Path]:
    dataset = tmp_path / "dataset"
    source_root = dataset / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    source_root.mkdir(parents=True)
    rows = []
    for number in range(1, 11):
        test_id = f"BenchmarkTest{number:05d}"
        vulnerable = number % 2 == 1
        body = "String value = \"same\";" if number <= 2 else f"String value = \"value-{number}\";"
        (source_root / f"{test_id}.java").write_text(
            f"package test; public class {test_id} {{ void go() {{ {body} }} }}",
            encoding="utf-8",
        )
        rows.append(f"{test_id},category,{str(vulnerable).lower()},78")
    ground_truth = dataset / "expectedresults-1.2.csv"
    ground_truth.write_text(
        "# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n" + "\n".join(rows) + "\n",
        encoding="utf-8",
    )
    sources = list((dataset / "src").rglob("BenchmarkTest*.java"))
    manifest = tmp_path / "dataset-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "audit_status": "passed",
                "dataset_id": "owasp-benchmark-java-v1.2",
                "frozen_commit": "a" * 40,
                "ground_truth_path": "expectedresults-1.2.csv",
                "ground_truth_sha256": sha256_file(ground_truth),
                "java_corpus_sha256": sha256_tree(dataset, sources),
            }
        ),
        encoding="utf-8",
    )
    return dataset, manifest


def test_canonicalization_ignores_test_id_and_literal_variation() -> None:
    first = 'class BenchmarkTest00001 { String value = "one"; }'
    second = 'class BenchmarkTest00002 { String value = "two"; }'
    assert canonicalize_source(first) == canonicalize_source(second)


def test_assignment_is_deterministic_and_keeps_families_whole() -> None:
    families = [
        {"family_id": "family-a", "unit_count": 3, "units": [{"test_id": "a", "cwe": 78}] * 3},
        {"family_id": "family-b", "unit_count": 2, "units": [{"test_id": "b", "cwe": 78}] * 2},
    ]
    first = assign_families(families, 5)
    assert first == assign_families(families, 5)
    assert len({item["split"] for item in first if item["family_id"] == "family-a"}) == 1


def test_build_and_validate_split(tmp_path: Path) -> None:
    dataset, manifest = write_dataset(tmp_path)
    result = build_split(dataset, manifest, tmp_path / "split")
    assert result.unit_count == 10
    assert sum(result.split_counts.values()) == 10
    validated = validate_split(dataset, manifest, tmp_path / "split")
    assert validated == result


def test_split_rejects_existing_output(tmp_path: Path) -> None:
    dataset, manifest = write_dataset(tmp_path)
    output = tmp_path / "split"
    build_split(dataset, manifest, output)
    with pytest.raises(SplitError, match="already exists"):
        build_split(dataset, manifest, output)


def test_validator_rejects_tampered_assignment(tmp_path: Path) -> None:
    dataset, manifest = write_dataset(tmp_path)
    output = tmp_path / "split"
    build_split(dataset, manifest, output)
    assignment = output / "assignments.jsonl"
    assignment.write_text(assignment.read_text(encoding="utf-8").replace('"development"', '"test"', 1), encoding="utf-8")
    with pytest.raises(SplitError, match="assignments artifact hash mismatch"):
        validate_split(dataset, manifest, output)


def test_validator_rejects_changed_source(tmp_path: Path) -> None:
    dataset, manifest = write_dataset(tmp_path)
    output = tmp_path / "split"
    build_split(dataset, manifest, output)
    source = next((dataset / "src").rglob("BenchmarkTest*.java"))
    source.write_text("changed", encoding="utf-8")
    with pytest.raises(SplitError, match="Java corpus hash mismatch"):
        validate_split(dataset, manifest, output)
