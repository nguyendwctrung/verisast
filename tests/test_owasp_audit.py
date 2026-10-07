import json
from pathlib import Path

import pytest

from owasp_audit import AuditError, GitInfo, audit_dataset, load_ground_truth, map_java_sources


FROZEN_COMMIT = "8b67a88d73b2594570fc21150705283de884620b"


def write_ground_truth(path: Path, rows: list[str]) -> None:
    content = [
        "# test name, category, real vulnerability, cwe, Benchmark version: 1.2",
        *rows,
    ]
    path.write_text("\n".join(content) + "\n", encoding="utf-8")


def write_dataset(root: Path, rows: list[str]) -> None:
    root.mkdir(parents=True)
    write_ground_truth(root / "expectedresults-1.2.csv", rows)
    (root / "LICENSE").write_text("license\n", encoding="utf-8")
    (root / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    source_dir = root / "src" / "main" / "java"
    source_dir.mkdir(parents=True)
    for row in rows:
        test_id = row.split(",", maxsplit=1)[0]
        (source_dir / f"{test_id}.java").write_text(
            f"class {test_id} {{}}\n",
            encoding="utf-8",
        )


def clean_git_info() -> GitInfo:
    return GitInfo(
        remote_url="https://github.com/OWASP-Benchmark/BenchmarkJava.git",
        commit=FROZEN_COMMIT,
        clean=True,
        detached=True,
    )


def test_load_ground_truth_accepts_valid_rows(tmp_path: Path) -> None:
    csv_path = tmp_path / "expectedresults-1.2.csv"
    write_ground_truth(
        csv_path,
        [
            "BenchmarkTest00001,pathtraver,true,22",
            "BenchmarkTest00002,sqli,false,89",
        ],
    )

    records = load_ground_truth(csv_path)

    assert [record.test_id for record in records] == [
        "BenchmarkTest00001",
        "BenchmarkTest00002",
    ]
    assert records[0].vulnerable is True
    assert records[1].vulnerable is False
    assert records[1].cwe == 89


@pytest.mark.parametrize(
    "rows, expected_message",
    [
        (
            [
                "BenchmarkTest00001,pathtraver,true,22",
                "BenchmarkTest00001,pathtraver,false,22",
            ],
            "duplicate test ID",
        ),
        (["BadId,pathtraver,true,22"], "invalid test ID"),
        (["BenchmarkTest00001,pathtraver,unknown,22"], "invalid label"),
        (["BenchmarkTest00001,pathtraver,true,not-a-cwe"], "invalid CWE"),
        (["BenchmarkTest00001,pathtraver,true"], "expected 4 columns"),
    ],
)
def test_load_ground_truth_rejects_invalid_rows(
    tmp_path: Path,
    rows: list[str],
    expected_message: str,
) -> None:
    csv_path = tmp_path / "expectedresults-1.2.csv"
    write_ground_truth(csv_path, rows)

    with pytest.raises(AuditError, match=expected_message):
        load_ground_truth(csv_path)


def test_map_java_sources_requires_one_source_per_record(tmp_path: Path) -> None:
    csv_path = tmp_path / "expectedresults-1.2.csv"
    write_ground_truth(
        csv_path,
        [
            "BenchmarkTest00001,pathtraver,true,22",
            "BenchmarkTest00002,sqli,false,89",
        ],
    )
    records = load_ground_truth(csv_path)
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "BenchmarkTest00001.java").write_text(
        "class BenchmarkTest00001 {}\n",
        encoding="utf-8",
    )

    with pytest.raises(AuditError, match="missing Java source.*BenchmarkTest00002"):
        map_java_sources(source_dir, records)


def test_map_java_sources_rejects_orphan_source(tmp_path: Path) -> None:
    csv_path = tmp_path / "expectedresults-1.2.csv"
    write_ground_truth(csv_path, ["BenchmarkTest00001,pathtraver,true,22"])
    records = load_ground_truth(csv_path)
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    for test_id in ("BenchmarkTest00001", "BenchmarkTest99999"):
        (source_dir / f"{test_id}.java").write_text(
            f"class {test_id} {{}}\n",
            encoding="utf-8",
        )

    with pytest.raises(AuditError, match="orphan Java source.*BenchmarkTest99999"):
        map_java_sources(source_dir, records)


def test_audit_dataset_writes_manifest_outside_raw_dataset(tmp_path: Path) -> None:
    dataset_dir = tmp_path / "raw" / "owasp"
    rows = [
        "BenchmarkTest00001,pathtraver,true,22",
        "BenchmarkTest00002,sqli,false,89",
    ]
    write_dataset(dataset_dir, rows)
    manifest_path = tmp_path / "manifests" / "owasp.json"

    result = audit_dataset(
        dataset_dir=dataset_dir,
        manifest_path=manifest_path,
        expected_commit=FROZEN_COMMIT,
        expected_records=2,
        expected_cwes={22, 89},
        git_reader=lambda _: clean_git_info(),
    )

    assert result.audit_status == "passed"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["dataset_id"] == "owasp-benchmark-java-v1.2"
    assert manifest["frozen_commit"] == FROZEN_COMMIT
    assert manifest["testcase_count"] == 2
    assert manifest["label_counts"] == {"false": 1, "true": 1}
    assert manifest["cwe_counts"] == {"22": 1, "89": 1}
    assert manifest["audit_status"] == "passed"
    assert not manifest_path.is_relative_to(dataset_dir)


@pytest.mark.parametrize(
    "git_info, expected_message",
    [
        (
            GitInfo("https://example.com/wrong.git", FROZEN_COMMIT, True, True),
            "unexpected Git remote",
        ),
        (
            GitInfo(
                "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
                "0" * 40,
                True,
                True,
            ),
            "unexpected Git commit",
        ),
        (
            GitInfo(
                "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
                FROZEN_COMMIT,
                False,
                True,
            ),
            "working tree is not clean",
        ),
        (
            GitInfo(
                "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
                FROZEN_COMMIT,
                True,
                False,
            ),
            "HEAD is not detached",
        ),
    ],
)
def test_audit_dataset_rejects_invalid_provenance(
    tmp_path: Path,
    git_info: GitInfo,
    expected_message: str,
) -> None:
    dataset_dir = tmp_path / "raw" / "owasp"
    write_dataset(dataset_dir, ["BenchmarkTest00001,pathtraver,true,22"])

    with pytest.raises(AuditError, match=expected_message):
        audit_dataset(
            dataset_dir=dataset_dir,
            manifest_path=tmp_path / "manifest.json",
            expected_commit=FROZEN_COMMIT,
            expected_records=1,
            expected_cwes={22},
            git_reader=lambda _: git_info,
        )


def test_audit_dataset_rejects_manifest_inside_raw_dataset(tmp_path: Path) -> None:
    dataset_dir = tmp_path / "raw" / "owasp"
    write_dataset(dataset_dir, ["BenchmarkTest00001,pathtraver,true,22"])

    with pytest.raises(AuditError, match="manifest must be outside"):
        audit_dataset(
            dataset_dir=dataset_dir,
            manifest_path=dataset_dir / "manifest.json",
            expected_commit=FROZEN_COMMIT,
            expected_records=1,
            expected_cwes={22},
            git_reader=lambda _: clean_git_info(),
        )
