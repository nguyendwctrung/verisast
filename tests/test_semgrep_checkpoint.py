import json
from pathlib import Path

import pytest

from semgrep_checkpoint import EXPECTED_DECISIONS, CheckpointError, validate_checkpoint


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def write_case(dataset: Path, name: str, source: str) -> None:
    source_dir = dataset / "src" / "main" / "java" / "example"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / f"{name}.java").write_text(source, encoding="utf-8")


def common_evidence(tmp_path: Path, cwe: int, rule_id: str) -> dict[str, Path]:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    review = tmp_path / "review.json"
    fixtures = tmp_path / "fixtures.json"
    compatibility = tmp_path / "compatibility.json"
    write_json(
        review,
        {
            "reviews": [
                {
                    "rule_id": rule_id,
                    "reviewed_cwes": [cwe],
                    "decision": "INCLUDE_DEVELOPMENT",
                    "benchmark_relevance": "relevant",
                }
            ]
        },
    )
    write_json(
        fixtures,
        {
            "files": [
                {
                    "rule_ids": [rule_id],
                    "test_status": "PASS",
                    "positive_annotations": 1,
                    "negative_annotations": 1,
                }
            ]
        },
    )
    write_json(
        compatibility,
        {
            "files": [
                {
                    "rule_ids": [rule_id],
                    "status": "COMPATIBLE",
                    "exit_code": 0,
                }
            ]
        },
    )
    return {
        "dataset": dataset,
        "review": review,
        "fixtures": fixtures,
        "compatibility": compatibility,
    }


def test_validates_cwe330_profile(tmp_path: Path) -> None:
    paths = common_evidence(tmp_path, 330, "weak-random")
    ground_truth = paths["dataset"] / "expectedresults-1.2.csv"
    ground_truth.write_text(
        "# header\n"
        "BenchmarkTest00001,weakrand,true,330\n"
        "BenchmarkTest00002,weakrand,false,330\n",
        encoding="utf-8",
    )
    write_case(
        paths["dataset"],
        "BenchmarkTest00001",
        "class A { double x = java.lang.Math.random(); }",
    )
    write_case(
        paths["dataset"],
        "BenchmarkTest00002",
        "class B { java.security.SecureRandom x; }",
    )

    result = validate_checkpoint(cwe=330, **paths)

    assert result.cwe == 330
    assert result.case_count == 2
    assert result.vulnerable_count == 1
    assert result.non_vulnerable_count == 1
    assert result.metrics["vulnerable_rule_covered_files"] == 1
    assert result.metrics["non_vulnerable_weak_rng_files"] == 0


def test_validates_cwe328_profile(tmp_path: Path) -> None:
    paths = common_evidence(tmp_path, 328, "use-of-md5")
    review = json.loads(paths["review"].read_text(encoding="utf-8"))
    review["reviews"].extend(
        {
            "rule_id": rule_id,
            "reviewed_cwes": [328],
            "decision": decision,
            "benchmark_relevance": relevance,
        }
        for rule_id, decision, relevance in (
            ("use-of-md5-digest-utils", "EXCLUDE", "not_relevant"),
            ("use-of-sha1", "INCLUDE_DEVELOPMENT", "relevant"),
            ("use-of-sha224", "EXCLUDE", "not_relevant"),
        )
    )
    write_json(paths["review"], review)
    fixtures = json.loads(paths["fixtures"].read_text(encoding="utf-8"))
    for rule_id in (
        "use-of-md5-digest-utils",
        "use-of-sha1",
        "use-of-sha224",
    ):
        fixtures["files"].append(
            {
                "rule_ids": [rule_id],
                "test_status": "PASS",
                "positive_annotations": 1,
                "negative_annotations": 1,
            }
        )
    write_json(paths["fixtures"], fixtures)
    compatibility = json.loads(
        paths["compatibility"].read_text(encoding="utf-8")
    )
    for rule_id in (
        "use-of-md5-digest-utils",
        "use-of-sha1",
        "use-of-sha224",
    ):
        compatibility["files"].append(
            {
                "rule_ids": [rule_id],
                "status": "COMPATIBLE",
                "exit_code": 0,
            }
        )
    write_json(paths["compatibility"], compatibility)
    ground_truth = paths["dataset"] / "expectedresults-1.2.csv"
    ground_truth.write_text(
        "# header\n"
        "BenchmarkTest00001,hash,true,328\n"
        "BenchmarkTest00002,hash,false,328\n",
        encoding="utf-8",
    )
    write_case(
        paths["dataset"],
        "BenchmarkTest00001",
        'class A { Object x = MessageDigest.getInstance("MD5"); }',
    )
    write_case(
        paths["dataset"],
        "BenchmarkTest00002",
        'class B { Object x = MessageDigest.getInstance("SHA-256"); }',
    )

    result = validate_checkpoint(cwe=328, **paths)

    assert result.metrics["message_digest_md5"] == 1
    assert result.metrics["message_digest_sha256"] == 1
    assert result.metrics["digest_utils_files"] == 0
    assert result.metrics["sha224_files"] == 0


def test_rejects_unsupported_cwe(tmp_path: Path) -> None:
    paths = common_evidence(tmp_path, 22, "example")

    with pytest.raises(CheckpointError, match="unsupported CWE: 22"):
        validate_checkpoint(cwe=22, **paths)


def test_cwe327_profile_keeps_only_padding_oracle_rule() -> None:
    included = {
        rule_id
        for rule_id, (decision, _) in EXPECTED_DECISIONS[327].items()
        if decision == "INCLUDE_DEVELOPMENT"
    }
    assert included == {"cbc-padding-oracle"}
    assert len(EXPECTED_DECISIONS[327]) == 12
