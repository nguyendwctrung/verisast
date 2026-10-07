import json
from pathlib import Path

import pytest

from semgrep_review import ReviewError, init_review, validate_review
from semgrep_rules import sha256_file


def write_inventory(tmp_path: Path) -> Path:
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "passed",
                "upstream_commit": "a" * 40,
                "candidate_rule_count": 2,
                "expected_cwes": [78, 89],
                "rules": [
                    {
                        "id": "command-rule",
                        "source_path": "java/command.yaml",
                        "source_sha256": "1" * 64,
                        "cwes": [78],
                        "mode": "taint",
                        "confidence": "HIGH",
                        "technology": ["servlet"],
                    },
                    {
                        "id": "sql-rule",
                        "source_path": "java/sql.yaml",
                        "source_sha256": "2" * 64,
                        "cwes": [89],
                        "mode": "search",
                        "confidence": "MEDIUM",
                        "technology": ["jdbc"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return inventory_path


def test_init_review_creates_complete_needs_evidence_worksheet(
    tmp_path: Path,
) -> None:
    inventory_path = write_inventory(tmp_path)
    output_path = tmp_path / "review.json"

    result = init_review(inventory_path, output_path)

    assert result.review_count == 2
    assert result.needs_evidence_count == 2
    worksheet = json.loads(output_path.read_text(encoding="utf-8"))
    assert worksheet["inventory_sha256"] == sha256_file(inventory_path)
    assert worksheet["upstream_commit"] == "a" * 40
    assert worksheet["reviews"][0]["decision"] == "NEEDS_EVIDENCE"
    assert worksheet["reviews"][0]["reason_codes"] == [
        "INSUFFICIENT_EVIDENCE"
    ]


def test_init_review_rejects_existing_output(tmp_path: Path) -> None:
    inventory_path = write_inventory(tmp_path)
    output_path = tmp_path / "review.json"
    output_path.write_text("existing", encoding="utf-8")

    with pytest.raises(ReviewError, match="already exists"):
        init_review(inventory_path, output_path)


def test_validate_review_reports_decision_and_cwe_counts(tmp_path: Path) -> None:
    inventory_path = write_inventory(tmp_path)
    review_path = tmp_path / "review.json"
    init_review(inventory_path, review_path)
    worksheet = json.loads(review_path.read_text(encoding="utf-8"))
    worksheet["reviews"][0].update(
        {
            "decision": "INCLUDE_DEVELOPMENT",
            "reason_codes": ["CWE_ALIGNED", "BENCHMARK_TECHNOLOGY_MATCH"],
            "benchmark_relevance": "relevant",
            "rationale": "The rule models servlet command input used by the benchmark.",
            "evidence": [
                {
                    "type": "upstream_fixture",
                    "reference": "java/command.java",
                }
            ],
        }
    )
    review_path.write_text(json.dumps(worksheet), encoding="utf-8")

    result = validate_review(inventory_path, review_path)

    assert result.include_count == 1
    assert result.needs_evidence_count == 1
    assert result.exclude_count == 0
    assert result.decision_counts == {
        "EXCLUDE": 0,
        "INCLUDE_DEVELOPMENT": 1,
        "NEEDS_EVIDENCE": 1,
    }
    assert result.include_counts_by_cwe == {78: 1, 89: 0}


def test_validate_review_rejects_missing_inventory_identity(
    tmp_path: Path,
) -> None:
    inventory_path = write_inventory(tmp_path)
    review_path = tmp_path / "review.json"
    init_review(inventory_path, review_path)
    worksheet = json.loads(review_path.read_text(encoding="utf-8"))
    worksheet["reviews"].pop()
    review_path.write_text(json.dumps(worksheet), encoding="utf-8")

    with pytest.raises(ReviewError, match="review identities do not match"):
        validate_review(inventory_path, review_path)


def test_validate_review_rejects_duplicate_identity(tmp_path: Path) -> None:
    inventory_path = write_inventory(tmp_path)
    review_path = tmp_path / "review.json"
    init_review(inventory_path, review_path)
    worksheet = json.loads(review_path.read_text(encoding="utf-8"))
    worksheet["reviews"].append(worksheet["reviews"][0])
    review_path.write_text(json.dumps(worksheet), encoding="utf-8")

    with pytest.raises(ReviewError, match="duplicate review identity"):
        validate_review(inventory_path, review_path)


def test_validate_review_rejects_source_hash_mismatch(tmp_path: Path) -> None:
    inventory_path = write_inventory(tmp_path)
    review_path = tmp_path / "review.json"
    init_review(inventory_path, review_path)
    worksheet = json.loads(review_path.read_text(encoding="utf-8"))
    worksheet["reviews"][0]["source_sha256"] = "f" * 64
    review_path.write_text(json.dumps(worksheet), encoding="utf-8")

    with pytest.raises(ReviewError, match="source hash mismatch"):
        validate_review(inventory_path, review_path)


def test_validate_review_requires_rationale_for_inclusion(
    tmp_path: Path,
) -> None:
    inventory_path = write_inventory(tmp_path)
    review_path = tmp_path / "review.json"
    init_review(inventory_path, review_path)
    worksheet = json.loads(review_path.read_text(encoding="utf-8"))
    worksheet["reviews"][0]["decision"] = "INCLUDE_DEVELOPMENT"
    worksheet["reviews"][0]["reason_codes"] = ["CWE_ALIGNED"]
    review_path.write_text(json.dumps(worksheet), encoding="utf-8")

    with pytest.raises(ReviewError, match="requires a rationale"):
        validate_review(inventory_path, review_path)
