import json
from pathlib import Path

import pytest

from semgrep_rules import sha256_file
from semgrep_ruleset import RulesetError, build_ruleset, load_ruleset


def write_inputs(tmp_path: Path, unresolved: bool = True) -> tuple[Path, Path, Path]:
    rules_dir = tmp_path / "rules"
    rule_path = rules_dir / "java" / "rule.yaml"
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text("rules:\n- id: test-rule\n  languages: [java]\n  message: test\n  severity: ERROR\n  pattern: $X\n", encoding="utf-8")
    inventory_path = tmp_path / "inventory.json"
    inventory = {
        "schema_version": 1,
        "status": "passed",
        "upstream_commit": "a" * 40,
        "candidate_rule_count": 2 if unresolved else 1,
        "rules": [
            {
                "id": "test-rule",
                "source_path": "java/rule.yaml",
                "source_sha256": sha256_file(rule_path),
                "cwes": [78],
                "mode": "search",
                "confidence": "HIGH",
                "technology": ["java"],
            }
        ],
    }
    if unresolved:
        other_path = rules_dir / "java" / "other.yaml"
        other_path.write_text(rule_path.read_text(encoding="utf-8").replace("test-rule", "other-rule"), encoding="utf-8")
        inventory["rules"].append(
            {
                "id": "other-rule",
                "source_path": "java/other.yaml",
                "source_sha256": sha256_file(other_path),
                "cwes": [89],
                "mode": "search",
                "confidence": "MEDIUM",
                "technology": ["jdbc"],
            }
        )
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    reviews = []
    for index, rule in enumerate(inventory["rules"]):
        included = index == 0
        reviews.append(
            {
                "source_path": rule["source_path"],
                "source_sha256": rule["source_sha256"],
                "rule_id": rule["id"],
                "declared_cwes": rule["cwes"],
                "reviewed_cwes": rule["cwes"],
                "mode": rule["mode"],
                "confidence": rule["confidence"],
                "technology": rule["technology"],
                "decision": "INCLUDE_DEVELOPMENT" if included else "NEEDS_EVIDENCE",
                "reason_codes": ["CWE_ALIGNED"] if included else ["INSUFFICIENT_EVIDENCE"],
                "benchmark_relevance": "relevant" if included else "unknown",
                "rationale": "Applicable rule." if included else "",
                "evidence": [{"type": "fixture", "reference": "fixture.java"}] if included else [],
                "notes": "",
            }
        )
    review_path = tmp_path / "review.json"
    review_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "in_progress",
                "inventory_sha256": sha256_file(inventory_path),
                "upstream_commit": "a" * 40,
                "candidate_rule_count": len(reviews),
                "allowed_decisions": ["EXCLUDE", "INCLUDE_DEVELOPMENT", "NEEDS_EVIDENCE"],
                "allowed_reason_codes": [
                    "BENCHMARK_TECHNOLOGY_MATCH", "CWE_ALIGNED", "CWE_METADATA_MISMATCH",
                    "DUPLICATE_SEMANTICS", "GENERIC_JAVA_SECURITY", "INSUFFICIENT_EVIDENCE",
                    "OUT_OF_BENCHMARK_SCOPE", "PRO_ONLY_OR_UNSUPPORTED", "TECHNOLOGY_NOT_PRESENT",
                ],
                "reviews": reviews,
            }
        ),
        encoding="utf-8",
    )
    return rules_dir, inventory_path, review_path


def test_build_development_ruleset_selects_included_rules(tmp_path: Path) -> None:
    rules_dir, inventory, review = write_inputs(tmp_path)
    output = tmp_path / "ruleset.json"
    result = build_ruleset(rules_dir, inventory, review, output, "development")
    payload = load_ruleset(output, rules_dir)
    assert result.rule_count == 1
    assert result.unresolved_count == 1
    assert payload["reportable"] is False
    assert payload["rules"][0]["identity"] == "java/rule.yaml::test-rule"


def test_build_reportable_ruleset_rejects_unresolved_review(tmp_path: Path) -> None:
    rules_dir, inventory, review = write_inputs(tmp_path)
    with pytest.raises(RulesetError, match="unresolved"):
        build_ruleset(rules_dir, inventory, review, tmp_path / "out.json", "reportable")


def test_load_ruleset_rejects_changed_rule(tmp_path: Path) -> None:
    rules_dir, inventory, review = write_inputs(tmp_path, unresolved=False)
    output = tmp_path / "ruleset.json"
    build_ruleset(rules_dir, inventory, review, output, "reportable")
    (rules_dir / "java" / "rule.yaml").write_text("changed", encoding="utf-8")
    with pytest.raises(RulesetError, match="hash mismatch"):
        load_ruleset(output, rules_dir)
