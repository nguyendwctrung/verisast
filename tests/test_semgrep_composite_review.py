import json
from pathlib import Path

from semgrep_composite_review import build_composite_review
from semgrep_rules import sha256_file


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_composite_review_preserves_upstream_and_adds_project_rule(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    upstream = tmp_path / "upstream-review.json"
    output = tmp_path / "review.json"
    write_json(catalog, {"schema_version": 1, "status": "passed", "upstream_commit": "a" * 40, "rules": [
        {"id": "upstream", "source_path": "java/a.yaml", "source_sha256": "1" * 64},
        {"id": "project-cwe327-desede-ecb-default", "source_path": "rules/project/rule.yaml", "source_sha256": "2" * 64, "source_type": "project_authored", "cwes": [327], "mode": "search", "confidence": "HIGH", "technology": ["java"]},
    ]})
    write_json(upstream, {"schema_version": 1, "generated_at": "x", "allowed_decisions": ["EXCLUDE", "INCLUDE_DEVELOPMENT", "NEEDS_EVIDENCE"], "allowed_reason_codes": ["BENCHMARK_TECHNOLOGY_MATCH", "CWE_ALIGNED"], "reviews": [
        {"source_path": "java/a.yaml", "rule_id": "upstream", "decision": "EXCLUDE"}
    ]})

    result = build_composite_review(catalog_path=catalog, upstream_review_path=upstream, output_path=output)

    assert result.review_count == 2
    review = json.loads(output.read_text(encoding="utf-8"))
    assert review["inventory_sha256"] == sha256_file(catalog)
    assert review["reviews"][0]["decision"] == "EXCLUDE"
    assert review["reviews"][1]["decision"] == "INCLUDE_DEVELOPMENT"
