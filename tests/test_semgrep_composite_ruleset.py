import json
from pathlib import Path

import pytest

from semgrep_rules import sha256_file
from semgrep_ruleset import RulesetError, build_composite_ruleset, load_ruleset


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def write_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    upstream_root = tmp_path / "upstream"
    project_root = tmp_path / "project"
    upstream_rule = upstream_root / "java" / "upstream.yaml"
    project_rule = project_root / "rules" / "project" / "project.yaml"
    upstream_rule.parent.mkdir(parents=True)
    project_rule.parent.mkdir(parents=True)
    upstream_rule.write_text("rules: []\n", encoding="utf-8")
    project_rule.write_text("rules: []\n", encoding="utf-8")
    catalog = tmp_path / "catalog.json"
    review = tmp_path / "review.json"
    output = tmp_path / "ruleset.json"
    rules = [
        {
            "id": "upstream-rule",
            "source_path": "java/upstream.yaml",
            "source_sha256": sha256_file(upstream_rule),
            "source_type": "official_upstream",
            "mode": "search",
        },
        {
            "id": "project-cwe327-desede-ecb-default",
            "source_path": "rules/project/project.yaml",
            "source_sha256": sha256_file(project_rule),
            "source_type": "project_authored",
            "source_root": "project_root",
            "mode": "search",
        },
    ]
    write_json(
        catalog,
        {
            "schema_version": 1,
            "status": "passed",
            "upstream_commit": "a" * 40,
            "candidate_rule_count": len(rules),
            "rules": rules,
        },
    )
    write_json(
        review,
        {
            "schema_version": 1,
            "inventory_sha256": sha256_file(catalog),
            "reviews": [
                {
                    "source_path": rule["source_path"],
                    "rule_id": rule["id"],
                    "source_sha256": rule["source_sha256"],
                    "mode": "search",
                    "reviewed_cwes": [78] if index == 0 else [327],
                    "decision": "INCLUDE_DEVELOPMENT",
                }
                for index, rule in enumerate(rules)
            ],
        },
    )
    return upstream_root, project_root, catalog, review, output


def test_build_composite_ruleset_resolves_upstream_and_project_roots(tmp_path: Path) -> None:
    upstream_root, project_root, catalog, review, output = write_inputs(tmp_path)

    result = build_composite_ruleset(
        upstream_rules_dir=upstream_root,
        project_root=project_root,
        catalog_path=catalog,
        review_path=review,
        output_path=output,
        purpose="development",
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert result.rule_count == 2
    assert payload["unresolved_review_count"] == 0
    assert [rule["source_root"] for rule in payload["rules"]] == [
        "upstream_rules",
        "project_root",
    ]
    assert load_ruleset(output, upstream_root, project_root)["rule_count"] == 2


def test_load_composite_ruleset_requires_project_root(tmp_path: Path) -> None:
    upstream_root, project_root, catalog, review, output = write_inputs(tmp_path)
    build_composite_ruleset(
        upstream_rules_dir=upstream_root,
        project_root=project_root,
        catalog_path=catalog,
        review_path=review,
        output_path=output,
        purpose="development",
    )

    with pytest.raises(RulesetError, match="project root is required"):
        load_ruleset(output, upstream_root)


def test_build_composite_ruleset_rejects_changed_project_rule(tmp_path: Path) -> None:
    upstream_root, project_root, catalog, review, output = write_inputs(tmp_path)
    (project_root / "rules" / "project" / "project.yaml").write_text(
        "changed\n", encoding="utf-8"
    )

    with pytest.raises(RulesetError, match="rule hash mismatch"):
        build_composite_ruleset(
            upstream_rules_dir=upstream_root,
            project_root=project_root,
            catalog_path=catalog,
            review_path=review,
            output_path=output,
            purpose="development",
        )


def test_build_composite_ruleset_rejects_review_for_different_catalog(tmp_path: Path) -> None:
    upstream_root, project_root, catalog, review, output = write_inputs(tmp_path)
    review_payload = json.loads(review.read_text(encoding="utf-8"))
    review_payload["inventory_sha256"] = "0" * 64
    write_json(review, review_payload)

    with pytest.raises(RulesetError, match="catalog hash mismatch"):
        build_composite_ruleset(
            upstream_rules_dir=upstream_root,
            project_root=project_root,
            catalog_path=catalog,
            review_path=review,
            output_path=output,
            purpose="development",
        )
