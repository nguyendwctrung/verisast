import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from semgrep_rules import sha256_file


class CompositeReviewError(ValueError):
    pass


@dataclass(frozen=True)
class CompositeReviewResult:
    review_count: int
    output_path: str


def build_composite_review(
    *,
    catalog_path: Path,
    upstream_review_path: Path,
    output_path: Path,
) -> CompositeReviewResult:
    catalog_path = catalog_path.resolve()
    upstream_review_path = upstream_review_path.resolve()
    output_path = output_path.resolve()
    if output_path.exists():
        raise CompositeReviewError(f"review output already exists: {output_path}")

    catalog = _read_object(catalog_path, "composite catalog")
    upstream = _read_object(upstream_review_path, "upstream review")
    catalog_rules = _rules(catalog, "composite catalog")
    upstream_reviews = _reviews(upstream)
    catalog_by_identity = {_identity(rule): rule for rule in catalog_rules}
    upstream_by_identity = {_identity(record): record for record in upstream_reviews}

    if not set(upstream_by_identity).issubset(catalog_by_identity):
        raise CompositeReviewError("upstream review contains identities absent from catalog")
    if len(catalog_by_identity) != len(catalog_rules):
        raise CompositeReviewError("composite catalog contains duplicate identities")

    records: list[dict[str, object]] = []
    for rule in catalog_rules:
        identity = _identity(rule)
        existing = upstream_by_identity.get(identity)
        if existing is not None:
            records.append(existing)
            continue
        if rule.get("source_type") != "project_authored":
            raise CompositeReviewError("catalog contains an unreviewed non-project rule")
        records.append(_project_review(rule))

    payload = {
        "schema_version": 1,
        "status": "in_progress",
        "generated_at": upstream.get("generated_at"),
        "inventory_path": catalog_path.name,
        "inventory_sha256": sha256_file(catalog_path),
        "upstream_commit": catalog.get("upstream_commit"),
        "candidate_rule_count": len(records),
        "allowed_decisions": upstream.get("allowed_decisions"),
        "allowed_reason_codes": upstream.get("allowed_reason_codes"),
        "reviews": records,
    }
    _write_json(output_path, payload)
    return CompositeReviewResult(len(records), str(output_path))


def _project_review(rule: dict[str, object]) -> dict[str, object]:
    cwes = rule.get("cwes")
    if not isinstance(cwes, list) or 327 not in cwes:
        raise CompositeReviewError("project rule must declare CWE-327")
    return {
        "source_path": rule["source_path"],
        "source_sha256": rule["source_sha256"],
        "rule_id": rule["id"],
        "declared_cwes": cwes,
        "reviewed_cwes": [327],
        "mode": rule["mode"],
        "confidence": rule.get("confidence"),
        "technology": rule["technology"],
        "decision": "INCLUDE_DEVELOPMENT",
        "reason_codes": ["CWE_ALIGNED", "BENCHMARK_TECHNOLOGY_MATCH"],
        "benchmark_relevance": "relevant",
        "rationale": (
            "Matches the independently audited Properties default "
            "DESede/ECB/PKCS5Padding pattern and is distinct from "
            "cbc-padding-oracle."
        ),
        "evidence": [
            {
                "type": "project_rule_manifest",
                "reference": "rules/project/manifest.json",
            },
            {
                "type": "benchmark_api_review",
                "reference": (
                    "The frozen OWASP source has 33 Properties.getProperty "
                    "defaults for DESede/ECB/PKCS5Padding."
                ),
            },
        ],
        "notes": "Project-authored rule; content is pinned in the project manifest.",
    }


def _rules(value: dict[str, object], label: str) -> list[dict[str, object]]:
    if value.get("schema_version") != 1 or value.get("status") != "passed":
        raise CompositeReviewError(f"{label} is not a passed schema version 1 artifact")
    rules = value.get("rules")
    if not isinstance(rules, list) or not rules:
        raise CompositeReviewError(f"{label} has no rules")
    return [rule for rule in rules if isinstance(rule, dict)]


def _reviews(value: dict[str, object]) -> list[dict[str, object]]:
    if value.get("schema_version") != 1:
        raise CompositeReviewError("upstream review schema version is unsupported")
    reviews = value.get("reviews")
    if not isinstance(reviews, list) or not reviews:
        raise CompositeReviewError("upstream review has no records")
    return [record for record in reviews if isinstance(record, dict)]


def _identity(value: dict[str, object]) -> tuple[str, str]:
    source_path = value.get("source_path")
    rule_id = value.get("id", value.get("rule_id"))
    if not isinstance(source_path, str) or not isinstance(rule_id, str):
        raise CompositeReviewError("record has an invalid identity")
    return source_path, rule_id


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CompositeReviewError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise CompositeReviewError(f"{label} must be a JSON object")
    return value


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--upstream-review", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_composite_review(
        catalog_path=args.catalog,
        upstream_review_path=args.upstream_review,
        output_path=args.output,
    )
    print(f"COMPOSITE_REVIEW={result.output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
