import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from semgrep_review import ReviewError, validate_review
from semgrep_rules import sha256_file

SCHEMA_VERSION = 1
PURPOSES = {"development", "reportable"}


class RulesetError(ValueError):
    pass


@dataclass(frozen=True)
class RulesetResult:
    status: str
    purpose: str
    reportable: bool
    rule_count: int
    unresolved_count: int
    output_path: str


def build_ruleset(
    rules_dir: Path,
    inventory_path: Path,
    review_path: Path,
    output_path: Path,
    purpose: str,
) -> RulesetResult:
    if purpose not in PURPOSES:
        raise RulesetError(f"invalid ruleset purpose: {purpose}")
    rules_dir = rules_dir.resolve()
    inventory_path = inventory_path.resolve()
    review_path = review_path.resolve()
    output_path = output_path.resolve()
    if output_path.exists():
        raise RulesetError(f"ruleset output already exists: {output_path}")
    try:
        review_result = validate_review(inventory_path, review_path)
    except ReviewError as error:
        raise RulesetError(str(error)) from error
    review = _read_object(review_path, "review worksheet")
    unresolved = review_result.needs_evidence_count
    if purpose == "reportable" and unresolved:
        raise RulesetError(
            f"reportable ruleset requires zero unresolved rules; found {unresolved}"
        )
    selected = []
    raw_reviews = cast(list[object], review["reviews"])
    for value in raw_reviews:
        if not isinstance(value, dict):
            raise RulesetError("review record must be an object")
        record = cast(dict[str, object], value)
        if not isinstance(record, dict) or record.get("decision") != "INCLUDE_DEVELOPMENT":
            continue
        relative_path = str(record["source_path"])
        rule_path = (rules_dir / relative_path).resolve()
        if not rule_path.is_relative_to(rules_dir) or not rule_path.is_file():
            raise RulesetError(f"rule file not found: {relative_path}")
        expected_hash = str(record["source_sha256"])
        if sha256_file(rule_path) != expected_hash:
            raise RulesetError(f"rule hash mismatch: {relative_path}")
        rule_id = str(record["rule_id"])
        selected.append(
            {
                "identity": f"{relative_path}::{rule_id}",
                "rule_id": rule_id,
                "source_path": relative_path,
                "source_sha256": expected_hash,
                "reviewed_cwes": list(cast(list[int], record["reviewed_cwes"])),
                "mode": record["mode"],
            }
        )
    if not selected:
        raise RulesetError("ruleset contains no included rules")
    identities = [item["identity"] for item in selected]
    if len(identities) != len(set(identities)):
        raise RulesetError("ruleset contains duplicate identities")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "status": "frozen" if purpose == "reportable" else "development",
        "purpose": purpose,
        "reportable": purpose == "reportable",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "upstream_commit": review["upstream_commit"],
        "inventory_path": inventory_path.name,
        "inventory_sha256": sha256_file(inventory_path),
        "review_path": review_path.name,
        "review_sha256": sha256_file(review_path),
        "unresolved_review_count": unresolved,
        "rule_count": len(selected),
        "cwes": sorted(
            {
                cwe
                for item in selected
                for cwe in cast(list[int], item["reviewed_cwes"])
            }
        ),
        "rules": selected,
    }
    _write_json(output_path, payload)
    return RulesetResult(
        status=str(payload["status"]),
        purpose=purpose,
        reportable=bool(payload["reportable"]),
        rule_count=len(selected),
        unresolved_count=unresolved,
        output_path=str(output_path),
    )


def load_ruleset(path: Path, rules_dir: Path | None = None) -> dict[str, object]:
    path = path.resolve()
    payload = _read_object(path, "ruleset")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise RulesetError("unsupported ruleset schema version")
    purpose = payload.get("purpose")
    if purpose not in PURPOSES:
        raise RulesetError("invalid ruleset purpose")
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RulesetError("ruleset rules must be a non-empty list")
    if payload.get("rule_count") != len(rules):
        raise RulesetError("ruleset rule count mismatch")
    identities: set[str] = set()
    for index, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            raise RulesetError(f"ruleset rule {index} must be an object")
        identity = rule.get("identity")
        if not isinstance(identity, str) or identity in identities:
            raise RulesetError("ruleset contains duplicate or invalid identities")
        identities.add(identity)
        if rules_dir is not None:
            root = rules_dir.resolve()
            rule_path = (root / str(rule.get("source_path", ""))).resolve()
            if not rule_path.is_relative_to(root) or not rule_path.is_file():
                raise RulesetError(f"rule file not found: {rule.get('source_path')}")
            if sha256_file(rule_path) != rule.get("source_sha256"):
                raise RulesetError(f"rule hash mismatch: {rule.get('source_path')}")
    if purpose == "reportable":
        if payload.get("status") != "frozen" or payload.get("reportable") is not True:
            raise RulesetError("invalid reportable ruleset status")
        if payload.get("unresolved_review_count") != 0:
            raise RulesetError("reportable ruleset contains unresolved reviews")
    return payload


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RulesetError(f"failed to read {label}: {error}") from error
    if not isinstance(value, dict):
        raise RulesetError(f"{label} must be a JSON object")
    return value


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
