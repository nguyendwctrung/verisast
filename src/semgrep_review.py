import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from semgrep_rules import sha256_file

SCHEMA_VERSION = 1
DECISIONS = (
    "EXCLUDE",
    "INCLUDE_DEVELOPMENT",
    "NEEDS_EVIDENCE",
)
REASON_CODES = frozenset(
    {
        "BENCHMARK_TECHNOLOGY_MATCH",
        "CWE_ALIGNED",
        "CWE_METADATA_MISMATCH",
        "DUPLICATE_SEMANTICS",
        "GENERIC_JAVA_SECURITY",
        "INSUFFICIENT_EVIDENCE",
        "OUT_OF_BENCHMARK_SCOPE",
        "PRO_ONLY_OR_UNSUPPORTED",
        "TECHNOLOGY_NOT_PRESENT",
    }
)
BENCHMARK_RELEVANCE = frozenset({"not_relevant", "relevant", "unknown"})


class ReviewError(ValueError):
    """Raised when a rule review worksheet is incomplete or inconsistent."""


@dataclass(frozen=True)
class ReviewResult:
    status: str
    upstream_commit: str
    review_count: int
    include_count: int
    exclude_count: int
    needs_evidence_count: int
    decision_counts: dict[str, int]
    include_counts_by_cwe: dict[int, int]
    review_path: str


def init_review(inventory_path: Path, output_path: Path) -> ReviewResult:
    inventory_path = _require_file(inventory_path, "inventory")
    output_path = output_path.resolve()
    if output_path.exists():
        raise ReviewError(f"review worksheet already exists: {output_path}")

    inventory, rules = _load_inventory(inventory_path)
    reviews = [_initial_review(rule) for rule in rules]
    worksheet = {
        "schema_version": SCHEMA_VERSION,
        "status": "in_progress",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inventory_path": inventory_path.name,
        "inventory_sha256": sha256_file(inventory_path),
        "upstream_commit": inventory["upstream_commit"],
        "candidate_rule_count": len(reviews),
        "allowed_decisions": list(DECISIONS),
        "allowed_reason_codes": sorted(REASON_CODES),
        "reviews": reviews,
    }
    _write_json_atomic(output_path, worksheet)
    return _result(
        str(inventory["upstream_commit"]),
        reviews,
        output_path,
    )


def validate_review(
    inventory_path: Path,
    review_path: Path,
) -> ReviewResult:
    inventory_path = _require_file(inventory_path, "inventory")
    review_path = _require_file(review_path, "review worksheet")
    inventory, rules = _load_inventory(inventory_path)
    worksheet = _load_json(review_path, "review worksheet")

    if worksheet.get("schema_version") != SCHEMA_VERSION:
        raise ReviewError("unsupported review worksheet schema version")
    if worksheet.get("inventory_sha256") != sha256_file(inventory_path):
        raise ReviewError("inventory hash mismatch")
    if worksheet.get("upstream_commit") != inventory["upstream_commit"]:
        raise ReviewError("upstream commit mismatch")
    if worksheet.get("candidate_rule_count") != len(rules):
        raise ReviewError("review candidate count mismatch")
    if worksheet.get("allowed_decisions") != list(DECISIONS):
        raise ReviewError("review decision vocabulary mismatch")
    if worksheet.get("allowed_reason_codes") != sorted(REASON_CODES):
        raise ReviewError("review reason-code vocabulary mismatch")

    raw_reviews = worksheet.get("reviews")
    if not isinstance(raw_reviews, list):
        raise ReviewError("reviews must be a list")
    reviews = [_review_object(value, index) for index, value in enumerate(raw_reviews, 1)]

    inventory_by_identity = {_identity(rule): rule for rule in rules}
    review_by_identity: dict[tuple[str, str], dict[str, object]] = {}
    for review in reviews:
        identity = _identity(review)
        if identity in review_by_identity:
            raise ReviewError(
                f"duplicate review identity: {identity[0]}::{identity[1]}"
            )
        review_by_identity[identity] = review
    if set(review_by_identity) != set(inventory_by_identity):
        raise ReviewError("review identities do not match inventory identities")

    for identity, review in review_by_identity.items():
        _validate_record(review, inventory_by_identity[identity])

    ordered_reviews = [review_by_identity[_identity(rule)] for rule in rules]
    return _result(
        str(inventory["upstream_commit"]),
        ordered_reviews,
        review_path,
    )


def _load_inventory(
    path: Path,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    inventory = _load_json(path, "inventory")
    if inventory.get("schema_version") != 1 or inventory.get("status") != "passed":
        raise ReviewError("inventory is not a passed schema version 1 report")
    commit = inventory.get("upstream_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReviewError("inventory upstream_commit is invalid")
    raw_rules = inventory.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ReviewError("inventory rules must be a non-empty list")
    rules = [_inventory_rule(value, index) for index, value in enumerate(raw_rules, 1)]
    if inventory.get("candidate_rule_count") != len(rules):
        raise ReviewError("inventory candidate count mismatch")
    identities = [_identity(rule) for rule in rules]
    if len(identities) != len(set(identities)):
        raise ReviewError("inventory contains duplicate rule identities")
    return inventory, rules


def _inventory_rule(value: object, index: int) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReviewError(f"inventory rule {index} must be an object")
    for field in ("id", "source_path", "source_sha256", "mode"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise ReviewError(f"inventory rule {index} has invalid {field}")
    if not re.fullmatch(r"[0-9a-f]{64}", str(value["source_sha256"])):
        raise ReviewError(f"inventory rule {index} has invalid source_sha256")
    _int_list(value.get("cwes"), f"inventory rule {index} cwes")
    _text_list(value.get("technology"), f"inventory rule {index} technology")
    confidence = value.get("confidence")
    if confidence is not None and not isinstance(confidence, str):
        raise ReviewError(f"inventory rule {index} has invalid confidence")
    return value


def _initial_review(rule: dict[str, object]) -> dict[str, object]:
    return {
        "source_path": rule["source_path"],
        "source_sha256": rule["source_sha256"],
        "rule_id": rule["id"],
        "declared_cwes": rule["cwes"],
        "reviewed_cwes": rule["cwes"],
        "mode": rule["mode"],
        "confidence": rule.get("confidence"),
        "technology": rule["technology"],
        "decision": "NEEDS_EVIDENCE",
        "reason_codes": ["INSUFFICIENT_EVIDENCE"],
        "benchmark_relevance": "unknown",
        "rationale": "",
        "evidence": [],
        "notes": "",
    }


def _review_object(value: object, index: int) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReviewError(f"review {index} must be an object")
    return value


def _validate_record(
    review: dict[str, object],
    inventory_rule: dict[str, object],
) -> None:
    identity = _identity(review)
    label = f"{identity[0]}::{identity[1]}"
    if review.get("source_sha256") != inventory_rule["source_sha256"]:
        raise ReviewError(f"source hash mismatch: {label}")
    declared = _int_list(review.get("declared_cwes"), f"declared_cwes for {label}")
    inventory_cwes = _int_list(
        inventory_rule.get("cwes"), f"inventory cwes for {label}"
    )
    if declared != inventory_cwes:
        raise ReviewError(f"declared CWE mismatch: {label}")
    if review.get("mode") != inventory_rule["mode"]:
        raise ReviewError(f"mode mismatch: {label}")
    if review.get("confidence") != inventory_rule.get("confidence"):
        raise ReviewError(f"confidence mismatch: {label}")
    if _text_list(review.get("technology"), f"technology for {label}") != _text_list(
        inventory_rule.get("technology"), f"inventory technology for {label}"
    ):
        raise ReviewError(f"technology mismatch: {label}")

    reviewed = _int_list(review.get("reviewed_cwes"), f"reviewed_cwes for {label}")
    if not set(reviewed).issubset(declared):
        raise ReviewError(f"reviewed CWEs must be a subset of declared CWEs: {label}")
    decision = review.get("decision")
    if decision not in DECISIONS:
        raise ReviewError(f"invalid decision for {label}")
    reasons = _text_list(review.get("reason_codes"), f"reason_codes for {label}")
    if not reasons or any(reason not in REASON_CODES for reason in reasons):
        raise ReviewError(f"invalid reason codes for {label}")
    relevance = review.get("benchmark_relevance")
    if relevance not in BENCHMARK_RELEVANCE:
        raise ReviewError(f"invalid benchmark relevance for {label}")
    rationale = review.get("rationale")
    if not isinstance(rationale, str):
        raise ReviewError(f"invalid rationale for {label}")
    if decision != "NEEDS_EVIDENCE" and not rationale.strip():
        raise ReviewError(f"{decision} requires a rationale: {label}")
    if decision == "INCLUDE_DEVELOPMENT" and not reviewed:
        raise ReviewError(f"included rule requires reviewed CWEs: {label}")
    if decision != "NEEDS_EVIDENCE" and "INSUFFICIENT_EVIDENCE" in reasons:
        raise ReviewError(f"resolved decision has insufficient evidence: {label}")
    _validate_evidence(review.get("evidence"), label)
    notes = review.get("notes")
    if not isinstance(notes, str):
        raise ReviewError(f"invalid notes for {label}")


def _validate_evidence(value: object, label: str) -> None:
    if not isinstance(value, list):
        raise ReviewError(f"evidence must be a list for {label}")
    for index, item in enumerate(value, 1):
        if not isinstance(item, dict):
            raise ReviewError(f"evidence {index} must be an object for {label}")
        if not isinstance(item.get("type"), str) or not item["type"].strip():
            raise ReviewError(f"evidence {index} has invalid type for {label}")
        reference = item.get("reference")
        if not isinstance(reference, str) or not reference.strip():
            raise ReviewError(f"evidence {index} has invalid reference for {label}")


def _result(
    upstream_commit: str,
    reviews: list[dict[str, object]],
    review_path: Path,
) -> ReviewResult:
    decisions = Counter(str(review["decision"]) for review in reviews)
    cwe_counts: Counter[int] = Counter()
    for review in reviews:
        if review["decision"] == "INCLUDE_DEVELOPMENT":
            cwe_counts.update(_int_list(review["reviewed_cwes"], "reviewed_cwes"))
    all_cwes = sorted(
        {
            cwe
            for review in reviews
            for cwe in _int_list(review["declared_cwes"], "declared_cwes")
        }
    )
    decision_counts = {decision: decisions[decision] for decision in DECISIONS}
    return ReviewResult(
        status="completed",
        upstream_commit=upstream_commit,
        review_count=len(reviews),
        include_count=decisions["INCLUDE_DEVELOPMENT"],
        exclude_count=decisions["EXCLUDE"],
        needs_evidence_count=decisions["NEEDS_EVIDENCE"],
        decision_counts=decision_counts,
        include_counts_by_cwe={cwe: cwe_counts[cwe] for cwe in all_cwes},
        review_path=str(review_path),
    )


def _identity(value: dict[str, object]) -> tuple[str, str]:
    source_path = value.get("source_path")
    rule_id = value.get("rule_id", value.get("id"))
    if not isinstance(source_path, str) or not source_path:
        raise ReviewError("rule identity has invalid source_path")
    if not isinstance(rule_id, str) or not rule_id:
        raise ReviewError("rule identity has invalid rule_id")
    return source_path, rule_id


def _int_list(value: object, label: str) -> list[int]:
    if not isinstance(value, list) or not all(
        isinstance(item, int) and item > 0 for item in value
    ):
        raise ReviewError(f"{label} must be a list of positive integers")
    if len(value) != len(set(value)):
        raise ReviewError(f"{label} contains duplicates")
    return value


def _text_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ReviewError(f"{label} must be a list of non-empty strings")
    return value


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReviewError(f"failed to read {label}: {error}") from error
    if not isinstance(value, dict):
        raise ReviewError(f"{label} must be a JSON object")
    return value


def _require_file(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise ReviewError(f"{label} not found: {path}")
    return resolved


def _write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    temporary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(path)
