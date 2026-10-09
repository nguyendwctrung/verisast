import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from owasp_audit import load_ground_truth
from semgrep_rules import sha256_file
from semgrep_ruleset import RulesetError, load_ruleset

SCHEMA_VERSION = 1
MATCHING_POLICY = "owasp-testcase-cwe-any-finding-v1"
PURPOSES = {"development", "reportable"}


class CohortError(ValueError):
    pass


@dataclass(frozen=True)
class CohortResult:
    status: str
    purpose: str
    reportable: bool
    unit_count: int
    cwes: list[int]
    output_path: str


def build_cohort(
    dataset_dir: Path,
    dataset_manifest_path: Path,
    ruleset_path: Path,
    output_path: Path,
    purpose: str,
) -> CohortResult:
    if purpose not in PURPOSES:
        raise CohortError(f"invalid cohort purpose: {purpose}")
    dataset_dir = dataset_dir.resolve()
    dataset_manifest_path = dataset_manifest_path.resolve()
    ruleset_path = ruleset_path.resolve()
    output_path = output_path.resolve()
    if output_path.exists():
        raise CohortError(f"cohort output already exists: {output_path}")
    manifest = _read_object(dataset_manifest_path, "dataset manifest")
    if manifest.get("audit_status") != "passed":
        raise CohortError("dataset manifest is not passed")
    ground_truth_path = dataset_dir / str(manifest.get("ground_truth_path", ""))
    if not ground_truth_path.is_file():
        raise CohortError("ground-truth file not found")
    if sha256_file(ground_truth_path) != manifest.get("ground_truth_sha256"):
        raise CohortError("ground-truth hash mismatch")
    try:
        ruleset = load_ruleset(ruleset_path)
    except RulesetError as error:
        raise CohortError(str(error)) from error
    if purpose == "reportable" and ruleset.get("reportable") is not True:
        raise CohortError("reportable cohort requires a reportable ruleset")
    rules = cast(list[dict[str, object]], ruleset["rules"])
    cwes = sorted(
        {
            cwe
            for rule in rules
            for cwe in cast(list[int], rule.get("reviewed_cwes", []))
        }
    )
    records = [record for record in load_ground_truth(ground_truth_path) if record.cwe in cwes]
    if not records:
        raise CohortError("cohort contains no evaluation units")
    unit_ids = [(record.test_id, record.cwe) for record in records]
    if len(unit_ids) != len(set(unit_ids)):
        raise CohortError("cohort contains duplicate evaluation units")
    labels = Counter(str(record.vulnerable).lower() for record in records)
    by_cwe_label = Counter(f"{record.cwe}:{str(record.vulnerable).lower()}" for record in records)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "status": "frozen" if purpose == "reportable" else "development",
        "purpose": purpose,
        "reportable": purpose == "reportable",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "matching_policy": MATCHING_POLICY,
        "dataset_id": manifest["dataset_id"],
        "dataset_commit": manifest["frozen_commit"],
        "dataset_manifest_path": dataset_manifest_path.name,
        "dataset_manifest_sha256": sha256_file(dataset_manifest_path),
        "ground_truth_path": str(manifest["ground_truth_path"]),
        "ground_truth_sha256": manifest["ground_truth_sha256"],
        "ruleset_path": ruleset_path.name,
        "ruleset_sha256": sha256_file(ruleset_path),
        "cwes": cwes,
        "unit_count": len(records),
        "label_counts": dict(sorted(labels.items())),
        "cwe_label_counts": dict(sorted(by_cwe_label.items())),
        "units": [
            {
                "test_id": record.test_id,
                "category": record.category,
                "cwe": record.cwe,
                "vulnerable": record.vulnerable,
            }
            for record in records
        ],
    }
    _write_json(output_path, payload)
    return CohortResult(
        status=str(payload["status"]),
        purpose=purpose,
        reportable=bool(payload["reportable"]),
        unit_count=len(records),
        cwes=cwes,
        output_path=str(output_path),
    )


def load_cohort(
    path: Path,
    dataset_dir: Path,
    dataset_manifest_path: Path,
    ruleset_path: Path,
) -> dict[str, object]:
    path = path.resolve()
    payload = _read_object(path, "cohort")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise CohortError("unsupported cohort schema version")
    units = payload.get("units")
    if not isinstance(units, list) or payload.get("unit_count") != len(units):
        raise CohortError("cohort unit count mismatch")
    identities = []
    for unit in units:
        if not isinstance(unit, dict):
            raise CohortError("cohort unit must be an object")
        identities.append((unit.get("test_id"), unit.get("cwe")))
    if len(identities) != len(set(identities)):
        raise CohortError("cohort contains duplicate evaluation units")
    manifest = _read_object(dataset_manifest_path.resolve(), "dataset manifest")
    ground_truth = dataset_dir.resolve() / str(manifest.get("ground_truth_path", ""))
    if sha256_file(ground_truth) != payload.get("ground_truth_sha256"):
        raise CohortError("ground-truth hash mismatch")
    if sha256_file(dataset_manifest_path.resolve()) != payload.get("dataset_manifest_sha256"):
        raise CohortError("dataset manifest hash mismatch")
    if sha256_file(ruleset_path.resolve()) != payload.get("ruleset_sha256"):
        raise CohortError("ruleset hash mismatch")
    if payload.get("purpose") == "reportable" and (
        payload.get("status") != "frozen" or payload.get("reportable") is not True
    ):
        raise CohortError("invalid reportable cohort status")
    return payload


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CohortError(f"failed to read {label}: {error}") from error
    if not isinstance(value, dict):
        raise CohortError(f"{label} must be a JSON object")
    return value


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
