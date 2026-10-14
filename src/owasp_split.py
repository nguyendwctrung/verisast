import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from owasp_audit import GroundTruthRecord, load_ground_truth, map_java_sources, sha256_file, sha256_tree


SCHEMA_VERSION = 1
FAMILY_POLICY = "canonical-java-template-v1"
ASSIGNMENT_POLICY = "deterministic-family-greedy-v1"
SPLITS = ("development", "validation", "test")
TARGET_RATIOS = {"development": 0.60, "validation": 0.20, "test": 0.20}


class SplitError(ValueError):
    pass


@dataclass(frozen=True)
class SplitResult:
    output_dir: str
    unit_count: int
    family_count: int
    split_counts: dict[str, int]


def canonicalize_source(source: str) -> str:
    """Return a label-independent structural representation of one Java testcase."""

    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    source = re.sub(r"//[^\r\n]*", " ", source)
    source = re.sub(r"BenchmarkTest\d{5}", "BenchmarkTestID", source)
    source = re.sub(r'"(?:\\.|[^"\\])*"', '"STRING"', source)
    source = re.sub(r"'(?:\\.|[^'\\])*'", "'CHAR'", source)
    source = re.sub(r"\b\d+(?:\.\d+)?(?:[lLfFdD])?\b", "NUMBER", source)
    return " ".join(source.split())


def build_split(dataset_dir: Path, dataset_manifest_path: Path, output_dir: Path) -> SplitResult:
    dataset_dir = dataset_dir.resolve()
    dataset_manifest_path = dataset_manifest_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise SplitError(f"split output already exists: {output_dir}")

    manifest = _load_object(dataset_manifest_path, "dataset manifest")
    _validate_dataset(dataset_dir, manifest)
    records = load_ground_truth(dataset_dir / str(manifest["ground_truth_path"]))
    source_map = map_java_sources(dataset_dir / "src", records)
    families = _build_families(records, source_map)
    assignments = assign_families(families, len(records))
    _validate_assignment_records(records, families, assignments)

    output_dir.mkdir(parents=True)
    families_path = output_dir / "families.jsonl"
    assignments_path = output_dir / "assignments.jsonl"
    audit_path = output_dir / "leakage-audit.json"
    _write_jsonl(families_path, families)
    _write_jsonl(assignments_path, assignments)
    audit = _build_audit(records, families, assignments)
    _write_json(audit_path, audit)
    artifact_manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "frozen",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_id": manifest["dataset_id"],
        "dataset_commit": manifest["frozen_commit"],
        "dataset_manifest_sha256": sha256_file(dataset_manifest_path),
        "ground_truth_sha256": manifest["ground_truth_sha256"],
        "java_corpus_sha256": manifest["java_corpus_sha256"],
        "split_policy": {
            "targets": TARGET_RATIOS,
            "unit": "testcase-cwe",
            "family_policy": FAMILY_POLICY,
            "assignment_policy": ASSIGNMENT_POLICY,
            "label_independent": True,
        },
        "counts": {
            "units": len(records),
            "families": len(families),
            "splits": audit["split_counts"],
        },
        "artifacts": {
            "families": _artifact(families_path),
            "assignments": _artifact(assignments_path),
            "leakage_audit": _artifact(audit_path),
        },
    }
    _write_json(output_dir / "manifest.json", artifact_manifest)
    return SplitResult(str(output_dir), len(records), len(families), audit["split_counts"])


def validate_split(dataset_dir: Path, dataset_manifest_path: Path, split_dir: Path) -> SplitResult:
    dataset_dir = dataset_dir.resolve()
    dataset_manifest_path = dataset_manifest_path.resolve()
    split_dir = split_dir.resolve()
    manifest = _load_object(split_dir / "manifest.json", "split manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("status") != "frozen":
        raise SplitError("split manifest is not a frozen supported schema artifact")
    dataset_manifest = _load_object(dataset_manifest_path, "dataset manifest")
    _validate_dataset(dataset_dir, dataset_manifest)
    if manifest.get("dataset_manifest_sha256") != sha256_file(dataset_manifest_path):
        raise SplitError("dataset manifest hash mismatch")
    if manifest.get("ground_truth_sha256") != dataset_manifest.get("ground_truth_sha256"):
        raise SplitError("ground-truth hash mismatch")
    if manifest.get("java_corpus_sha256") != dataset_manifest.get("java_corpus_sha256"):
        raise SplitError("Java corpus hash mismatch")
    policy = manifest.get("split_policy")
    if not isinstance(policy, dict) or policy != {
        "targets": TARGET_RATIOS,
        "unit": "testcase-cwe",
        "family_policy": FAMILY_POLICY,
        "assignment_policy": ASSIGNMENT_POLICY,
        "label_independent": True,
    }:
        raise SplitError("unsupported split policy")
    paths = _validate_artifact_hashes(split_dir, manifest)
    records = load_ground_truth(dataset_dir / str(dataset_manifest["ground_truth_path"]))
    source_map = map_java_sources(dataset_dir / "src", records)
    expected_families = _build_families(records, source_map)
    families = _load_jsonl(paths["families"], "families")
    assignments = _load_jsonl(paths["assignments"], "assignments")
    if families != expected_families:
        raise SplitError("family records do not match frozen source")
    _validate_assignment_records(records, families, assignments)
    expected_assignments = assign_families(families, len(records))
    if assignments != expected_assignments:
        raise SplitError("assignments do not match deterministic policy")
    audit = _build_audit(records, families, assignments)
    if _load_object(paths["leakage_audit"], "leakage audit") != audit:
        raise SplitError("leakage audit does not match split artifacts")
    counts = manifest.get("counts")
    if not isinstance(counts, dict) or counts.get("units") != len(records) or counts.get("families") != len(families) or counts.get("splits") != audit["split_counts"]:
        raise SplitError("split manifest counts mismatch")
    return SplitResult(str(split_dir), len(records), len(families), audit["split_counts"])


def assign_families(families: list[dict[str, object]], unit_count: int) -> list[dict[str, object]]:
    """Assign whole families by size and stable ID; labels are not accepted here."""

    targets = _target_counts(unit_count)
    assigned_counts = {split: 0 for split in SPLITS}
    assignments: list[dict[str, object]] = []
    for family in sorted(families, key=lambda item: (-int(item["unit_count"]), str(item["family_id"]))):
        size = int(family["unit_count"])
        split = min(
            SPLITS,
            key=lambda name: (
                max(0, size - (targets[name] - assigned_counts[name])),
                -(targets[name] - assigned_counts[name]),
                SPLITS.index(name),
            ),
        )
        assigned_counts[split] += size
        for unit in family["units"]:
            if not isinstance(unit, dict):
                raise SplitError("family unit must be an object")
            assignments.append(
                {
                    "test_id": unit["test_id"],
                    "cwe": unit["cwe"],
                    "family_id": family["family_id"],
                    "split": split,
                }
            )
    return sorted(assignments, key=lambda item: (str(item["test_id"]), int(item["cwe"])))


def _build_families(records: list[GroundTruthRecord], source_map: dict[str, Path]) -> list[dict[str, object]]:
    grouped: dict[str, list[GroundTruthRecord]] = defaultdict(list)
    for record in records:
        source = source_map[record.test_id].read_text(encoding="utf-8")
        fingerprint = hashlib.sha256(canonicalize_source(source).encode("utf-8")).hexdigest()
        grouped[fingerprint].append(record)
    families = []
    for fingerprint, members in sorted(grouped.items()):
        units = [{"test_id": item.test_id, "cwe": item.cwe} for item in sorted(members, key=lambda item: (item.test_id, item.cwe))]
        families.append({"family_id": f"family-{fingerprint[:16]}", "fingerprint": fingerprint, "unit_count": len(units), "units": units})
    return families


def _build_audit(records: list[GroundTruthRecord], families: list[dict[str, object]], assignments: list[dict[str, object]]) -> dict[str, object]:
    assignment_by_unit = {(item["test_id"], item["cwe"]): item for item in assignments}
    family_splits: dict[str, set[str]] = defaultdict(set)
    fingerprint_splits: dict[str, set[str]] = defaultdict(set)
    fingerprint_by_family = {str(item["family_id"]): str(item["fingerprint"]) for item in families}
    for item in assignments:
        family_splits[str(item["family_id"])].add(str(item["split"]))
        fingerprint_splits[fingerprint_by_family[str(item["family_id"])]].add(str(item["split"]))
    split_counts = Counter(str(item["split"]) for item in assignments)
    by_cwe_split = Counter(f"{record.cwe}:{assignment_by_unit[(record.test_id, record.cwe)]['split']}" for record in records)
    by_label_split = Counter(f"{str(record.vulnerable).lower()}:{assignment_by_unit[(record.test_id, record.cwe)]['split']}" for record in records)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "unit_count": len(records),
        "family_count": len(families),
        "split_counts": {split: split_counts[split] for split in SPLITS},
        "target_counts": _target_counts(len(records)),
        "family_isolation_violations": sorted(key for key, value in family_splits.items() if len(value) != 1),
        "cross_split_fingerprint_violations": sorted(key for key, value in fingerprint_splits.items() if len(value) != 1),
        "cwe_split_counts": dict(sorted(by_cwe_split.items())),
        "label_split_counts": dict(sorted(by_label_split.items())),
        "coverage_warnings": _coverage_warnings(records, assignment_by_unit),
    }


def _coverage_warnings(records: list[GroundTruthRecord], assignments: dict[tuple[object, object], dict[str, object]]) -> list[str]:
    cwe_splits: dict[int, set[str]] = defaultdict(set)
    for record in records:
        cwe_splits[record.cwe].add(str(assignments[(record.test_id, record.cwe)]["split"]))
    return [f"CWE-{cwe} appears only in {','.join(sorted(splits))}" for cwe, splits in sorted(cwe_splits.items()) if len(splits) < len(SPLITS)]


def _validate_dataset(dataset_dir: Path, manifest: dict[str, object]) -> None:
    if manifest.get("audit_status") != "passed":
        raise SplitError("dataset manifest is not passed")
    ground_truth = dataset_dir / str(manifest.get("ground_truth_path", ""))
    if sha256_file(ground_truth) != manifest.get("ground_truth_sha256"):
        raise SplitError("ground-truth hash mismatch")
    records = load_ground_truth(ground_truth)
    source_map = map_java_sources(dataset_dir / "src", records)
    if sha256_tree(dataset_dir, source_map.values()) != manifest.get("java_corpus_sha256"):
        raise SplitError("Java corpus hash mismatch")


def _validate_assignment_records(records: list[GroundTruthRecord], families: list[dict[str, object]], assignments: list[dict[str, object]]) -> None:
    expected = {(record.test_id, record.cwe) for record in records}
    observed = [(item.get("test_id"), item.get("cwe")) for item in assignments]
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise SplitError("assignments must contain every unit exactly once")
    valid_families = {str(item["family_id"]) for item in families}
    for item in assignments:
        if item.get("family_id") not in valid_families or item.get("split") not in SPLITS:
            raise SplitError("invalid assignment family or split")
    by_family: dict[str, set[str]] = defaultdict(set)
    for item in assignments:
        by_family[str(item["family_id"])].add(str(item["split"]))
    if any(len(splits) != 1 for splits in by_family.values()):
        raise SplitError("template family is assigned to multiple splits")


def _target_counts(unit_count: int) -> dict[str, int]:
    development = round(unit_count * TARGET_RATIOS["development"])
    validation = round(unit_count * TARGET_RATIOS["validation"])
    return {"development": development, "validation": validation, "test": unit_count - development - validation}


def _artifact(path: Path) -> dict[str, str]:
    return {"path": path.name, "sha256": sha256_file(path)}


def _validate_artifact_hashes(root: Path, manifest: dict[str, object]) -> dict[str, Path]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise SplitError("split artifact records are missing")
    paths: dict[str, Path] = {}
    for name in ("families", "assignments", "leakage_audit"):
        record = artifacts.get(name)
        if not isinstance(record, dict) or not isinstance(record.get("path"), str) or not isinstance(record.get("sha256"), str):
            raise SplitError(f"invalid {name} artifact record")
        path = root / record["path"]
        if path.parent != root or not path.is_file() or sha256_file(path) != record["sha256"]:
            raise SplitError(f"{name} artifact hash mismatch")
        paths[name] = path
    return paths


def _load_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SplitError(f"failed to read {label}: {error}") from error
    if not isinstance(value, dict):
        raise SplitError(f"{label} must be an object")
    return value


def _load_jsonl(path: Path, label: str) -> list[dict[str, object]]:
    try:
        items = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SplitError(f"failed to read {label}: {error}") from error
    if not all(isinstance(item, dict) for item in items):
        raise SplitError(f"{label} records must be objects")
    return items


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records), encoding="utf-8")
