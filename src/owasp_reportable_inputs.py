import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from owasp_audit import load_ground_truth
from owasp_split import SplitError, validate_split
from semgrep_rules import sha256_file
from semgrep_ruleset import RulesetError, build_composite_ruleset, load_ruleset


SCHEMA_VERSION = 1
SPLITS = ("development", "validation", "test")


class ReportableInputError(ValueError):
    pass


@dataclass(frozen=True)
class ReportableInputResult:
    output_dir: str
    rule_count: int
    unit_count: int
    cohort_counts: dict[str, int]


def freeze_reportable_inputs(
    *,
    dataset: Path,
    dataset_manifest: Path,
    split: Path,
    upstream: Path,
    project: Path,
    catalog: Path,
    review: Path,
    output_dir: Path,
) -> ReportableInputResult:
    paths = _resolve_paths(dataset, dataset_manifest, split, upstream, project, catalog, review)
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise ReportableInputError(f"reportable input output already exists: {output_dir}")
    _validate_source_inputs(paths)
    output_dir.mkdir(parents=True)
    copied = _copy_inputs(paths, output_dir)
    try:
        ruleset_result = build_composite_ruleset(
            upstream_rules_dir=paths["upstream"],
            project_root=paths["project"],
            catalog_path=copied["catalog"],
            review_path=copied["review"],
            output_path=output_dir / "ruleset.json",
            purpose="reportable",
        )
    except RulesetError as error:
        raise ReportableInputError(str(error)) from error
    ruleset_path = Path(ruleset_result.output_path)
    records = load_ground_truth(paths["dataset"] / _ground_truth_path(paths["dataset_manifest"]))
    assignments = _load_assignments(copied["split"] / "assignments.jsonl")
    ruleset = _load_ruleset(ruleset_path, paths)
    cohort_counts = _write_cohorts(output_dir, records, assignments, ruleset, ruleset_path, copied["split"])
    artifacts = _collect_artifacts(output_dir)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "frozen",
        "purpose": "reportable-inputs",
        "reportable": True,
        "sources": {name: {"path": str(path), "sha256": sha256_file(path)} for name, path in _source_files(paths).items()},
        "artifacts": artifacts,
        "counts": {"rules": ruleset_result.rule_count, "units": len(records), "cohorts": cohort_counts},
    }
    _write_json(output_dir / "manifest.json", manifest)
    return ReportableInputResult(str(output_dir), ruleset_result.rule_count, len(records), cohort_counts)


def validate_reportable_inputs(
    *,
    dataset: Path,
    dataset_manifest: Path,
    split: Path,
    upstream: Path,
    project: Path,
    catalog: Path,
    review: Path,
    bundle_dir: Path,
) -> ReportableInputResult:
    paths = _resolve_paths(dataset, dataset_manifest, split, upstream, project, catalog, review)
    bundle_dir = bundle_dir.resolve()
    _validate_source_inputs(paths)
    manifest = _load_object(bundle_dir / "manifest.json", "reportable input manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("status") != "frozen" or manifest.get("reportable") is not True:
        raise ReportableInputError("reportable input manifest is invalid")
    _validate_source_hashes(manifest, paths)
    artifacts = _validate_artifacts(bundle_dir, manifest)
    try:
        validate_split(paths["dataset"], paths["dataset_manifest"], bundle_dir / "split")
    except SplitError as error:
        raise ReportableInputError(f"split validation failed: {error}") from error
    if sha256_file(bundle_dir / "catalog.json") != sha256_file(paths["catalog"]) or sha256_file(bundle_dir / "review.json") != sha256_file(paths["review"]):
        raise ReportableInputError("copied catalog or review does not match source")
    ruleset = _load_ruleset(bundle_dir / "ruleset.json", paths)
    records = load_ground_truth(paths["dataset"] / _ground_truth_path(paths["dataset_manifest"]))
    assignments = _load_assignments(bundle_dir / "split" / "assignments.jsonl")
    cohort_counts = _validate_cohorts(bundle_dir, records, assignments, ruleset, bundle_dir / "ruleset.json")
    counts = manifest.get("counts")
    if not isinstance(counts, dict) or counts.get("rules") != len(ruleset["rules"]) or counts.get("units") != len(records) or counts.get("cohorts") != cohort_counts:
        raise ReportableInputError("reportable input manifest counts mismatch")
    if not artifacts:
        raise ReportableInputError("reportable input artifacts are missing")
    return ReportableInputResult(str(bundle_dir), len(ruleset["rules"]), len(records), cohort_counts)


def _resolve_paths(dataset: Path, dataset_manifest: Path, split: Path, upstream: Path, project: Path, catalog: Path, review: Path) -> dict[str, Path]:
    paths = {"dataset": dataset.resolve(), "dataset_manifest": dataset_manifest.resolve(), "split": split.resolve(), "upstream": upstream.resolve(), "project": project.resolve(), "catalog": catalog.resolve(), "review": review.resolve()}
    for name, path in paths.items():
        if not path.exists():
            raise ReportableInputError(f"required {name} path not found: {path}")
    return paths


def _validate_source_inputs(paths: dict[str, Path]) -> None:
    try:
        validate_split(paths["dataset"], paths["dataset_manifest"], paths["split"])
    except SplitError as error:
        raise ReportableInputError(f"split validation failed: {error}") from error


def _copy_inputs(paths: dict[str, Path], output_dir: Path) -> dict[str, Path]:
    catalog = output_dir / "catalog.json"
    review = output_dir / "review.json"
    shutil.copy2(paths["catalog"], catalog)
    shutil.copy2(paths["review"], review)
    split_dir = output_dir / "split"
    shutil.copytree(paths["split"], split_dir)
    return {"catalog": catalog, "review": review, "split": split_dir}


def _load_ruleset(path: Path, paths: dict[str, Path]) -> dict[str, object]:
    try:
        ruleset = load_ruleset(path, paths["upstream"], paths["project"])
    except RulesetError as error:
        raise ReportableInputError(str(error)) from error
    if ruleset.get("purpose") != "reportable" or ruleset.get("reportable") is not True:
        raise ReportableInputError("ruleset is not reportable")
    return ruleset


def _write_cohorts(output_dir: Path, records: list[Any], assignments: dict[tuple[str, int], str], ruleset: dict[str, object], ruleset_path: Path, split_dir: Path) -> dict[str, int]:
    cohort_dir = output_dir / "cohorts"
    cohort_dir.mkdir()
    cwes = sorted({cwe for rule in ruleset["rules"] for cwe in rule["reviewed_cwes"]})
    counts = {}
    for split in SPLITS:
        units = [{"test_id": record.test_id, "category": record.category, "cwe": record.cwe, "vulnerable": record.vulnerable} for record in records if record.cwe in cwes and assignments[(record.test_id, record.cwe)] == split]
        payload = {"schema_version": SCHEMA_VERSION, "status": "frozen", "purpose": "reportable", "reportable": True, "split": split, "ruleset_sha256": sha256_file(ruleset_path), "split_assignments_sha256": sha256_file(split_dir / "assignments.jsonl"), "unit_count": len(units), "cwes": cwes, "units": units}
        _write_json(cohort_dir / f"{split}.json", payload)
        counts[split] = len(units)
    return counts


def _validate_cohorts(bundle_dir: Path, records: list[Any], assignments: dict[tuple[str, int], str], ruleset: dict[str, object], ruleset_path: Path) -> dict[str, int]:
    cwes = sorted({cwe for rule in ruleset["rules"] for cwe in rule["reviewed_cwes"]})
    observed: set[tuple[str, int]] = set()
    counts: dict[str, int] = {}
    for split in SPLITS:
        payload = _load_object(bundle_dir / "cohorts" / f"{split}.json", f"{split} cohort")
        units = payload.get("units")
        expected = [{"test_id": record.test_id, "category": record.category, "cwe": record.cwe, "vulnerable": record.vulnerable} for record in records if record.cwe in cwes and assignments[(record.test_id, record.cwe)] == split]
        if payload.get("schema_version") != SCHEMA_VERSION or payload.get("status") != "frozen" or payload.get("purpose") != "reportable" or payload.get("reportable") is not True or payload.get("split") != split or payload.get("ruleset_sha256") != sha256_file(ruleset_path) or payload.get("split_assignments_sha256") != sha256_file(bundle_dir / "split" / "assignments.jsonl") or payload.get("cwes") != cwes or payload.get("unit_count") != len(expected) or units != expected:
            raise ReportableInputError(f"invalid {split} cohort")
        identities = {(unit["test_id"], unit["cwe"]) for unit in expected}
        if observed.intersection(identities):
            raise ReportableInputError("cohorts contain duplicate units")
        observed.update(identities)
        counts[split] = len(expected)
    expected_all = {(record.test_id, record.cwe) for record in records if record.cwe in cwes}
    if observed != expected_all:
        raise ReportableInputError("cohorts do not cover the reportable ruleset scope")
    return counts


def _load_assignments(path: Path) -> dict[tuple[str, int], str]:
    entries = _load_jsonl(path, "split assignments")
    assignments = {(str(item.get("test_id")), int(item.get("cwe"))): str(item.get("split")) for item in entries}
    if len(assignments) != len(entries) or any(split not in SPLITS for split in assignments.values()):
        raise ReportableInputError("invalid split assignments")
    return assignments


def _collect_artifacts(output_dir: Path) -> dict[str, dict[str, str]]:
    paths = [output_dir / "catalog.json", output_dir / "review.json", output_dir / "ruleset.json", output_dir / "split" / "manifest.json", output_dir / "split" / "families.jsonl", output_dir / "split" / "assignments.jsonl", output_dir / "split" / "leakage-audit.json", *(output_dir / "cohorts" / f"{split}.json" for split in SPLITS)]
    return {path.relative_to(output_dir).as_posix(): {"sha256": sha256_file(path)} for path in paths}


def _validate_artifacts(output_dir: Path, manifest: dict[str, object]) -> dict[str, dict[str, str]]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ReportableInputError("reportable input artifact records are missing")
    expected = _collect_artifacts(output_dir)
    if artifacts != expected:
        raise ReportableInputError("reportable input artifact hash mismatch")
    return expected


def _source_files(paths: dict[str, Path]) -> dict[str, Path]:
    return {"dataset_manifest": paths["dataset_manifest"], "split_manifest": paths["split"] / "manifest.json", "catalog": paths["catalog"], "review": paths["review"]}


def _validate_source_hashes(manifest: dict[str, object], paths: dict[str, Path]) -> None:
    sources = manifest.get("sources")
    expected = {name: {"path": str(path), "sha256": sha256_file(path)} for name, path in _source_files(paths).items()}
    if sources != expected:
        raise ReportableInputError("reportable input source hash mismatch")


def _ground_truth_path(dataset_manifest: Path) -> str:
    return str(_load_object(dataset_manifest, "dataset manifest").get("ground_truth_path", ""))


def _load_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReportableInputError(f"failed to read {label}: {error}") from error
    if not isinstance(value, dict):
        raise ReportableInputError(f"{label} must be an object")
    return value


def _load_jsonl(path: Path, label: str) -> list[dict[str, object]]:
    try:
        values = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReportableInputError(f"failed to read {label}: {error}") from error
    if not all(isinstance(value, dict) for value in values):
        raise ReportableInputError(f"{label} records must be objects")
    return values


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
