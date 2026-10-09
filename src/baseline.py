import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from owasp_cohort import CohortError, load_cohort
from owasp_evaluate import EvaluationError, evaluate_findings
from semgrep_normalize import NormalizeError, normalize_findings
from semgrep_rules import sha256_file
from semgrep_ruleset import RulesetError, load_ruleset
from semgrep_scan import ScanError, scan_rules

SCHEMA_VERSION = 1
ScanRunner = Callable[..., list[dict[str, object]]]


class BaselineError(ValueError):
    pass


@dataclass(frozen=True)
class BaselineResult:
    status: str
    run_id: str
    purpose: str
    reportable: bool
    semgrep_version: str
    rule_count: int
    raw_finding_count: int
    normalized_finding_count: int
    predicted_unit_count: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float | None
    recall: float | None
    f1: float | None
    fpr: float | None
    manifest_path: str


def run_owasp_baseline(
    run_id: str,
    purpose: str,
    dataset_dir: Path,
    dataset_manifest_path: Path,
    rules_dir: Path,
    ruleset_path: Path,
    cohort_path: Path,
    run_dir: Path,
    semgrep_executable: str,
    expected_version: str,
    scan_runner: ScanRunner = scan_rules,
) -> BaselineResult:
    if not run_id.strip() or any(character in run_id for character in "\\/:"):
        raise BaselineError("invalid run ID")
    if purpose not in {"development", "reportable"}:
        raise BaselineError(f"invalid baseline purpose: {purpose}")
    run_dir = run_dir.resolve()
    if run_dir.exists():
        raise BaselineError(f"run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True)
    manifest_path = run_dir / "manifest.json"
    stages: dict[str, str] = {
        "inputs": "pending",
        "scan": "pending",
        "normalize": "pending",
        "evaluate": "pending",
    }
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "running",
        "run_id": run_id,
        "purpose": purpose,
        "reportable": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "semgrep_version": expected_version,
        "stages": stages,
    }
    _write_json(manifest_path, manifest)
    try:
        ruleset = load_ruleset(ruleset_path, rules_dir)
        cohort = load_cohort(cohort_path, dataset_dir, dataset_manifest_path, ruleset_path)
        if ruleset.get("purpose") != purpose or cohort.get("purpose") != purpose:
            raise BaselineError("baseline purpose does not match input snapshots")
        if purpose == "reportable" and (
            ruleset.get("reportable") is not True or cohort.get("reportable") is not True
        ):
            raise BaselineError("reportable baseline requires frozen reportable inputs")
        inputs_dir = run_dir / "inputs"
        inputs_dir.mkdir()
        ruleset_copy = inputs_dir / "ruleset.json"
        cohort_copy = inputs_dir / "cohort.json"
        dataset_manifest_copy = inputs_dir / "dataset-manifest.json"
        shutil.copy2(ruleset_path, ruleset_copy)
        shutil.copy2(cohort_path, cohort_copy)
        shutil.copy2(dataset_manifest_path, dataset_manifest_copy)
        manifest["stages"]["inputs"] = "completed"
        manifest["inputs"] = {
            "ruleset": _artifact(run_dir, ruleset_copy),
            "cohort": _artifact(run_dir, cohort_copy),
            "dataset_manifest": _artifact(run_dir, dataset_manifest_copy),
            "dataset_dir": str(dataset_dir.resolve()),
            "rules_dir": str(rules_dir.resolve()),
        }
        _write_json(manifest_path, manifest)
        source_root = dataset_dir.resolve() / "src" / "main" / "java"
        scans = scan_runner(
            rules_dir.resolve(),
            ruleset,
            source_root,
            run_dir / "raw",
            semgrep_executable,
            expected_version,
        )
        manifest["stages"]["scan"] = "completed"
        manifest["scans"] = scans
        _write_json(manifest_path, manifest)
        dataset_manifest = _read_object(dataset_manifest_path, "dataset manifest")
        findings, raw_count = normalize_findings(
            dataset_dir,
            str(dataset_manifest["frozen_commit"]),
            scans,
        )
        findings_path = run_dir / "normalized" / "findings.jsonl"
        _write_jsonl(findings_path, findings)
        manifest["stages"]["normalize"] = "completed"
        manifest["normalized"] = _artifact(run_dir, findings_path)
        _write_json(manifest_path, manifest)
        matches, metrics = evaluate_findings(cohort, findings, raw_count)
        matches_path = run_dir / "evaluation" / "matches.jsonl"
        metrics_path = run_dir / "evaluation" / "metrics.json"
        _write_jsonl(matches_path, matches)
        _write_json(metrics_path, metrics)
        manifest["stages"]["evaluate"] = "completed"
        manifest["evaluation"] = {
            "matches": _artifact(run_dir, matches_path),
            "metrics": _artifact(run_dir, metrics_path),
        }
        manifest["counts"] = {
            "rules": len(cast(list[object], ruleset["rules"])),
            "raw_findings": raw_count,
            "normalized_findings": len(findings),
            "predicted_units": metrics["predicted_unit_count"],
        }
        manifest["reportable"] = purpose == "reportable"
        manifest["status"] = "completed"
        manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
        _write_json(manifest_path, manifest)
        return _result(manifest, metrics, manifest_path)
    except (BaselineError, CohortError, EvaluationError, NormalizeError, RulesetError, ScanError, KeyError, OSError, ValueError) as error:
        manifest["status"] = "failed"
        manifest["reportable"] = False
        manifest["error"] = str(error)
        manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
        _write_json(manifest_path, manifest)
        raise BaselineError(str(error)) from error


def validate_baseline_run(
    run_dir: Path,
    dataset_dir: Path,
    dataset_manifest_path: Path,
    rules_dir: Path,
) -> BaselineResult:
    run_dir = run_dir.resolve()
    manifest_path = run_dir / "manifest.json"
    manifest = _read_object(manifest_path, "baseline manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("status") != "completed":
        raise BaselineError("baseline run is not a completed schema version 1 run")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise BaselineError("baseline input records are missing")
    for record in inputs.values():
        if isinstance(record, dict):
            _validate_artifact(run_dir, record)
    ruleset_path = run_dir / str(inputs["ruleset"]["path"])
    cohort_path = run_dir / str(inputs["cohort"]["path"])
    ruleset = load_ruleset(ruleset_path, rules_dir)
    cohort = load_cohort(cohort_path, dataset_dir, dataset_manifest_path, ruleset_path)
    scans = manifest.get("scans")
    if not isinstance(scans, list):
        raise BaselineError("baseline scan records are missing")
    for scan in scans:
        if not isinstance(scan, dict):
            raise BaselineError("baseline scan record must be an object")
        for prefix in ("stdout", "stderr"):
            path = Path(str(scan[f"{prefix}_path"])).resolve()
            if not path.is_relative_to(run_dir) or sha256_file(path) != scan[f"{prefix}_sha256"]:
                raise BaselineError(f"scan {prefix} artifact mismatch")
    dataset_manifest = _read_object(dataset_manifest_path.resolve(), "dataset manifest")
    findings, raw_count = normalize_findings(dataset_dir, str(dataset_manifest["frozen_commit"]), scans)
    normalized_record = manifest.get("normalized")
    evaluation = manifest.get("evaluation")
    if not isinstance(normalized_record, dict) or not isinstance(evaluation, dict):
        raise BaselineError("baseline derived artifacts are missing")
    _validate_artifact(run_dir, normalized_record)
    _validate_artifact(run_dir, evaluation["matches"])
    _validate_artifact(run_dir, evaluation["metrics"])
    stored_findings = _read_jsonl(run_dir / str(normalized_record["path"]))
    if stored_findings != findings:
        raise BaselineError("normalized findings do not match raw evidence")
    matches, metrics = evaluate_findings(cohort, findings, raw_count)
    if _read_jsonl(run_dir / str(evaluation["matches"]["path"])) != matches:
        raise BaselineError("evaluation matches do not match normalized findings")
    if _read_object(run_dir / str(evaluation["metrics"]["path"]), "metrics") != metrics:
        raise BaselineError("evaluation metrics do not match normalized findings")
    if manifest.get("purpose") == "reportable" and (
        manifest.get("reportable") is not True
        or ruleset.get("reportable") is not True
        or cohort.get("reportable") is not True
    ):
        raise BaselineError("invalid reportable baseline claim")
    return _result(manifest, metrics, manifest_path)


def _result(manifest: dict[str, Any], metrics: dict[str, Any], manifest_path: Path) -> BaselineResult:
    overall = metrics["overall"]
    counts = manifest["counts"]
    return BaselineResult(
        status=str(manifest["status"]), run_id=str(manifest["run_id"]), purpose=str(manifest["purpose"]),
        reportable=bool(manifest["reportable"]), semgrep_version=str(manifest["semgrep_version"]),
        rule_count=int(counts["rules"]), raw_finding_count=int(counts["raw_findings"]),
        normalized_finding_count=int(counts["normalized_findings"]), predicted_unit_count=int(counts["predicted_units"]),
        tp=int(overall["tp"]), fp=int(overall["fp"]), tn=int(overall["tn"]), fn=int(overall["fn"]),
        precision=overall["precision"], recall=overall["recall"], f1=overall["f1"], fpr=overall["fpr"],
        manifest_path=str(manifest_path),
    )


def _artifact(root: Path, path: Path) -> dict[str, object]:
    return {"path": path.resolve().relative_to(root.resolve()).as_posix(), "sha256": sha256_file(path)}


def _validate_artifact(root: Path, record: object) -> None:
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        raise BaselineError("invalid artifact record")
    path = (root / record["path"]).resolve()
    if not path.is_relative_to(root) or not path.is_file() or sha256_file(path) != record.get("sha256"):
        raise BaselineError(f"artifact mismatch: {record.get('path')}")


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BaselineError(f"failed to read {label}: {error}") from error
    if not isinstance(value, dict):
        raise BaselineError(f"{label} must be a JSON object")
    return value


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    rows = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise BaselineError(f"JSONL row must be an object: {path}")
            rows.append(value)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BaselineError(f"failed to read JSONL: {error}") from error
    return rows
