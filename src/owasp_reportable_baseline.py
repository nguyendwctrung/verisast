import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from owasp_evaluate import evaluate_findings
from semgrep_normalize import normalize_findings
from semgrep_rules import sha256_file
from semgrep_ruleset import load_ruleset
from semgrep_scan import scan_rules
from source_context import build_contexts, validate_contexts


SPLITS = ("development", "validation", "test")
CONTEXT_BEFORE = 20
CONTEXT_AFTER = 20
CONTEXT_MAX_LINES = 120


class ReportableBaselineError(ValueError):
    pass


@dataclass(frozen=True)
class ReportableBaselineResult:
    run_id: str
    run_dir: str
    raw_finding_count: int
    normalized_finding_count: int
    split_metrics: dict[str, dict[str, object]]


def evaluate_cohorts(cohort_dir: Path, findings: list[dict[str, object]], raw_finding_count: int) -> dict[str, dict[str, object]]:
    result = {}
    for split in SPLITS:
        cohort = _read_object(cohort_dir / f"{split}.json", f"{split} cohort")
        if cohort.get("purpose") != "reportable" or cohort.get("reportable") is not True or cohort.get("split") != split:
            raise ReportableBaselineError(f"invalid {split} reportable cohort")
        matches, metrics = evaluate_findings(cohort, findings, raw_finding_count)
        result[split] = {"matches": matches, "metrics": metrics}
    return result


def run_reportable_baseline(*, run_id: str, dataset: Path, dataset_manifest: Path, bundle_dir: Path, rules_dir: Path, project_root: Path, run_dir: Path, semgrep: str, expected_version: str) -> ReportableBaselineResult:
    if not run_id.strip() or any(character in run_id for character in "\\/:"):
        raise ReportableBaselineError("invalid run ID")
    run_dir = run_dir.resolve()
    if run_dir.exists():
        raise ReportableBaselineError(f"run directory already exists: {run_dir}")
    dataset, dataset_manifest, bundle_dir, rules_dir, project_root = (dataset.resolve(), dataset_manifest.resolve(), bundle_dir.resolve(), rules_dir.resolve(), project_root.resolve())
    _validate_bundle(bundle_dir, rules_dir, project_root)
    run_dir.mkdir(parents=True)
    manifest_path = run_dir / "manifest.json"
    manifest: dict[str, Any] = {"schema_version": 1, "status": "running", "run_id": run_id, "purpose": "reportable", "reportable": False, "created_at": datetime.now(timezone.utc).isoformat(), "stages": {"inputs": "pending", "scan": "pending", "normalize": "pending", "context": "pending", "evaluate": "pending"}}
    _write_json(manifest_path, manifest)
    try:
        inputs = run_dir / "inputs"
        inputs.mkdir()
        copied = {"bundle_manifest": inputs / "bundle-manifest.json", "ruleset": inputs / "ruleset.json"}
        shutil.copy2(bundle_dir / "manifest.json", copied["bundle_manifest"])
        shutil.copy2(bundle_dir / "ruleset.json", copied["ruleset"])
        cohort_dir = inputs / "cohorts"
        cohort_dir.mkdir()
        for split in SPLITS:
            shutil.copy2(bundle_dir / "cohorts" / f"{split}.json", cohort_dir / f"{split}.json")
        manifest["inputs"] = {name: _artifact(run_dir, path) for name, path in copied.items()}
        manifest["inputs"]["cohorts"] = {split: _artifact(run_dir, cohort_dir / f"{split}.json") for split in SPLITS}
        manifest["inputs"]["bundle_source"] = {"path": str(bundle_dir), "manifest_sha256": sha256_file(bundle_dir / "manifest.json")}
        manifest["stages"]["inputs"] = "completed"
        _write_json(manifest_path, manifest)
        ruleset = load_ruleset(copied["ruleset"], rules_dir, project_root)
        scans = scan_rules(rules_dir, ruleset, dataset / "src" / "main" / "java", run_dir / "raw", semgrep, expected_version, project_root=project_root)
        manifest["scans"] = scans
        manifest["stages"]["scan"] = "completed"
        _write_json(manifest_path, manifest)
        dataset_info = _read_object(dataset_manifest, "dataset manifest")
        findings, raw_count = normalize_findings(dataset, str(dataset_info["frozen_commit"]), scans)
        findings_path = run_dir / "normalized" / "findings.jsonl"
        _write_jsonl(findings_path, findings)
        manifest["normalized"] = _artifact(run_dir, findings_path)
        manifest["stages"]["normalize"] = "completed"
        contexts_path = run_dir / "contexts" / "contexts.jsonl"
        context_result = build_contexts(
            dataset, findings_path, contexts_path,
            before=CONTEXT_BEFORE, after=CONTEXT_AFTER, max_lines=CONTEXT_MAX_LINES,
        )
        manifest["context"] = {"artifact": _artifact(run_dir, contexts_path), "count": context_result.context_count, "policy": {"before": CONTEXT_BEFORE, "after": CONTEXT_AFTER, "max_lines": CONTEXT_MAX_LINES}}
        manifest["stages"]["context"] = "completed"
        evaluations = evaluate_cohorts(cohort_dir, findings, raw_count)
        evaluation_records = {}
        for split, value in evaluations.items():
            matches_path = run_dir / "evaluation" / split / "matches.jsonl"
            metrics_path = run_dir / "evaluation" / split / "metrics.json"
            _write_jsonl(matches_path, value["matches"])
            _write_json(metrics_path, value["metrics"])
            evaluation_records[split] = {"matches": _artifact(run_dir, matches_path), "metrics": _artifact(run_dir, metrics_path)}
        manifest["evaluation"] = evaluation_records
        manifest["counts"] = {"rules": len(ruleset["rules"]), "raw_findings": raw_count, "normalized_findings": len(findings), "contexts": context_result.context_count}
        manifest["semgrep_version"] = expected_version
        manifest["stages"]["evaluate"] = "completed"
        manifest["reportable"] = True
        manifest["status"] = "completed"
        manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
        _write_json(manifest_path, manifest)
        return ReportableBaselineResult(run_id, str(run_dir), raw_count, len(findings), {name: value["metrics"] for name, value in evaluations.items()})
    except Exception as error:
        manifest["status"] = "failed"
        manifest["reportable"] = False
        manifest["error"] = str(error)
        manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
        _write_json(manifest_path, manifest)
        raise ReportableBaselineError(str(error)) from error


def validate_reportable_baseline(*, run_dir: Path, dataset: Path, dataset_manifest: Path, bundle_dir: Path, rules_dir: Path, project_root: Path) -> ReportableBaselineResult:
    run_dir, dataset, dataset_manifest, bundle_dir, rules_dir, project_root = (run_dir.resolve(), dataset.resolve(), dataset_manifest.resolve(), bundle_dir.resolve(), rules_dir.resolve(), project_root.resolve())
    _validate_bundle(bundle_dir, rules_dir, project_root)
    manifest = _read_object(run_dir / "manifest.json", "reportable baseline manifest")
    if manifest.get("schema_version") != 1 or manifest.get("status") != "completed" or manifest.get("purpose") != "reportable" or manifest.get("reportable") is not True:
        raise ReportableBaselineError("reportable baseline manifest is incomplete")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise ReportableBaselineError("reportable baseline inputs are missing")
    for name in ("bundle_manifest", "ruleset"):
        _validate_artifact(run_dir, inputs.get(name))
    cohorts = inputs.get("cohorts")
    if not isinstance(cohorts, dict):
        raise ReportableBaselineError("reportable baseline cohorts are missing")
    for split in SPLITS:
        _validate_artifact(run_dir, cohorts.get(split))
    source = inputs.get("bundle_source")
    if not isinstance(source, dict) or source.get("manifest_sha256") != sha256_file(bundle_dir / "manifest.json"):
        raise ReportableBaselineError("reportable bundle source mismatch")
    copied_ruleset = run_dir / str(inputs["ruleset"]["path"])
    load_ruleset(copied_ruleset, rules_dir, project_root)
    scans = manifest.get("scans")
    if not isinstance(scans, list):
        raise ReportableBaselineError("reportable baseline scans are missing")
    for scan in scans:
        if not isinstance(scan, dict):
            raise ReportableBaselineError("invalid scan record")
        for prefix in ("stdout", "stderr"):
            path = Path(str(scan.get(f"{prefix}_path", ""))).resolve()
            if not path.is_relative_to(run_dir) or sha256_file(path) != scan.get(f"{prefix}_sha256"):
                raise ReportableBaselineError(f"scan {prefix} artifact mismatch")
    dataset_info = _read_object(dataset_manifest, "dataset manifest")
    findings, raw_count = normalize_findings(dataset, str(dataset_info["frozen_commit"]), scans)
    normalized = manifest.get("normalized")
    _validate_artifact(run_dir, normalized)
    findings_path = run_dir / str(normalized["path"])
    if _read_jsonl(findings_path) != findings:
        raise ReportableBaselineError("normalized findings do not match raw evidence")
    context = manifest.get("context")
    if not isinstance(context, dict) or not isinstance(context.get("artifact"), dict):
        raise ReportableBaselineError("reportable baseline context is missing")
    _validate_artifact(run_dir, context["artifact"])
    context_result = validate_contexts(
        dataset, findings_path, run_dir / str(context["artifact"]["path"]),
        before=CONTEXT_BEFORE, after=CONTEXT_AFTER, max_lines=CONTEXT_MAX_LINES,
    )
    if context.get("count") != context_result.context_count or context_result.context_count != len(findings):
        raise ReportableBaselineError("reportable baseline context mismatch")
    evaluations = evaluate_cohorts(_cohort_dir_from_inputs(run_dir, inputs), findings, raw_count)
    stored = manifest.get("evaluation")
    if not isinstance(stored, dict):
        raise ReportableBaselineError("reportable baseline evaluation is missing")
    for split, value in evaluations.items():
        record = stored.get(split)
        if not isinstance(record, dict):
            raise ReportableBaselineError(f"missing {split} evaluation")
        _validate_artifact(run_dir, record.get("matches"))
        _validate_artifact(run_dir, record.get("metrics"))
        if _read_jsonl(run_dir / str(record["matches"]["path"])) != value["matches"] or _read_object(run_dir / str(record["metrics"]["path"]), f"{split} metrics") != value["metrics"]:
            raise ReportableBaselineError(f"{split} evaluation does not match normalized findings")
    counts = manifest.get("counts")
    if not isinstance(counts, dict) or counts.get("raw_findings") != raw_count or counts.get("normalized_findings") != len(findings):
        raise ReportableBaselineError("reportable baseline counts mismatch")
    return ReportableBaselineResult(str(manifest["run_id"]), str(run_dir), raw_count, len(findings), {name: value["metrics"] for name, value in evaluations.items()})


def _validate_bundle(bundle_dir: Path, rules_dir: Path, project_root: Path) -> None:
    manifest = _read_object(bundle_dir / "manifest.json", "reportable input manifest")
    if manifest.get("status") != "frozen" or manifest.get("reportable") is not True:
        raise ReportableBaselineError("reportable input bundle is invalid")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ReportableBaselineError("reportable input artifacts are missing")
    for relative, record in artifacts.items():
        if not isinstance(relative, str) or not isinstance(record, dict):
            raise ReportableBaselineError("invalid reportable input artifact")
        path = (bundle_dir / relative).resolve()
        if not path.is_relative_to(bundle_dir) or not path.is_file() or sha256_file(path) != record.get("sha256"):
            raise ReportableBaselineError("reportable input artifact hash mismatch")
    load_ruleset(bundle_dir / "ruleset.json", rules_dir, project_root)


def _cohort_dir_from_inputs(run_dir: Path, inputs: dict[str, object]) -> Path:
    cohorts = inputs.get("cohorts")
    if not isinstance(cohorts, dict):
        raise ReportableBaselineError("reportable baseline cohorts are missing")
    development = cohorts.get("development")
    if not isinstance(development, dict) or not isinstance(development.get("path"), str):
        raise ReportableBaselineError("development cohort artifact is invalid")
    return (run_dir / development["path"]).parent


def _artifact(root: Path, path: Path) -> dict[str, object]:
    return {"path": path.resolve().relative_to(root.resolve()).as_posix(), "sha256": sha256_file(path)}


def _validate_artifact(root: Path, record: object) -> None:
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        raise ReportableBaselineError("invalid artifact record")
    path = (root / record["path"]).resolve()
    if not path.is_relative_to(root) or not path.is_file() or sha256_file(path) != record.get("sha256"):
        raise ReportableBaselineError("reportable baseline artifact mismatch")


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReportableBaselineError(f"failed to read {label}: {error}") from error
    if not isinstance(value, dict):
        raise ReportableBaselineError(f"{label} must be an object")
    return value


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [value for line in path.read_text(encoding="utf-8").splitlines() if line for value in [json.loads(line)] if isinstance(value, dict)]


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
