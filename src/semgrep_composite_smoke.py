import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from semgrep_rules import sha256_file
from semgrep_ruleset import RulesetError, load_ruleset
from semgrep_scan import ScanError, scan_rules


class CompositeSmokeError(ValueError):
    pass


@dataclass(frozen=True)
class CompositeSmokeResult:
    run_id: str
    rule_count: int
    project_finding_count: int
    manifest_path: str


def run_composite_smoke(
    *,
    run_id: str,
    upstream_rules_dir: Path,
    project_root: Path,
    catalog_path: Path,
    review_path: Path,
    ruleset_path: Path,
    source_root: Path,
    run_dir: Path,
    semgrep_executable: str,
    expected_version: str,
    scan_runner=scan_rules,
) -> CompositeSmokeResult:
    if not run_id.strip() or any(character in run_id for character in "\\/:"):
        raise CompositeSmokeError("invalid run ID")
    run_dir = run_dir.resolve()
    if run_dir.exists():
        raise CompositeSmokeError(f"smoke run directory already exists: {run_dir}")
    source_root = source_root.resolve()
    if not source_root.is_dir():
        raise CompositeSmokeError(f"smoke source root not found: {source_root}")
    source_files = _source_files(source_root)
    if not source_files:
        raise CompositeSmokeError("smoke source root has no Java files")

    run_dir.mkdir(parents=True)
    manifest_path = run_dir / "manifest.json"
    manifest: dict[str, object] = {
        "schema_version": 1,
        "status": "running",
        "run_id": run_id,
        "purpose": "composite_smoke",
        "reportable": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(manifest_path, manifest)
    try:
        catalog_path = catalog_path.resolve()
        review_path = review_path.resolve()
        ruleset_path = ruleset_path.resolve()
        catalog = _read_object(catalog_path, "composite catalog")
        review = _read_object(review_path, "composite review")
        _validate_inputs(catalog, review, catalog_path, ruleset_path, review_path)
        ruleset = load_ruleset(ruleset_path, upstream_rules_dir, project_root)
        if ruleset.get("purpose") != "development" or ruleset.get("reportable") is not False:
            raise CompositeSmokeError("composite smoke requires a development-only ruleset")
        scans = scan_runner(
            upstream_rules_dir,
            ruleset,
            source_root,
            run_dir / "raw",
            semgrep_executable,
            expected_version,
            project_root=project_root,
        )
        _validate_raw_scans(scans, run_dir / "raw")
        project_findings = sum(
            int(scan["finding_count"])
            for scan in scans
            if scan.get("rule_id") == "project-cwe327-desede-ecb-default"
        )
        if project_findings < 1:
            raise CompositeSmokeError("project CWE-327 rule produced no smoke finding")
        manifest["inputs"] = {
            "catalog": _artifact(catalog_path),
            "review": _artifact(review_path),
            "ruleset": _artifact(ruleset_path),
            "source_files": [
                {
                    "path": path.relative_to(source_root).as_posix(),
                    "sha256": sha256_file(path),
                }
                for path in source_files
            ],
        }
        manifest["semgrep_version"] = expected_version
        manifest["scans"] = scans
        manifest["rule_count"] = len(scans)
        manifest["project_cwe327_finding_count"] = project_findings
        manifest["status"] = "completed"
        manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
        _write_json(manifest_path, manifest)
        return CompositeSmokeResult(
            run_id=run_id,
            rule_count=len(scans),
            project_finding_count=project_findings,
            manifest_path=str(manifest_path),
        )
    except (CompositeSmokeError, RulesetError, ScanError, OSError, ValueError) as error:
        manifest["status"] = "failed"
        manifest["reportable"] = False
        manifest["error"] = str(error)
        manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
        _write_json(manifest_path, manifest)
        raise CompositeSmokeError(str(error)) from error


def run_composite_smoke_command(args: object) -> int:
    result = run_composite_smoke(
        run_id=str(getattr(args, "run_id")),
        upstream_rules_dir=Path(getattr(args, "upstream_rules")),
        project_root=Path(getattr(args, "project_root")),
        catalog_path=Path(getattr(args, "catalog")),
        review_path=Path(getattr(args, "review")),
        ruleset_path=Path(getattr(args, "ruleset")),
        source_root=Path(getattr(args, "source_root")),
        run_dir=Path(getattr(args, "run_dir")),
        semgrep_executable=str(getattr(args, "semgrep")),
        expected_version=str(getattr(args, "expected_version")),
    )
    print("COMPOSITE_SMOKE_STATUS=completed")
    print(f"COMPOSITE_SMOKE_RUN_ID={result.run_id}")
    print(f"COMPOSITE_SMOKE_RULES={result.rule_count}")
    print(f"PROJECT_CWE327_FINDINGS={result.project_finding_count}")
    print(f"COMPOSITE_SMOKE_MANIFEST={result.manifest_path}")
    return 0


def _validate_inputs(
    catalog: dict[str, object],
    review: dict[str, object],
    catalog_path: Path,
    ruleset_path: Path,
    review_path: Path,
) -> None:
    if catalog.get("schema_version") != 1 or catalog.get("status") != "passed":
        raise CompositeSmokeError("composite catalog is not a passed schema version 1 artifact")
    if review.get("inventory_sha256") != sha256_file(catalog_path):
        raise CompositeSmokeError("composite review catalog hash mismatch")
    ruleset = _read_object(ruleset_path, "composite ruleset")
    if ruleset.get("catalog_sha256") != sha256_file(catalog_path):
        raise CompositeSmokeError("composite ruleset catalog hash mismatch")
    if ruleset.get("review_sha256") != sha256_file(review_path):
        raise CompositeSmokeError("composite ruleset review hash mismatch")


def _validate_raw_scans(scans: list[dict[str, object]], raw_dir: Path) -> None:
    if not scans:
        raise CompositeSmokeError("composite smoke produced no scans")
    raw_dir = raw_dir.resolve()
    for scan in scans:
        for prefix in ("stdout", "stderr"):
            path = Path(str(scan.get(f"{prefix}_path", ""))).resolve()
            if not path.is_relative_to(raw_dir) or not path.is_file():
                raise CompositeSmokeError(f"smoke {prefix} artifact is missing")
            if sha256_file(path) != scan.get(f"{prefix}_sha256"):
                raise CompositeSmokeError(f"smoke {prefix} artifact hash mismatch")


def _source_files(source_root: Path) -> list[Path]:
    return sorted(path for path in source_root.rglob("*.java") if path.is_file())


def _artifact(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": sha256_file(path)}


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CompositeSmokeError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise CompositeSmokeError(f"{label} must be a JSON object")
    return value


def _write_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--upstream-rules", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--ruleset", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--expected-version", required=True)
    return run_composite_smoke_command(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
