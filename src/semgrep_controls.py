import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from semgrep_compat import CommandResult, run_command
from semgrep_rules import EXPECTED_REMOTE, RuleGitInfo, read_git_info, sha256_file

SCHEMA_VERSION = 1
CONTROL_TYPE = "independent_negative"
VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")


class ControlError(ValueError):
    """Raised when independent control evidence cannot be trusted."""


@dataclass(frozen=True)
class ControlResult:
    status: str
    semgrep_version: str
    upstream_commit: str
    control_count: int
    pass_count: int
    false_positive_count: int
    error_count: int
    report_path: str


class ControlRecord(TypedDict):
    control_id: str
    rule_id: str
    cwes: list[int]
    rule_path: str
    rule_sha256: str
    fixture_path: str
    fixture_sha256: str
    expected_findings: int
    rationale: str


class ControlManifest(TypedDict):
    schema_version: int
    control_type: str
    semgrep_version: str
    upstream_commit: str
    controls: list[ControlRecord]


CommandRunner = Callable[[list[str], Path | None], CommandResult]
GitReader = Callable[[Path], RuleGitInfo]


def validate_controls(
    project_root: Path,
    rules_dir: Path,
    manifest_path: Path,
    run_dir: Path,
    semgrep_executable: str,
    expected_version: str,
    git_reader: GitReader = read_git_info,
    command_runner: CommandRunner = run_command,
) -> ControlResult:
    if run_dir.exists():
        raise ControlError(f"run directory already exists: {run_dir}")

    project_root = _require_directory(project_root, "project root")
    rules_dir = _require_directory(rules_dir, "rules directory")
    manifest_path = _require_file(manifest_path, "control manifest")
    run_dir = run_dir.resolve()
    _require_within(manifest_path, project_root, "control manifest")
    if _is_within(run_dir, rules_dir):
        raise ControlError("run directory must be outside the upstream rules checkout")

    manifest = _load_manifest(manifest_path)
    if manifest["semgrep_version"] != expected_version:
        raise ControlError(
            "manifest Semgrep version mismatch: "
            f"expected {expected_version}, got {manifest['semgrep_version']}"
        )

    git_info = git_reader(rules_dir)
    _validate_git_info(git_info, manifest["upstream_commit"])
    resolved_controls = _preflight_controls(
        manifest["controls"], project_root, rules_dir
    )

    version_result = command_runner([semgrep_executable, "--version"], None)
    actual_version = _extract_version(version_result)
    if actual_version != expected_version:
        raise ControlError(
            "unexpected Semgrep version: "
            f"expected {expected_version}, got {actual_version or 'unknown'}"
        )

    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True)
    entries: list[dict[str, object]] = []
    summary: Counter[str] = Counter()

    for control, rule_path, fixture_path in resolved_controls:
        command = [
            semgrep_executable,
            "scan",
            "--config",
            str(rule_path),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--quiet",
            str(fixture_path),
        ]
        result = command_runner(command, project_root)
        stem = hashlib.sha256(control["control_id"].encode()).hexdigest()[:16]
        stdout_path = raw_dir / f"{stem}.stdout.json"
        stderr_path = raw_dir / f"{stem}.stderr.txt"
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        status, findings, scanner_errors, diagnostic = _classify_scan(
            result, control["expected_findings"]
        )
        summary[status] += 1
        entries.append(
            {
                **control,
                "status": status,
                "diagnostic": diagnostic,
                "command": command,
                "exit_code": result.returncode,
                "duration_ms": result.duration_ms,
                "finding_count": len(findings),
                "scanner_error_count": len(scanner_errors),
                "findings": [_finding_identity(item) for item in findings],
                "stdout_path": stdout_path.relative_to(run_dir).as_posix(),
                "stdout_sha256": sha256_file(stdout_path),
                "stderr_path": stderr_path.relative_to(run_dir).as_posix(),
                "stderr_sha256": sha256_file(stderr_path),
            }
        )

    normalized_summary = {
        status: summary[status] for status in ("ERROR", "FALSE_POSITIVE", "PASS")
    }
    report_path = run_dir / "controls.json"
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "control_type": CONTROL_TYPE,
        "coverage_status": "independent_negative_controls",
        "ruleset_status": "not_frozen",
        "semgrep_version": actual_version,
        "upstream_remote": git_info.remote_url,
        "upstream_commit": git_info.commit,
        "upstream_clean": git_info.clean,
        "upstream_detached": git_info.detached,
        "manifest_path": manifest_path.relative_to(project_root).as_posix(),
        "manifest_sha256": sha256_file(manifest_path),
        "control_count": len(entries),
        "summary": normalized_summary,
        "controls": entries,
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return ControlResult(
        status="completed",
        semgrep_version=actual_version,
        upstream_commit=git_info.commit,
        control_count=len(entries),
        pass_count=summary["PASS"],
        false_positive_count=summary["FALSE_POSITIVE"],
        error_count=summary["ERROR"],
        report_path=str(report_path),
    )


def _load_manifest(path: Path) -> ControlManifest:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ControlError(f"failed to read control manifest: {error}") from error
    if not isinstance(raw, dict):
        raise ControlError("control manifest must be a JSON object")
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ControlError("unsupported control manifest schema version")
    if raw.get("control_type") != CONTROL_TYPE:
        raise ControlError(f"control_type must be {CONTROL_TYPE}")

    version = raw.get("semgrep_version")
    commit = raw.get("upstream_commit")
    controls = raw.get("controls")
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise ControlError("manifest semgrep_version is invalid")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ControlError("manifest upstream_commit is invalid")
    if not isinstance(controls, list) or not controls:
        raise ControlError("manifest controls must be a non-empty list")

    parsed_controls: list[ControlRecord] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(controls, start=1):
        parsed = _parse_control(item, index)
        if parsed["control_id"] in seen_ids:
            raise ControlError(f"duplicate control ID: {parsed['control_id']}")
        seen_ids.add(parsed["control_id"])
        parsed_controls.append(parsed)
    return {
        "schema_version": SCHEMA_VERSION,
        "control_type": CONTROL_TYPE,
        "semgrep_version": version,
        "upstream_commit": commit,
        "controls": parsed_controls,
    }


def _parse_control(value: object, index: int) -> ControlRecord:
    if not isinstance(value, dict):
        raise ControlError(f"control {index} must be an object")
    text_fields = (
        "control_id",
        "rule_id",
        "rule_path",
        "rule_sha256",
        "fixture_path",
        "fixture_sha256",
        "rationale",
    )
    for field in text_fields:
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise ControlError(f"control {index} has invalid {field}")
    cwes = value.get("cwes")
    if not isinstance(cwes, list) or not cwes or not all(
        isinstance(cwe, int) and cwe > 0 for cwe in cwes
    ):
        raise ControlError(f"control {index} has invalid cwes")
    if value.get("expected_findings") != 0:
        raise ControlError(f"control {index} must expect zero findings")
    for field in ("rule_sha256", "fixture_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", value[field]):
            raise ControlError(f"control {index} has invalid {field}")
    return {
        "control_id": value["control_id"],
        "rule_id": value["rule_id"],
        "cwes": cwes,
        "rule_path": value["rule_path"],
        "rule_sha256": value["rule_sha256"],
        "fixture_path": value["fixture_path"],
        "fixture_sha256": value["fixture_sha256"],
        "expected_findings": 0,
        "rationale": value["rationale"],
    }


def _preflight_controls(
    controls: list[ControlRecord], project_root: Path, rules_dir: Path
) -> list[tuple[ControlRecord, Path, Path]]:
    resolved: list[tuple[ControlRecord, Path, Path]] = []
    for control in controls:
        rule_path = _require_file(
            rules_dir / control["rule_path"], f"rule for {control['control_id']}"
        )
        fixture_path = _require_file(
            project_root / control["fixture_path"],
            f"fixture for {control['control_id']}",
        )
        _require_within(rule_path, rules_dir, "rule")
        _require_within(fixture_path, project_root, "fixture")
        if _is_within(fixture_path, rules_dir):
            raise ControlError("control fixture must be outside upstream rules checkout")
        if sha256_file(rule_path) != control["rule_sha256"]:
            raise ControlError(f"rule hash mismatch: {control['control_id']}")
        if sha256_file(fixture_path) != control["fixture_sha256"]:
            raise ControlError(f"fixture hash mismatch: {control['control_id']}")
        resolved.append((control, rule_path, fixture_path))
    return resolved


def _validate_git_info(git_info: RuleGitInfo, expected_commit: str) -> None:
    if git_info.remote_url.rstrip("/") != EXPECTED_REMOTE.rstrip("/"):
        raise ControlError(f"unexpected upstream remote: {git_info.remote_url}")
    if git_info.commit != expected_commit:
        raise ControlError(
            f"upstream commit mismatch: expected {expected_commit}, got {git_info.commit}"
        )
    if not git_info.clean:
        raise ControlError("upstream rules checkout is not clean")
    if not git_info.detached:
        raise ControlError("upstream rules checkout is not detached")


def _extract_version(result: CommandResult) -> str:
    if result.returncode != 0:
        return ""
    match = VERSION_PATTERN.search(result.stdout)
    return match.group(0) if match else ""


def _classify_scan(
    result: CommandResult, expected_findings: int
) -> tuple[str, list[object], list[object], str | None]:
    if result.returncode != 0:
        return "ERROR", [], [], "Semgrep exited with a non-zero status"
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return "ERROR", [], [], "Semgrep stdout is not valid JSON"
    if not isinstance(payload, dict):
        return "ERROR", [], [], "Semgrep JSON must be an object"
    findings = payload.get("results")
    errors = payload.get("errors")
    if not isinstance(findings, list) or not isinstance(errors, list):
        return "ERROR", [], [], "Semgrep JSON has invalid results or errors"
    if errors:
        return "ERROR", findings, errors, "Semgrep reported scanner errors"
    if len(findings) != expected_findings:
        return "FALSE_POSITIVE", findings, errors, "unexpected finding count"
    return "PASS", findings, errors, None


def _finding_identity(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"raw_type": type(value).__name__}
    start = value.get("start")
    line = start.get("line") if isinstance(start, dict) else None
    return {
        "check_id": value.get("check_id"),
        "path": value.get("path"),
        "start_line": line,
    }


def _require_directory(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_dir():
        raise ControlError(f"{label} not found: {path}")
    return resolved


def _require_file(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise ControlError(f"{label} not found: {path}")
    return resolved


def _require_within(path: Path, parent: Path, label: str) -> None:
    if not _is_within(path, parent):
        raise ControlError(f"{label} path escapes its allowed root: {path}")


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True
