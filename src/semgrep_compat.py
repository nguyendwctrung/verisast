import hashlib
import json
import re
import subprocess
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from semgrep_rules import EXPECTED_REMOTE, RuleGitInfo, read_git_info, sha256_file

SCHEMA_VERSION = 1
VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")

PRO_MARKERS = (
    "semgrep pro",
    "pro engine",
    "requires pro",
    "requires semgrep pro",
    "interfile analysis",
    "semgrep login",
)

INCOMPATIBLE_MARKERS = (
    "invalid rule schema",
    "invalid configuration",
    "configuration error",
    "pattern parse error",
    "rule parse error",
    "invalid pattern",
    "invalid language",
    "unsupported rule",
)


class CompatError(ValueError):
    """Raised when compatibility validation cannot be trusted."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int


@dataclass(frozen=True)
class CompatResult:
    status: str
    semgrep_version: str
    upstream_commit: str
    file_count: int
    compatible_count: int
    incompatible_count: int
    requires_pro_count: int
    error_count: int
    report_path: str


CommandRunner = Callable[[list[str], Path | None], CommandResult]
GitReader = Callable[[Path], RuleGitInfo]


class InventoryData(TypedDict):
    status: object
    upstream_commit: object
    rules: list[object]


class CandidateGroup(TypedDict):
    source_sha256: str
    rule_ids: list[str]
    cwes: set[int]


def run_command(
    command: list[str],
    cwd: Path | None = None,
) -> CommandResult:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        duration_ms = round((time.perf_counter() - started) * 1000)
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr=str(error),
            duration_ms=duration_ms,
        )

    duration_ms = round((time.perf_counter() - started) * 1000)
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_ms=duration_ms,
    )


def classify_result(result: CommandResult) -> str:
    diagnostic = f"{result.stdout}\n{result.stderr}".lower()

    if any(marker in diagnostic for marker in PRO_MARKERS):
        return "REQUIRES_PRO"

    parsed = _parse_json(result.stdout)
    errors = parsed.get("errors") if isinstance(parsed, dict) else None

    if result.returncode == 0:
        if not isinstance(parsed, dict):
            return "ERROR"
        if not isinstance(parsed.get("results"), list):
            return "ERROR"
        if isinstance(errors, list) and errors:
            error_text = json.dumps(errors).lower()
            if any(marker in error_text for marker in PRO_MARKERS):
                return "REQUIRES_PRO"
            return "INCOMPATIBLE"
        return "COMPATIBLE"

    if isinstance(errors, list) and errors:
        return "INCOMPATIBLE"

    if any(marker in diagnostic for marker in INCOMPATIBLE_MARKERS):
        return "INCOMPATIBLE"

    return "ERROR"


def validate_rules(
    rules_dir: Path,
    inventory_path: Path,
    run_dir: Path,
    semgrep_executable: str,
    expected_version: str,
    git_reader: GitReader = read_git_info,
    command_runner: CommandRunner = run_command,
) -> CompatResult:
    rules_dir = rules_dir.resolve()
    inventory_path = inventory_path.resolve()
    run_dir = run_dir.resolve()

    if run_dir.exists():
        raise CompatError(f"run directory already exists: {run_dir}")
    if not rules_dir.is_dir():
        raise CompatError(f"rule directory not found: {rules_dir}")
    if not inventory_path.is_file():
        raise CompatError(f"inventory not found: {inventory_path}")
    if run_dir.is_relative_to(rules_dir):
        raise CompatError("run directory must be outside the upstream checkout")

    inventory = _load_inventory(inventory_path)
    git_info = git_reader(rules_dir)
    _validate_provenance(inventory, git_info)
    candidates = _group_candidates(inventory, rules_dir)

    version_result = command_runner(
        [semgrep_executable, "--version"],
        None,
    )
    if version_result.returncode != 0:
        detail = version_result.stderr.strip() or version_result.stdout.strip()
        raise CompatError(f"failed to read Semgrep version: {detail}")

    semgrep_version = _extract_version(version_result.stdout)
    if semgrep_version != expected_version:
        raise CompatError(
            "unexpected Semgrep version: "
            f"expected {expected_version}, observed {semgrep_version}"
        )

    run_dir.mkdir(parents=True)
    raw_dir = run_dir / "raw"
    raw_dir.mkdir()
    probe_path = run_dir / "CompatProbe.java"
    probe_path.write_text(
        "final class CompatProbe {\n"
        "    void run() {\n"
        '        System.out.println("compatibility probe");\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    file_results: list[dict[str, object]] = []
    summary: Counter[str] = Counter()

    for source_path, candidate in sorted(candidates.items()):
        absolute_rule_path = rules_dir / source_path
        evidence_id = hashlib.sha256(
            source_path.encode("utf-8")
        ).hexdigest()[:16]

        command = [
            semgrep_executable,
            "scan",
            "--config",
            str(absolute_rule_path),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--jobs=1",
            "--timeout=30",
            str(probe_path),
        ]

        result = command_runner(command, run_dir)
        status = classify_result(result)
        summary[status] += 1

        stdout_path = raw_dir / f"{evidence_id}.stdout.json"
        stderr_path = raw_dir / f"{evidence_id}.stderr.txt"
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")

        file_results.append(
            {
                "source_path": source_path,
                "source_sha256": candidate["source_sha256"],
                "rule_ids": sorted(candidate["rule_ids"]),
                "cwes": sorted(candidate["cwes"]),
                "status": status,
                "command": command,
                "exit_code": result.returncode,
                "duration_ms": result.duration_ms,
                "stdout_path": stdout_path.relative_to(run_dir).as_posix(),
                "stdout_sha256": sha256_file(stdout_path),
                "stderr_path": stderr_path.relative_to(run_dir).as_posix(),
                "stderr_sha256": sha256_file(stderr_path),
            }
        )

    report_path = run_dir / "compatibility.json"
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "semgrep_version": semgrep_version,
        "semgrep_executable": semgrep_executable,
        "upstream_url": git_info.remote_url,
        "upstream_commit": git_info.commit,
        "working_tree_clean": git_info.clean,
        "head_detached": git_info.detached,
        "inventory_path": str(inventory_path),
        "inventory_sha256": sha256_file(inventory_path),
        "probe_path": probe_path.relative_to(run_dir).as_posix(),
        "probe_sha256": sha256_file(probe_path),
        "candidate_rule_count": len(inventory["rules"]),
        "candidate_file_count": len(file_results),
        "summary": {
            status: summary[status]
            for status in (
                "COMPATIBLE",
                "INCOMPATIBLE",
                "REQUIRES_PRO",
                "ERROR",
            )
        },
        "files": file_results,
        "coverage_status": "not_validated",
        "ruleset_status": "not_frozen",
    }
    _write_json_atomic(report_path, report)

    return CompatResult(
        status="completed",
        semgrep_version=semgrep_version,
        upstream_commit=git_info.commit,
        file_count=len(file_results),
        compatible_count=summary["COMPATIBLE"],
        incompatible_count=summary["INCOMPATIBLE"],
        requires_pro_count=summary["REQUIRES_PRO"],
        error_count=summary["ERROR"],
        report_path=str(report_path),
    )


def _load_inventory(path: Path) -> InventoryData:
    try:
        inventory = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CompatError(f"failed to read inventory: {error}") from error

    if not isinstance(inventory, dict):
        raise CompatError("inventory root must be an object")
    status = inventory.get("status")
    if status != "passed":
        raise CompatError("inventory status is not passed")
    rules = inventory.get("rules")
    if not isinstance(rules, list) or not rules:
        raise CompatError("inventory contains no candidate rules")
    return {
        "status": status,
        "upstream_commit": inventory.get("upstream_commit"),
        "rules": rules,
    }


def _validate_provenance(
    inventory: InventoryData,
    git_info: RuleGitInfo,
) -> None:
    if _normalize_remote(git_info.remote_url) != _normalize_remote(EXPECTED_REMOTE):
        raise CompatError(f"unexpected Git remote: {git_info.remote_url}")
    if not git_info.clean:
        raise CompatError("rule working tree is not clean")
    if not git_info.detached:
        raise CompatError("rule HEAD is not detached")

    inventory_commit = inventory.get("upstream_commit")
    if inventory_commit != git_info.commit:
        raise CompatError(
            "inventory commit does not match rule checkout: "
            f"{inventory_commit} != {git_info.commit}"
        )


def _group_candidates(
    inventory: InventoryData,
    rules_dir: Path,
) -> dict[str, CandidateGroup]:
    grouped: dict[str, CandidateGroup] = {}
    observed_keys: set[tuple[str, str]] = set()

    for index, item in enumerate(inventory["rules"], start=1):
        if not isinstance(item, dict):
            raise CompatError(f"inventory rule {index} must be an object")

        rule_id = item.get("id")
        source_path = item.get("source_path")
        source_hash = item.get("source_sha256")
        cwes = item.get("cwes")

        if not isinstance(rule_id, str) or not rule_id:
            raise CompatError(f"inventory rule {index} has no valid ID")
        if not isinstance(source_path, str) or not source_path:
            raise CompatError(f"inventory rule {rule_id} has no source path")

        identity = (source_path, rule_id)
        if identity in observed_keys:
            raise CompatError(
                "duplicate inventory rule identity: "
                f"{source_path}::{rule_id}"
            )
        observed_keys.add(identity)

        if not isinstance(source_hash, str) or len(source_hash) != 64:
            raise CompatError(f"inventory rule {rule_id} has no valid source hash")
        if not isinstance(cwes, list) or not all(
            isinstance(cwe, int) for cwe in cwes
        ):
            raise CompatError(f"inventory rule {rule_id} has invalid CWEs")

        absolute_path = (rules_dir / source_path).resolve()
        if not absolute_path.is_relative_to(rules_dir):
            raise CompatError(f"rule path escapes checkout: {source_path}")
        if not absolute_path.is_file():
            raise CompatError(f"rule file not found: {source_path}")

        observed_hash = sha256_file(absolute_path)
        if observed_hash != source_hash:
            raise CompatError(
                f"rule hash mismatch for {source_path}: "
                f"{source_hash} != {observed_hash}"
            )

        if source_path not in grouped:
            grouped[source_path] = {
                "source_sha256": source_hash,
                "rule_ids": [],
                "cwes": set(),
            }
        elif grouped[source_path]["source_sha256"] != source_hash:
            raise CompatError(
                f"conflicting source hashes for {source_path}"
            )

        grouped[source_path]["rule_ids"].append(rule_id)
        grouped[source_path]["cwes"].update(cwes)

    return grouped


def _extract_version(output: str) -> str:
    match = VERSION_PATTERN.search(output)
    if not match:
        raise CompatError(f"unable to parse Semgrep version: {output.strip()}")
    return match.group(0)


def _parse_json(value: str) -> object:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _normalize_remote(url: str) -> str:
    normalized = url.strip().rstrip("/")
    normalized = normalized.removesuffix(".git")
    return normalized.lower()


def _write_json_atomic(
    path: Path,
    payload: dict[str, object],
) -> None:
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    temporary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(path)
