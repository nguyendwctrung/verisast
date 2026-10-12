import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path

from semgrep_compat import CommandResult, run_command
from semgrep_rules import sha256_file

VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")
CommandRunner = Callable[[list[str], Path | None], CommandResult]


class ScanError(ValueError):
    pass


def scan_rules(
    rules_dir: Path,
    ruleset: dict[str, object],
    source_root: Path,
    raw_dir: Path,
    semgrep_executable: str,
    expected_version: str,
    command_runner: CommandRunner = run_command,
    verify_hashes: bool = True,
) -> list[dict[str, object]]:
    rules_dir = rules_dir.resolve()
    source_root = source_root.resolve()
    raw_dir = raw_dir.resolve()
    if not source_root.is_dir():
        raise ScanError(f"source root not found: {source_root}")
    command_prefix = _command_prefix(semgrep_executable)
    version_result = command_runner([*command_prefix, "--version"], None)
    version_output = f"{version_result.stdout}\n{version_result.stderr}"
    match = VERSION_PATTERN.search(version_output)
    if version_result.returncode != 0:
        detail = version_result.stderr.strip() or version_result.stdout.strip()
        raise ScanError(
            "Semgrep version command failed with exit code "
            f"{version_result.returncode}: {detail or 'no diagnostic'}"
        )
    if match is None:
        raise ScanError(
            "failed to parse Semgrep version from command output: "
            f"{version_output.strip() or 'no output'}"
        )
    version = match.group(0)
    if version != expected_version:
        raise ScanError(f"unexpected Semgrep version: {version}; expected {expected_version}")
    raw_dir.mkdir(parents=True, exist_ok=True)
    scans: list[dict[str, object]] = []
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ScanError("ruleset contains no rules")
    for rule in rules:
        if not isinstance(rule, dict):
            raise ScanError("ruleset rule must be an object")
        identity = str(rule.get("identity", ""))
        relative_rule = str(rule.get("source_path", ""))
        rule_path = (rules_dir / relative_rule).resolve()
        if not rule_path.is_relative_to(rules_dir) or not rule_path.is_file():
            raise ScanError(f"rule file not found: {relative_rule}")
        if verify_hashes and sha256_file(rule_path) != rule.get("source_sha256"):
            raise ScanError(f"rule hash mismatch: {relative_rule}")
        key = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        stdout_path = raw_dir / f"{key}.stdout.json"
        stderr_path = raw_dir / f"{key}.stderr.txt"
        command = [
            *command_prefix,
            "scan",
            "--config",
            str(rule_path),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--quiet",
            str(source_root),
        ]
        result = command_runner(command, None)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        if result.returncode != 0:
            raise ScanError(f"Semgrep failed for {identity} with exit code {result.returncode}")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ScanError(f"invalid Semgrep JSON for {identity}: {error}") from error
        if not isinstance(payload, dict):
            raise ScanError(f"Semgrep JSON must be an object for {identity}")
        if payload.get("version") != expected_version:
            raise ScanError(f"Semgrep JSON version mismatch for {identity}")
        results = payload.get("results")
        errors = payload.get("errors")
        if not isinstance(results, list) or not isinstance(errors, list):
            raise ScanError(f"Semgrep JSON has invalid results or errors for {identity}")
        if errors:
            raise ScanError(f"Semgrep reported scanner errors for {identity}")
        scans.append(
            {
                "rule_identity": identity,
                "rule_id": rule["rule_id"],
                "rule_path": relative_rule,
                "rule_sha256": rule["source_sha256"],
                "reviewed_cwes": rule["reviewed_cwes"],
                "command": command,
                "duration_ms": result.duration_ms,
                "exit_code": result.returncode,
                "finding_count": len(results),
                "stdout_path": str(stdout_path),
                "stdout_sha256": sha256_file(stdout_path),
                "stderr_path": str(stderr_path),
                "stderr_sha256": sha256_file(stderr_path),
            }
        )
    return scans


def _command_prefix(executable: str) -> list[str]:
    if executable != "semgrep":
        raise ScanError("Semgrep must use the semgrep CLI command")
    return ["semgrep"]
