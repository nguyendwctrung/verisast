import json
from pathlib import Path

import pytest

from semgrep_compat import CommandResult
from semgrep_rules import sha256_file
from semgrep_scan import ScanError, _command_prefix, scan_rules


def ruleset(rule_hash: str) -> dict[str, object]:
    return {
        "rules": [
            {
                "identity": "java/rule.yaml::same-id",
                "rule_id": "same-id",
                "source_path": "java/rule.yaml",
                "source_sha256": rule_hash,
                "reviewed_cwes": [78],
            },
            {
                "identity": "java/other.yaml::same-id",
                "rule_id": "same-id",
                "source_path": "java/other.yaml",
                "source_sha256": rule_hash,
                "reviewed_cwes": [78],
            },
        ]
    }


def test_scan_rules_runs_each_identity_separately(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    (rules_dir / "java").mkdir(parents=True)
    for name in ("rule.yaml", "other.yaml"):
        (rules_dir / "java" / name).write_text("rule", encoding="utf-8")
    source_root = tmp_path / "source"
    source_root.mkdir()
    calls: list[list[str]] = []

    def runner(command: list[str], cwd: Path | None) -> CommandResult:
        calls.append(command)
        if command[-1] == "--version":
            return CommandResult(0, "1.179.0\n", "", 1)
        return CommandResult(
            0,
            json.dumps({"version": "1.179.0", "results": [], "errors": [], "paths": {"scanned": []}}),
            "",
            2,
        )

    scans = scan_rules(
        rules_dir,
        ruleset("0" * 64),
        source_root,
        tmp_path / "raw",
        "semgrep",
        "1.179.0",
        runner,
        verify_hashes=False,
    )
    assert len(scans) == 2
    assert scans[0]["rule_identity"] != scans[1]["rule_identity"]
    assert calls[1][1:3] == ["scan", "--config"]
    assert "--metrics=off" in calls[1]


def test_scan_rules_rejects_scanner_errors(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    (rules_dir / "java").mkdir(parents=True)
    for name in ("rule.yaml", "other.yaml"):
        (rules_dir / "java" / name).write_text("rule", encoding="utf-8")
    source_root = tmp_path / "source"
    source_root.mkdir()

    def runner(command: list[str], cwd: Path | None) -> CommandResult:
        if command[-1] == "--version":
            return CommandResult(0, "1.179.0", "", 1)
        return CommandResult(0, json.dumps({"version": "1.179.0", "results": [], "errors": [{}]}), "", 1)

    with pytest.raises(ScanError, match="scanner errors"):
        scan_rules(
            rules_dir,
            ruleset("0" * 64),
            source_root,
            tmp_path / "raw",
            "semgrep",
            "1.179.0",
            runner,
            verify_hashes=False,
        )


def test_scan_rules_accepts_version_written_to_stderr(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    (rules_dir / "java").mkdir(parents=True)
    for name in ("rule.yaml", "other.yaml"):
        (rules_dir / "java" / name).write_text("rule", encoding="utf-8")
    source_root = tmp_path / "source"
    source_root.mkdir()

    def runner(command: list[str], cwd: Path | None) -> CommandResult:
        if command[-1] == "--version":
            return CommandResult(0, "", "Semgrep 1.179.0\n", 1)
        return CommandResult(
            0,
            json.dumps(
                {
                    "version": "1.179.0",
                    "results": [],
                    "errors": [],
                    "paths": {"scanned": []},
                }
            ),
            "",
            1,
        )

    scans = scan_rules(
        rules_dir,
        ruleset("0" * 64),
        source_root,
        tmp_path / "raw",
        "semgrep",
        "1.179.0",
        runner,
        verify_hashes=False,
    )
    assert len(scans) == 2


def test_scan_rules_resolves_project_authored_rule_from_project_root(tmp_path: Path) -> None:
    upstream_rules = tmp_path / "upstream"
    upstream_rules.mkdir()
    project_root = tmp_path / "project"
    rule_path = project_root / "rules" / "project" / "rule.yaml"
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text("rule", encoding="utf-8")
    source_root = tmp_path / "source"
    source_root.mkdir()
    commands: list[list[str]] = []

    def runner(command: list[str], cwd: Path | None) -> CommandResult:
        commands.append(command)
        if command[-1] == "--version":
            return CommandResult(0, "1.179.0", "", 1)
        return CommandResult(
            0,
            json.dumps({"version": "1.179.0", "results": [], "errors": []}),
            "",
            1,
        )

    scan_rules(
        upstream_rules,
        {
            "rules": [
                {
                    "identity": "project_root:rules/project/rule.yaml::project-rule",
                    "rule_id": "project-rule",
                    "source_path": "rules/project/rule.yaml",
                    "source_root": "project_root",
                    "source_sha256": sha256_file(rule_path),
                    "reviewed_cwes": [327],
                }
            ]
        },
        source_root,
        tmp_path / "raw",
        "semgrep",
        "1.179.0",
        runner,
        project_root=project_root,
    )

    assert commands[1][3] == str(rule_path.resolve())


def test_scan_rules_requires_project_root_for_project_authored_rule(tmp_path: Path) -> None:
    upstream_rules = tmp_path / "upstream"
    upstream_rules.mkdir()
    source_root = tmp_path / "source"
    source_root.mkdir()

    def runner(command: list[str], cwd: Path | None) -> CommandResult:
        return CommandResult(0, "1.179.0", "", 1)

    with pytest.raises(ScanError, match="project root is required"):
        scan_rules(
            upstream_rules,
            {
                "rules": [
                    {
                        "identity": "project::rule",
                        "rule_id": "rule",
                        "source_path": "rules/project/rule.yaml",
                        "source_root": "project_root",
                        "source_sha256": "0" * 64,
                        "reviewed_cwes": [327],
                    }
                ]
            },
            source_root,
            tmp_path / "raw",
            "semgrep",
            "1.179.0",
            runner,
        )


@pytest.mark.parametrize("command", ["semgrep.exe", "pysemgrep_launcher.py", "C:/tools/semgrep"])
def test_command_prefix_rejects_non_cli_semgrep_commands(command: str) -> None:
    with pytest.raises(ScanError, match="semgrep CLI command"):
        _command_prefix(command)


def test_command_prefix_uses_semgrep_cli() -> None:
    assert _command_prefix("semgrep") == ["semgrep"]
