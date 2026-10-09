import json
from pathlib import Path

import pytest

from semgrep_compat import CommandResult
from semgrep_scan import ScanError, scan_rules


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


def test_scan_rules_uses_python_for_script_launcher(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    (rules_dir / "java").mkdir(parents=True)
    for name in ("rule.yaml", "other.yaml"):
        (rules_dir / "java" / name).write_text("rule", encoding="utf-8")
    source_root = tmp_path / "source"
    source_root.mkdir()
    launcher = tmp_path / "launcher.py"
    launcher.write_text("pass\n", encoding="utf-8")
    calls: list[list[str]] = []

    def runner(command: list[str], cwd: Path | None) -> CommandResult:
        calls.append(command)
        if command[-1] == "--version":
            return CommandResult(0, "1.179.0", "", 1)
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

    scan_rules(
        rules_dir,
        ruleset("0" * 64),
        source_root,
        tmp_path / "raw",
        str(launcher),
        "1.179.0",
        runner,
        verify_hashes=False,
    )
    assert calls[0][1] == str(launcher.resolve())
    assert calls[0][-1] == "--version"
    assert calls[1][2] == "scan"
