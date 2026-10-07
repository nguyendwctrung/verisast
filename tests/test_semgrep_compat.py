import json
from pathlib import Path

import pytest

from semgrep_compat import CommandResult, CompatError, classify_result, validate_rules
from semgrep_rules import RuleGitInfo, sha256_file

RULE_COMMIT = "a" * 40
SEMGREP_VERSION = "1.179.0"


def write_rule(path: Path, rule_id: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""rules:
  - id: {rule_id}
    languages: [java]
    severity: WARNING
    message: Test rule
    pattern: danger(...)
    metadata:
      category: security
      cwe: CWE-78
""",
        encoding="utf-8",
    )
    return sha256_file(path)


def write_inventory(
    path: Path,
    rule_path: str,
    rule_hash: str,
    commit: str = RULE_COMMIT,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "passed",
                "upstream_url": "https://github.com/semgrep/semgrep-rules.git",
                "upstream_commit": commit,
                "working_tree_clean": True,
                "head_detached": True,
                "candidate_rule_count": 1,
                "rules": [
                    {
                        "id": "test-rule",
                        "source_path": rule_path,
                        "source_sha256": rule_hash,
                        "cwes": [78],
                        "execution_compatibility": "not_validated",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def clean_git_info() -> RuleGitInfo:
    return RuleGitInfo(
        remote_url="https://github.com/semgrep/semgrep-rules.git",
        commit=RULE_COMMIT,
        clean=True,
        detached=True,
    )


@pytest.mark.parametrize(
    "result, expected",
    [
        (
            CommandResult(
                returncode=0,
                stdout='{"results": [], "errors": []}',
                stderr="",
                duration_ms=10,
            ),
            "COMPATIBLE",
        ),
        (
            CommandResult(
                returncode=2,
                stdout="",
                stderr="This rule requires Semgrep Pro Engine",
                duration_ms=10,
            ),
            "REQUIRES_PRO",
        ),
        (
            CommandResult(
                returncode=2,
                stdout="",
                stderr="Invalid rule schema",
                duration_ms=10,
            ),
            "INCOMPATIBLE",
        ),
        (
            CommandResult(
                returncode=1,
                stdout="",
                stderr="Fatal runtime failure",
                duration_ms=10,
            ),
            "ERROR",
        ),
    ],
)
def test_classify_result(
    result: CommandResult,
    expected: str,
) -> None:
    assert classify_result(result) == expected


def test_classify_result_rejects_malformed_success_json() -> None:
    result = CommandResult(
        returncode=0,
        stdout="not-json",
        stderr="",
        duration_ms=10,
    )

    assert classify_result(result) == "ERROR"


def test_validate_rules_writes_compatible_report(tmp_path: Path) -> None:
    rules_dir = tmp_path / "upstream"
    rule_path = rules_dir / "java" / "test.yaml"
    rule_hash = write_rule(rule_path, "test-rule")
    inventory_path = tmp_path / "inventory.json"
    write_inventory(
        inventory_path,
        "java/test.yaml",
        rule_hash,
    )
    run_dir = tmp_path / "run"

    commands: list[list[str]] = []

    def fake_runner(
        command: list[str],
        cwd: Path | None = None,
    ) -> CommandResult:
        commands.append(command)
        if command[-1] == "--version":
            return CommandResult(
                returncode=0,
                stdout=SEMGREP_VERSION,
                stderr="",
                duration_ms=5,
            )
        return CommandResult(
            returncode=0,
            stdout='{"results": [], "errors": []}',
            stderr="",
            duration_ms=20,
        )

    result = validate_rules(
        rules_dir=rules_dir,
        inventory_path=inventory_path,
        run_dir=run_dir,
        semgrep_executable="semgrep",
        expected_version=SEMGREP_VERSION,
        git_reader=lambda _: clean_git_info(),
        command_runner=fake_runner,
    )

    assert result.status == "completed"
    assert result.compatible_count == 1
    assert result.incompatible_count == 0
    assert len(commands) == 2

    report = json.loads(
        (run_dir / "compatibility.json").read_text(encoding="utf-8")
    )
    assert report["semgrep_version"] == SEMGREP_VERSION
    assert report["upstream_commit"] == RULE_COMMIT
    assert report["summary"]["COMPATIBLE"] == 1
    assert report["files"][0]["status"] == "COMPATIBLE"
    assert report["files"][0]["rule_ids"] == ["test-rule"]
    assert report["files"][0]["source_sha256"] == rule_hash

    raw_stdout = run_dir / report["files"][0]["stdout_path"]
    raw_stderr = run_dir / report["files"][0]["stderr_path"]
    assert raw_stdout.is_file()
    assert raw_stderr.is_file()


def test_validate_rules_rejects_wrong_semgrep_version(tmp_path: Path) -> None:
    rules_dir = tmp_path / "upstream"
    rule_path = rules_dir / "java" / "test.yaml"
    rule_hash = write_rule(rule_path, "test-rule")
    inventory_path = tmp_path / "inventory.json"
    write_inventory(inventory_path, "java/test.yaml", rule_hash)

    def wrong_version_runner(
        command: list[str],
        cwd: Path | None = None,
    ) -> CommandResult:
        return CommandResult(
            returncode=0,
            stdout="1.180.0",
            stderr="",
            duration_ms=5,
        )

    with pytest.raises(CompatError, match="unexpected Semgrep version"):
        validate_rules(
            rules_dir=rules_dir,
            inventory_path=inventory_path,
            run_dir=tmp_path / "run",
            semgrep_executable="semgrep",
            expected_version=SEMGREP_VERSION,
            git_reader=lambda _: clean_git_info(),
            command_runner=wrong_version_runner,
        )


def test_validate_rules_rejects_changed_rule(tmp_path: Path) -> None:
    rules_dir = tmp_path / "upstream"
    rule_path = rules_dir / "java" / "test.yaml"
    write_rule(rule_path, "test-rule")
    inventory_path = tmp_path / "inventory.json"
    write_inventory(
        inventory_path,
        "java/test.yaml",
        "0" * 64,
    )

    with pytest.raises(CompatError, match="rule hash mismatch"):
        validate_rules(
            rules_dir=rules_dir,
            inventory_path=inventory_path,
            run_dir=tmp_path / "run",
            semgrep_executable="semgrep",
            expected_version=SEMGREP_VERSION,
            git_reader=lambda _: clean_git_info(),
        )


def test_validate_rules_rejects_existing_run_directory(
    tmp_path: Path,
) -> None:
    rules_dir = tmp_path / "upstream"
    inventory_path = tmp_path / "inventory.json"
    run_dir = tmp_path / "existing"
    rules_dir.mkdir()
    inventory_path.write_text("{}", encoding="utf-8")
    run_dir.mkdir()

    with pytest.raises(CompatError, match="run directory already exists"):
        validate_rules(
            rules_dir=rules_dir,
            inventory_path=inventory_path,
            run_dir=run_dir,
            semgrep_executable="semgrep",
            expected_version=SEMGREP_VERSION,
        )


def test_validate_rules_allows_same_rule_id_in_different_files(
    tmp_path: Path,
) -> None:
    rules_dir = tmp_path / "upstream"
    first_path = rules_dir / "java" / "aws" / "tainted-sql-string.yaml"
    second_path = rules_dir / "java" / "spring" / "tainted-sql-string.yaml"

    first_hash = write_rule(first_path, "tainted-sql-string")
    second_hash = write_rule(second_path, "tainted-sql-string")

    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "passed",
                "upstream_url": "https://github.com/semgrep/semgrep-rules.git",
                "upstream_commit": RULE_COMMIT,
                "working_tree_clean": True,
                "head_detached": True,
                "candidate_rule_count": 2,
                "rules": [
                    {
                        "id": "tainted-sql-string",
                        "source_path": "java/aws/tainted-sql-string.yaml",
                        "source_sha256": first_hash,
                        "cwes": [89],
                        "execution_compatibility": "not_validated",
                    },
                    {
                        "id": "tainted-sql-string",
                        "source_path": "java/spring/tainted-sql-string.yaml",
                        "source_sha256": second_hash,
                        "cwes": [89],
                        "execution_compatibility": "not_validated",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    commands: list[list[str]] = []

    def fake_runner(
        command: list[str],
        cwd: Path | None = None,
    ) -> CommandResult:
        commands.append(command)
        if command[-1] == "--version":
            return CommandResult(
                returncode=0,
                stdout=SEMGREP_VERSION,
                stderr="",
                duration_ms=5,
            )
        return CommandResult(
            returncode=0,
            stdout='{"results": [], "errors": []}',
            stderr="",
            duration_ms=10,
        )

    result = validate_rules(
        rules_dir=rules_dir,
        inventory_path=inventory_path,
        run_dir=tmp_path / "run",
        semgrep_executable="semgrep",
        expected_version=SEMGREP_VERSION,
        git_reader=lambda _: clean_git_info(),
        command_runner=fake_runner,
    )

    assert result.file_count == 2
    assert result.compatible_count == 2
    assert len(commands) == 3

    report = json.loads(
        (tmp_path / "run" / "compatibility.json").read_text(encoding="utf-8")
    )
    assert {item["source_path"] for item in report["files"]} == {
        "java/aws/tainted-sql-string.yaml",
        "java/spring/tainted-sql-string.yaml",
    }
    assert all(
        item["rule_ids"] == ["tainted-sql-string"] for item in report["files"]
    )
