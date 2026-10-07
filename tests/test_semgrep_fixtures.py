import json
from pathlib import Path

import pytest

from semgrep_compat import CommandResult
from semgrep_fixtures import FixtureError, annotation_status, parse_annotations, validate_fixtures
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


def write_fixture(
    path: Path,
    rule_id: str,
    include_negative: bool = True,
) -> str:
    negative = (
        f"    // ok: {rule_id}\n"
        "    safe();\n"
        if include_negative
        else ""
    )
    path.write_text(
        "class TestCase {\n"
        "  void run() {\n"
        f"    // ruleid: {rule_id}\n"
        "    danger();\n"
        f"{negative}"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    return sha256_file(path)


def write_inventory(
    path: Path,
    entries: list[dict[str, object]],
) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "passed",
                "upstream_url": (
                    "https://github.com/semgrep/semgrep-rules.git"
                ),
                "upstream_commit": RULE_COMMIT,
                "working_tree_clean": True,
                "head_detached": True,
                "candidate_rule_count": len(entries),
                "rules": entries,
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


def success_runner(
    command: list[str],
    cwd: Path | None = None,
) -> CommandResult:
    if command[-1] == "--version":
        return CommandResult(
            returncode=0,
            stdout=SEMGREP_VERSION,
            stderr="",
            duration_ms=5,
        )
    return CommandResult(
        returncode=0,
        stdout="1/1: All tests passed\n",
        stderr="",
        duration_ms=20,
    )


def test_parse_annotations_counts_active_and_todo_cases(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "test.java"
    fixture.write_text(
        """class Test {
  void run() {
    // ruleid: first-rule, second-rule
    danger();
    // ok: first-rule
    safe();
    // todoruleid: first-rule
    missed();
    // todook: second-rule
    knownFalsePositive();
  }
}
""",
        encoding="utf-8",
    )

    counts = parse_annotations(
        fixture,
        {"first-rule", "second-rule"},
    )

    assert counts.positive == 2
    assert counts.negative == 1
    assert counts.todo_positive == 1
    assert counts.todo_negative == 1


@pytest.mark.parametrize(
    "positive, negative, expected",
    [
        (1, 1, "BOTH"),
        (1, 0, "POSITIVE_ONLY"),
        (0, 1, "NEGATIVE_ONLY"),
        (0, 0, "NONE"),
    ],
)
def test_annotation_status(
    positive: int,
    negative: int,
    expected: str,
) -> None:
    assert annotation_status(positive, negative) == expected


def test_validate_fixtures_writes_report_and_raw_evidence(
    tmp_path: Path,
) -> None:
    rules_dir = tmp_path / "upstream"

    complete_rule = rules_dir / "java" / "complete.yaml"
    positive_rule = rules_dir / "java" / "positive-only.yaml"

    complete_hash = write_rule(complete_rule, "complete-rule")
    positive_hash = write_rule(positive_rule, "positive-only-rule")

    write_fixture(
        complete_rule.with_suffix(".java"),
        "complete-rule",
        include_negative=True,
    )
    write_fixture(
        positive_rule.with_suffix(".java"),
        "positive-only-rule",
        include_negative=False,
    )

    inventory_path = tmp_path / "inventory.json"
    write_inventory(
        inventory_path,
        [
            {
                "id": "complete-rule",
                "source_path": "java/complete.yaml",
                "source_sha256": complete_hash,
                "cwes": [78],
            },
            {
                "id": "positive-only-rule",
                "source_path": "java/positive-only.yaml",
                "source_sha256": positive_hash,
                "cwes": [78],
            },
        ],
    )

    run_dir = tmp_path / "run"
    result = validate_fixtures(
        rules_dir=rules_dir,
        inventory_path=inventory_path,
        run_dir=run_dir,
        semgrep_executable="semgrep",
        expected_version=SEMGREP_VERSION,
        git_reader=lambda _: clean_git_info(),
        command_runner=success_runner,
    )

    assert result.status == "completed"
    assert result.file_count == 2
    assert result.pass_count == 2
    assert result.fail_count == 0
    assert result.error_count == 0
    assert result.complete_annotation_count == 1
    assert result.incomplete_annotation_count == 1

    report = json.loads(
        (run_dir / "fixtures.json").read_text(encoding="utf-8")
    )
    assert report["summary"]["PASS"] == 2
    assert report["annotation_summary"]["BOTH"] == 1
    assert report["annotation_summary"]["POSITIVE_ONLY"] == 1

    statuses = {
        item["source_path"]: item["annotation_status"]
        for item in report["files"]
    }
    assert statuses == {
        "java/complete.yaml": "BOTH",
        "java/positive-only.yaml": "POSITIVE_ONLY",
    }

    for item in report["files"]:
        assert (run_dir / item["stdout_path"]).is_file()
        assert (run_dir / item["stderr_path"]).is_file()


def test_validate_fixtures_rejects_missing_fixture(
    tmp_path: Path,
) -> None:
    rules_dir = tmp_path / "upstream"
    rule_path = rules_dir / "java" / "missing.yaml"
    rule_hash = write_rule(rule_path, "missing-fixture")

    inventory_path = tmp_path / "inventory.json"
    write_inventory(
        inventory_path,
        [
            {
                "id": "missing-fixture",
                "source_path": "java/missing.yaml",
                "source_sha256": rule_hash,
                "cwes": [78],
            }
        ],
    )

    with pytest.raises(FixtureError, match="fixture not found"):
        validate_fixtures(
            rules_dir=rules_dir,
            inventory_path=inventory_path,
            run_dir=tmp_path / "run",
            semgrep_executable="semgrep",
            expected_version=SEMGREP_VERSION,
            git_reader=lambda _: clean_git_info(),
            command_runner=success_runner,
        )


def test_validate_fixtures_rejects_existing_run_directory(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    with pytest.raises(
        FixtureError,
        match="run directory already exists",
    ):
        validate_fixtures(
            rules_dir=tmp_path / "rules",
            inventory_path=tmp_path / "inventory.json",
            run_dir=run_dir,
            semgrep_executable="semgrep",
            expected_version=SEMGREP_VERSION,
        )


def test_validate_fixtures_records_failed_semgrep_test(
    tmp_path: Path,
) -> None:
    rules_dir = tmp_path / "upstream"
    rule_path = rules_dir / "java" / "failed.yaml"
    rule_hash = write_rule(rule_path, "failed-rule")
    write_fixture(
        rule_path.with_suffix(".java"),
        "failed-rule",
    )

    inventory_path = tmp_path / "inventory.json"
    write_inventory(
        inventory_path,
        [
            {
                "id": "failed-rule",
                "source_path": "java/failed.yaml",
                "source_sha256": rule_hash,
                "cwes": [78],
            }
        ],
    )

    def failed_runner(
        command: list[str],
        cwd: Path | None = None,
    ) -> CommandResult:
        if command[-1] == "--version":
            return success_runner(command, cwd)
        return CommandResult(
            returncode=1,
            stdout="1 unit test failed",
            stderr="",
            duration_ms=20,
        )

    result = validate_fixtures(
        rules_dir=rules_dir,
        inventory_path=inventory_path,
        run_dir=tmp_path / "run",
        semgrep_executable="semgrep",
        expected_version=SEMGREP_VERSION,
        git_reader=lambda _: clean_git_info(),
        command_runner=failed_runner,
    )

    assert result.fail_count == 1
    assert result.error_count == 0
