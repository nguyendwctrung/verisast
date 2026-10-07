import json
from pathlib import Path

import pytest

from semgrep_compat import CommandResult
from semgrep_controls import ControlError, validate_controls
from semgrep_rules import RuleGitInfo, sha256_file

RULE_COMMIT = "a" * 40
SEMGREP_VERSION = "1.179.0"


def write_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    project_root = tmp_path / "project"
    rules_dir = tmp_path / "upstream"
    rule_path = rules_dir / "java" / "test.yaml"
    fixture_path = project_root / "rules" / "fixtures" / "test.java"
    rule_path.parent.mkdir(parents=True)
    fixture_path.parent.mkdir(parents=True)
    rule_path.write_text("rules: []\n", encoding="utf-8")
    fixture_path.write_text("class Test {}\n", encoding="utf-8")

    manifest_path = project_root / "rules" / "fixtures" / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "control_type": "independent_negative",
                "semgrep_version": SEMGREP_VERSION,
                "upstream_commit": RULE_COMMIT,
                "controls": [
                    {
                        "control_id": "test-negative",
                        "rule_id": "test-rule",
                        "cwes": [78],
                        "rule_path": "java/test.yaml",
                        "rule_sha256": sha256_file(rule_path),
                        "fixture_path": "rules/fixtures/test.java",
                        "fixture_sha256": sha256_file(fixture_path),
                        "expected_findings": 0,
                        "rationale": "Safe near miss.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return project_root, rules_dir, manifest_path


def clean_git_info() -> RuleGitInfo:
    return RuleGitInfo(
        remote_url="https://github.com/semgrep/semgrep-rules.git",
        commit=RULE_COMMIT,
        clean=True,
        detached=True,
    )


def runner_with_findings(finding_count: int):
    def runner(
        command: list[str],
        cwd: Path | None = None,
    ) -> CommandResult:
        if command[-1] == "--version":
            return CommandResult(0, SEMGREP_VERSION, "", 5)
        results = [
            {
                "check_id": "test-rule",
                "path": "test.java",
                "start": {"line": index + 1},
            }
            for index in range(finding_count)
        ]
        return CommandResult(
            0,
            json.dumps({"results": results, "errors": []}),
            "",
            20,
        )

    return runner


def test_validate_controls_writes_pass_report(tmp_path: Path) -> None:
    project_root, rules_dir, manifest_path = write_inputs(tmp_path)
    run_dir = project_root / "artifacts" / "run"

    result = validate_controls(
        project_root=project_root,
        rules_dir=rules_dir,
        manifest_path=manifest_path,
        run_dir=run_dir,
        semgrep_executable="semgrep",
        expected_version=SEMGREP_VERSION,
        git_reader=lambda _: clean_git_info(),
        command_runner=runner_with_findings(0),
    )

    assert result.pass_count == 1
    assert result.false_positive_count == 0
    assert result.error_count == 0
    report = json.loads((run_dir / "controls.json").read_text(encoding="utf-8"))
    assert report["summary"] == {"ERROR": 0, "FALSE_POSITIVE": 0, "PASS": 1}
    assert report["controls"][0]["status"] == "PASS"
    assert (run_dir / report["controls"][0]["stdout_path"]).is_file()


def test_validate_controls_records_false_positive(tmp_path: Path) -> None:
    project_root, rules_dir, manifest_path = write_inputs(tmp_path)

    result = validate_controls(
        project_root=project_root,
        rules_dir=rules_dir,
        manifest_path=manifest_path,
        run_dir=project_root / "artifacts" / "run",
        semgrep_executable="semgrep",
        expected_version=SEMGREP_VERSION,
        git_reader=lambda _: clean_git_info(),
        command_runner=runner_with_findings(1),
    )

    assert result.false_positive_count == 1
    assert result.pass_count == 0


def test_validate_controls_rejects_fixture_hash_mismatch(tmp_path: Path) -> None:
    project_root, rules_dir, manifest_path = write_inputs(tmp_path)
    fixture = project_root / "rules" / "fixtures" / "test.java"
    fixture.write_text("class Changed {}\n", encoding="utf-8")

    with pytest.raises(ControlError, match="fixture hash mismatch"):
        validate_controls(
            project_root=project_root,
            rules_dir=rules_dir,
            manifest_path=manifest_path,
            run_dir=project_root / "artifacts" / "run",
            semgrep_executable="semgrep",
            expected_version=SEMGREP_VERSION,
            git_reader=lambda _: clean_git_info(),
            command_runner=runner_with_findings(0),
        )


def test_validate_controls_rejects_existing_run_directory(tmp_path: Path) -> None:
    project_root, rules_dir, manifest_path = write_inputs(tmp_path)
    run_dir = project_root / "artifacts" / "run"
    run_dir.mkdir(parents=True)

    with pytest.raises(ControlError, match="run directory already exists"):
        validate_controls(
            project_root=project_root,
            rules_dir=rules_dir,
            manifest_path=manifest_path,
            run_dir=run_dir,
            semgrep_executable="semgrep",
            expected_version=SEMGREP_VERSION,
        )
