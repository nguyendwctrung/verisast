from pathlib import Path

import main as cli
from baseline import BaselineError, BaselineResult
from owasp_audit import AuditError, AuditResult
from owasp_cohort import CohortResult
from semgrep_checkpoint import CheckpointResult
from semgrep_compat import CompatError, CompatResult
from semgrep_controls import ControlError, ControlResult
from semgrep_fixtures import FixtureError, FixtureResult
from semgrep_review import ReviewError, ReviewResult
from semgrep_rules import InventoryError, InventoryResult
from semgrep_ruleset import RulesetResult
from source_context import ContextResult


def test_main_runs_owasp_audit(monkeypatch, capsys, tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"

    def fake_audit_dataset(**kwargs) -> AuditResult:
        assert kwargs["dataset_dir"] == Path("dataset")
        assert kwargs["manifest_path"] == manifest_path
        assert kwargs["expected_commit"] == "a" * 40
        return AuditResult(
            audit_status="passed",
            dataset_id="owasp-benchmark-java-v1.2",
            frozen_commit="a" * 40,
            testcase_count=2740,
            source_file_count=2740,
            manifest_path=str(manifest_path),
        )

    monkeypatch.setattr(cli, "audit_dataset", fake_audit_dataset)

    exit_code = cli.main(
        [
            "dataset",
            "audit-owasp",
            "--dataset",
            "dataset",
            "--manifest",
            str(manifest_path),
            "--expected-commit",
            "a" * 40,
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "AUDIT_STATUS=passed" in output
    assert "TESTCASES=2740" in output


def test_main_reports_audit_failure(monkeypatch, capsys, tmp_path: Path) -> None:
    def fail_audit(**kwargs) -> AuditResult:
        raise AuditError("dataset working tree is not clean")

    monkeypatch.setattr(cli, "audit_dataset", fail_audit)

    exit_code = cli.main(
        [
            "dataset",
            "audit-owasp",
            "--dataset",
            "dataset",
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--expected-commit",
            "a" * 40,
        ]
    )

    assert exit_code == 1
    error = capsys.readouterr().err
    assert "AUDIT_STATUS=failed" in error
    assert "dataset working tree is not clean" in error


def test_main_runs_semgrep_rule_inventory(monkeypatch, capsys, tmp_path: Path) -> None:
    output_path = tmp_path / "inventory.json"

    def fake_inventory_rules(**kwargs) -> InventoryResult:
        assert kwargs["rules_dir"] == Path("rules")
        assert kwargs["output_path"] == output_path
        return InventoryResult(
            status="passed",
            upstream_commit="b" * 40,
            scanned_rule_count=12,
            candidate_rule_count=4,
            output_path=str(output_path),
        )

    monkeypatch.setattr(cli, "inventory_rules", fake_inventory_rules)

    exit_code = cli.main(
        [
            "rules",
            "inventory-semgrep",
            "--rules",
            "rules",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "INVENTORY_STATUS=passed" in output
    assert "CANDIDATE_RULES=4" in output


def test_main_reports_rule_inventory_failure(monkeypatch, capsys) -> None:
    def fail_inventory(**kwargs) -> InventoryResult:
        raise InventoryError("rule working tree is not clean")

    monkeypatch.setattr(cli, "inventory_rules", fail_inventory)

    exit_code = cli.main(
        [
            "rules",
            "inventory-semgrep",
            "--rules",
            "rules",
            "--output",
            "inventory.json",
        ]
    )

    assert exit_code == 1
    error = capsys.readouterr().err
    assert "INVENTORY_STATUS=failed" in error
    assert "rule working tree is not clean" in error


def test_main_runs_semgrep_compatibility(
    monkeypatch,
    capsys,
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"

    def fake_validate_rules(**kwargs) -> CompatResult:
        assert kwargs["rules_dir"] == Path("rules")
        assert kwargs["inventory_path"] == Path("inventory.json")
        assert kwargs["run_dir"] == run_dir
        assert kwargs["semgrep_executable"] == "semgrep"
        assert kwargs["expected_version"] == "1.179.0"
        return CompatResult(
            status="completed",
            semgrep_version="1.179.0",
            upstream_commit="a" * 40,
            file_count=10,
            compatible_count=8,
            incompatible_count=1,
            requires_pro_count=1,
            error_count=0,
            report_path=str(run_dir / "compatibility.json"),
        )

    monkeypatch.setattr(cli, "validate_rules", fake_validate_rules)

    exit_code = cli.main(
        [
            "rules",
            "validate-semgrep",
            "--rules",
            "rules",
            "--inventory",
            "inventory.json",
            "--run-dir",
            str(run_dir),
            "--semgrep",
            "semgrep",
            "--expected-version",
            "1.179.0",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "COMPAT_STATUS=completed" in output
    assert "COMPATIBLE=8" in output
    assert "REQUIRES_PRO=1" in output


def test_main_reports_semgrep_compatibility_failure(
    monkeypatch,
    capsys,
) -> None:
    def fail_validation(**kwargs) -> CompatResult:
        raise CompatError("unexpected Semgrep version")

    monkeypatch.setattr(cli, "validate_rules", fail_validation)

    exit_code = cli.main(
        [
            "rules",
            "validate-semgrep",
            "--rules",
            "rules",
            "--inventory",
            "inventory.json",
            "--run-dir",
            "run",
            "--semgrep",
            "semgrep",
            "--expected-version",
            "1.179.0",
        ]
    )

    assert exit_code == 1
    error = capsys.readouterr().err
    assert "COMPAT_STATUS=failed" in error
    assert "unexpected Semgrep version" in error


def test_main_runs_semgrep_fixture_validation(
    monkeypatch,
    capsys,
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"

    def fake_validate_fixtures(**kwargs) -> FixtureResult:
        assert kwargs["rules_dir"] == Path("rules")
        assert kwargs["inventory_path"] == Path(
            "inventory.json"
        )
        assert kwargs["run_dir"] == run_dir
        assert kwargs["semgrep_executable"] == "semgrep"
        assert kwargs["expected_version"] == "1.179.0"
        return FixtureResult(
            status="completed",
            semgrep_version="1.179.0",
            upstream_commit="a" * 40,
            file_count=48,
            pass_count=48,
            fail_count=0,
            error_count=0,
            complete_annotation_count=43,
            incomplete_annotation_count=5,
            report_path=str(run_dir / "fixtures.json"),
        )

    monkeypatch.setattr(
        cli,
        "validate_fixtures",
        fake_validate_fixtures,
    )

    exit_code = cli.main(
        [
            "rules",
            "validate-fixtures",
            "--rules",
            "rules",
            "--inventory",
            "inventory.json",
            "--run-dir",
            str(run_dir),
            "--semgrep",
            "semgrep",
            "--expected-version",
            "1.179.0",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "FIXTURE_STATUS=completed" in output
    assert "PASSED=48" in output
    assert "INCOMPLETE_ANNOTATIONS=5" in output


def test_main_reports_semgrep_fixture_failure(
    monkeypatch,
    capsys,
) -> None:
    def fail_validation(**kwargs) -> FixtureResult:
        raise FixtureError("fixture not found")

    monkeypatch.setattr(
        cli,
        "validate_fixtures",
        fail_validation,
    )

    exit_code = cli.main(
        [
            "rules",
            "validate-fixtures",
            "--rules",
            "rules",
            "--inventory",
            "inventory.json",
            "--run-dir",
            "run",
            "--semgrep",
            "semgrep",
            "--expected-version",
            "1.179.0",
        ]
    )

    assert exit_code == 1
    error = capsys.readouterr().err
    assert "FIXTURE_STATUS=failed" in error
    assert "fixture not found" in error


def test_main_runs_semgrep_control_validation(
    monkeypatch,
    capsys,
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"

    def fake_validate_controls(**kwargs) -> ControlResult:
        assert kwargs["project_root"] == Path(".")
        assert kwargs["rules_dir"] == Path("rules")
        assert kwargs["manifest_path"] == Path("manifest.json")
        assert kwargs["run_dir"] == run_dir
        assert kwargs["semgrep_executable"] == "semgrep"
        assert kwargs["expected_version"] == "1.179.0"
        return ControlResult(
            status="completed",
            semgrep_version="1.179.0",
            upstream_commit="a" * 40,
            control_count=5,
            pass_count=5,
            false_positive_count=0,
            error_count=0,
            report_path=str(run_dir / "controls.json"),
        )

    monkeypatch.setattr(cli, "validate_controls", fake_validate_controls)

    exit_code = cli.main(
        [
            "rules",
            "validate-controls",
            "--project-root",
            ".",
            "--rules",
            "rules",
            "--manifest",
            "manifest.json",
            "--run-dir",
            str(run_dir),
            "--semgrep",
            "semgrep",
            "--expected-version",
            "1.179.0",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "CONTROL_STATUS=completed" in output
    assert "PASSED=5" in output
    assert "FALSE_POSITIVES=0" in output


def test_main_fails_when_control_finds_false_positive(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "validate_controls",
        lambda **_: ControlResult(
            status="completed",
            semgrep_version="1.179.0",
            upstream_commit="a" * 40,
            control_count=1,
            pass_count=0,
            false_positive_count=1,
            error_count=0,
            report_path="controls.json",
        ),
    )

    exit_code = cli.main(
        [
            "rules",
            "validate-controls",
            "--project-root",
            ".",
            "--rules",
            "rules",
            "--manifest",
            "manifest.json",
            "--run-dir",
            "run",
            "--semgrep",
            "semgrep",
            "--expected-version",
            "1.179.0",
        ]
    )

    assert exit_code == 1


def test_main_reports_semgrep_control_failure(monkeypatch, capsys) -> None:
    def fail_validation(**kwargs) -> ControlResult:
        raise ControlError("fixture hash mismatch")

    monkeypatch.setattr(cli, "validate_controls", fail_validation)

    exit_code = cli.main(
        [
            "rules",
            "validate-controls",
            "--project-root",
            ".",
            "--rules",
            "rules",
            "--manifest",
            "manifest.json",
            "--run-dir",
            "run",
            "--semgrep",
            "semgrep",
            "--expected-version",
            "1.179.0",
        ]
    )

    assert exit_code == 1
    error = capsys.readouterr().err
    assert "CONTROL_STATUS=failed" in error
    assert "fixture hash mismatch" in error


def review_result(path: str = "review.json") -> ReviewResult:
    return ReviewResult(
        status="completed",
        upstream_commit="a" * 40,
        review_count=48,
        include_count=0,
        exclude_count=0,
        needs_evidence_count=48,
        decision_counts={
            "EXCLUDE": 0,
            "INCLUDE_DEVELOPMENT": 0,
            "NEEDS_EVIDENCE": 48,
        },
        include_counts_by_cwe={78: 0, 89: 0},
        review_path=path,
    )


def test_main_initializes_semgrep_review(monkeypatch, capsys) -> None:
    def fake_init_review(inventory_path, output_path) -> ReviewResult:
        assert inventory_path == Path("inventory.json")
        assert output_path == Path("review.json")
        return review_result()

    monkeypatch.setattr(cli, "init_review", fake_init_review)

    exit_code = cli.main(
        [
            "rules",
            "init-review",
            "--inventory",
            "inventory.json",
            "--output",
            "review.json",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "REVIEW_STATUS=completed" in output
    assert "NEEDS_EVIDENCE=48" in output


def test_main_validates_semgrep_review(monkeypatch, capsys) -> None:
    def fake_validate_review(inventory_path, review_path) -> ReviewResult:
        assert inventory_path == Path("inventory.json")
        assert review_path == Path("review.json")
        return review_result()

    monkeypatch.setattr(cli, "validate_review", fake_validate_review)

    exit_code = cli.main(
        [
            "rules",
            "validate-review",
            "--inventory",
            "inventory.json",
            "--review",
            "review.json",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "RULES=48" in output
    assert "INCLUDE_DEVELOPMENT=0" in output


def test_main_reports_semgrep_review_failure(monkeypatch, capsys) -> None:
    def fail_review(inventory_path, review_path) -> ReviewResult:
        raise ReviewError("review identities do not match")

    monkeypatch.setattr(cli, "validate_review", fail_review)

    exit_code = cli.main(
        [
            "rules",
            "validate-review",
            "--inventory",
            "inventory.json",
            "--review",
            "review.json",
        ]
    )

    assert exit_code == 1
    error = capsys.readouterr().err
    assert "REVIEW_STATUS=failed" in error
    assert "review identities do not match" in error


def test_main_validates_semgrep_checkpoint(monkeypatch, capsys) -> None:
    def fake_validate_checkpoint(**kwargs) -> CheckpointResult:
        assert kwargs["cwe"] == 330
        assert kwargs["dataset"] == Path("dataset")
        return CheckpointResult(330, 493, 218, 275, 1, {"covered": 218})

    monkeypatch.setattr(cli, "validate_checkpoint", fake_validate_checkpoint)

    exit_code = cli.main(
        [
            "rules",
            "validate-checkpoint",
            "--cwe",
            "330",
            "--dataset",
            "dataset",
            "--review",
            "review.json",
            "--fixtures",
            "fixtures.json",
            "--compatibility",
            "compatibility.json",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "CHECKPOINT_CWE330=PASS" in output
    assert "CWE330_TOTAL=493" in output
    assert "COVERED=218" in output


def test_main_builds_source_context(monkeypatch, capsys) -> None:
    def fake_build_contexts(dataset_dir, findings_path, output_path, **kwargs):
        assert dataset_dir == Path("dataset")
        assert findings_path == Path("findings.jsonl")
        assert kwargs == {"before": 10, "after": 12, "max_lines": 50}
        return ContextResult(7, output_path, "a" * 64)

    monkeypatch.setattr(cli, "build_contexts", fake_build_contexts)
    exit_code = cli.main(
        [
            "context",
            "build",
            "--dataset",
            "dataset",
            "--findings",
            "findings.jsonl",
            "--output",
            "contexts.jsonl",
            "--before",
            "10",
            "--after",
            "12",
            "--max-lines",
            "50",
        ]
    )
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "CONTEXT_STATUS=completed" in output
    assert "CONTEXTS=7" in output


def test_main_builds_ruleset_and_cohort(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "build_ruleset", lambda **_: RulesetResult("development", "development", False, 11, 25, "ruleset.json"))
    monkeypatch.setattr(cli, "build_cohort", lambda **_: CohortResult("development", "development", False, 1210, [78, 79, 89], "cohort.json"))
    assert cli.main(["rules", "build-ruleset", "--rules", "rules", "--inventory", "inventory.json", "--review", "review.json", "--output", "ruleset.json", "--purpose", "development"]) == 0
    assert cli.main(["dataset", "build-owasp-cohort", "--dataset", "dataset", "--dataset-manifest", "manifest.json", "--ruleset", "ruleset.json", "--output", "cohort.json", "--purpose", "development"]) == 0
    output = capsys.readouterr().out
    assert "RULESET_RULES=11" in output
    assert "COHORT_UNITS=1210" in output


def baseline_result() -> BaselineResult:
    return BaselineResult("completed", "run-1", "development", False, "1.179.0", 11, 10, 8, 5, 3, 2, 4, 1, 0.6, 0.75, 2 / 3, 1 / 3, "manifest.json")


def test_main_runs_and_validates_baseline(monkeypatch, capsys) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(cli, "run_owasp_baseline", lambda **kwargs: calls.append(kwargs) or baseline_result())
    monkeypatch.setattr(cli, "validate_baseline_run", lambda **kwargs: calls.append(kwargs) or baseline_result())
    common = ["--dataset", "dataset", "--dataset-manifest", "dataset.json", "--rules", "rules", "--project-root", "project"]
    assert cli.main(["baseline", "run-owasp", "--run-id", "run-1", "--purpose", "development", *common, "--ruleset", "ruleset.json", "--cohort", "cohort.json", "--run-dir", "run", "--semgrep", "semgrep", "--expected-version", "1.179.0"]) == 0
    assert cli.main(["baseline", "validate-run", "--run-dir", "run", *common]) == 0
    output = capsys.readouterr().out
    assert "BASELINE_STATUS=completed" in output
    assert "REPORTABLE=false" in output
    assert "TP=3" in output
    assert calls[0]["project_root"] == Path("project")
    assert calls[1]["project_root"] == Path("project")


def test_main_reports_baseline_failure(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "validate_baseline_run", lambda **_: (_ for _ in ()).throw(BaselineError("artifact mismatch")))
    exit_code = cli.main(["baseline", "validate-run", "--run-dir", "run", "--dataset", "dataset", "--dataset-manifest", "dataset.json", "--rules", "rules"])
    assert exit_code == 1
    assert "BASELINE_STATUS=failed" in capsys.readouterr().err
