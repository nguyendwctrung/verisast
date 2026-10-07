from pathlib import Path

import main as cli
from owasp_audit import AuditError, AuditResult
from semgrep_compat import CompatError, CompatResult
from semgrep_controls import ControlError, ControlResult
from semgrep_fixtures import FixtureError, FixtureResult
from semgrep_rules import InventoryError, InventoryResult


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
