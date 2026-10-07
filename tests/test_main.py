from pathlib import Path

import main as cli
from owasp_audit import AuditError, AuditResult
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
