from pathlib import Path

import main as cli
from owasp_audit import AuditError, AuditResult


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
