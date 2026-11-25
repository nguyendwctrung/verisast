import json
from pathlib import Path

from run_experiment import _contract_issues, _feasibility_issues, _gate_status, _runtime_issues, main


def test_preflight_cli_reports_missing_inputs_without_a_run(tmp_path: Path, capsys) -> None:
    manifest = tmp_path / "partial.json"
    manifest.write_text(json.dumps({"schema_version": 1, "mode": "partial",
                                    "owasp": {"expected_count": 2, "selected_ids": {"22": ["a", "b"]}}}), encoding="utf-8")
    output = tmp_path / "results"
    status = main(["preflight", "--manifest", str(manifest), "--source-root", str(tmp_path),
                   "--output-dir", str(output), "--result-name", "sample"])
    assert status == 2
    assert not output.exists()
    assert "OWASP" in capsys.readouterr().out


def test_mock_cli_uses_named_output(tmp_path: Path, capsys) -> None:
    status = main(["mock", "--output-dir", str(tmp_path), "--result-name", "fixture"])
    assert status == 0
    assert "mock_completed" in capsys.readouterr().out


def test_run_cli_stops_at_preflight_without_allocating_result(tmp_path: Path, capsys) -> None:
    manifest = tmp_path / "full.json"
    manifest.write_text(json.dumps({"schema_version": 1, "mode": "full",
                                    "owasp": {"expected_count": 2740}}), encoding="utf-8")
    output = tmp_path / "results"
    status = main(["run", "--manifest", str(manifest), "--source-root", str(tmp_path),
                   "--output-dir", str(output), "--result-name", "no-data"])
    assert status == 2
    assert not output.exists()
    assert "issues" in capsys.readouterr().out


def test_contract_check_rejects_wrong_cwe(tmp_path: Path) -> None:
    contract = tmp_path / "retrieval.json"
    contract.write_text(json.dumps({"contract_id": "variant-c-retrieval-bundle-v1",
                                    "metadata_filter": {"cwe_id": 22},
                                    "admitted_retrieval": {"chunks_path": "missing"}}), encoding="utf-8")
    issues = _contract_issues({"78": contract}, {"78"})
    assert any("CWE-78" in item for item in issues)


def test_gate_status_requires_verifiable_evidence(tmp_path: Path) -> None:
    gate = tmp_path / "gate.json"
    gate.write_text(json.dumps({"OD-002": {"status": "accepted"},
                                "OD-006": {"status": "accepted"}}), encoding="utf-8")
    assert _gate_status(gate) == {"OD-002": False, "OD-006": False}


def test_runtime_check_rejects_model_digest_mismatch(tmp_path: Path, monkeypatch) -> None:
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps({"codeql": "codeql", "codeql_version": "2.27.0"}), encoding="utf-8")
    inference = tmp_path / "inference.json"
    inference.write_text(json.dumps({"provider": "ollama", "endpoint": "http://local",
                                     "model": "model", "model_digest": "expected",
                                     "timeout_seconds": 1}), encoding="utf-8")
    monkeypatch.setattr("run_experiment._codeql_version", lambda _: "2.27.0")
    monkeypatch.setattr("run_experiment.metadata", lambda *args: {"model_digest": "different"})
    assert any("digest" in issue for issue in _runtime_issues(scan, inference))


def test_feasibility_requires_hashed_scan_evidence(tmp_path: Path) -> None:
    manifest = tmp_path / "feasibility.json"
    manifest.write_text(json.dumps({"sources": [{"dataset": "owasp",
        "slug": "owasp-benchmark-java-v1.2", "role": "source", "status": "complete",
        "target_file_extracted": True}]}), encoding="utf-8")
    issues = _feasibility_issues(manifest, {"mode": "partial", "owasp": {"commit": "abc"}},
                                "owasp", tmp_path)
    assert any("evidence" in issue for issue in issues)
