import json
from pathlib import Path

import pytest

from experiment_execution import ExecutionError, execute, selected_sources


def test_selected_sources_keep_both_cwe_roles(tmp_path: Path) -> None:
    manifest = {"mode": "partial", "cwe_bench": {"selected_slugs": ["project_CVE-1_1"]}}
    sources = selected_sources(manifest, "cwe-bench", tmp_path)
    assert [(item["slug"], item["role"]) for item in sources] == [
        ("project_CVE-1_1", "buggy"), ("project_CVE-1_1", "fixed"),
    ]


def test_selected_sources_require_complete_manifest(tmp_path: Path) -> None:
    data = tmp_path / "cwe-bench-java-120" / "data"
    data.mkdir(parents=True)
    (data / "project_info.csv").write_text("project_slug\n", encoding="utf-8")
    with pytest.raises(ExecutionError, match="project slugs"):
        selected_sources({"mode": "full", "cwe_bench": {}}, "cwe-bench", tmp_path)


def test_mocked_full_pipeline_runs_a_b_c_repetitions(tmp_path: Path, monkeypatch) -> None:
    source_root = tmp_path / "datasets"
    source = source_root / "owasp-benchmark-java-v1.2"
    source.mkdir(parents=True)
    (source / "expectedresults-1.2.csv").write_text(
        "BenchmarkTest00001,x,true,22\nBenchmarkTest00002,x,false,22\n", encoding="utf-8")
    manifest = {"mode": "partial", "owasp": {"commit": "fixture-revision",
        "selected_ids": {"22": ["BenchmarkTest00001", "BenchmarkTest00002"]}}}
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    manifest_path = inputs / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    scan_config = inputs / "scan.json"
    scan_config.write_text(json.dumps({"codeql": "mock", "suite": "mock-suite",
                                      "query_pack": "mock-pack"}), encoding="utf-8")
    inference = inputs / "inference.json"
    (inputs / "schema.json").write_text("{}", encoding="utf-8")
    (inputs / "neutral.json").write_text(json.dumps({"contract_id": "neutral-triage-interface"}), encoding="utf-8")
    inference.write_text(json.dumps({"interface": "neutral-triage", "schema": "schema.json",
                                     "neutral_contract": "neutral.json", "model": "mock",
                                     "model_digest": "mock-digest"}), encoding="utf-8")
    prompt = inputs / "prompt.txt"
    prompt.write_text("fixture", encoding="utf-8")
    contract = inputs / "cwe-22.json"
    contract.write_text(json.dumps({"admitted_retrieval": {"corpus_id": "fixture-corpus"}}), encoding="utf-8")

    def mock_scan(source_path, output, codeql, suite):
        (output / "raw").mkdir(parents=True)
        (output / "raw" / "results.sarif").write_text("{}", encoding="utf-8")
        return {"duration_seconds": 0.1}

    def mock_normalize(*args):
        return [{"id": "candidate-1", "test_id": "BenchmarkTest00001",
                 "path": "BenchmarkTest00001.java", "cwes": [22]}]

    def mock_triage(findings, contexts, prompt_path, config, output, variant, **kwargs):
        (output / "raw").mkdir(parents=True)
        (output / "verdicts.jsonl").write_text(json.dumps({"candidate_id": "candidate-1",
            "effective_verdict": "UNCERTAIN", "error": "fixture_only"}) + "\n", encoding="utf-8")
        (output / "raw" / "candidate-1.json").write_text(json.dumps({
            "response": "{}", "prompt_eval_count": 10, "eval_count": 5,
            "total_duration": 1000000000}), encoding="utf-8")
        if variant == "C":
            (output / "retrieval-records.jsonl").write_text(json.dumps({
                "candidate_id": "candidate-1", "bundle": {"knowledge_items": [{
                    "knowledge_id": "fixture-chunk", "source_id": "fixture-source"}]}
            }) + "\n", encoding="utf-8")
        return {"status": "mock_completed", "variant": variant}

    monkeypatch.setattr("experiment_execution.scan_source", mock_scan)
    monkeypatch.setattr("experiment_execution.normalize", mock_normalize)
    monkeypatch.setattr("experiment_execution.build_context", lambda *args: [
        {"candidate_id": "candidate-1", "lines": [], "guards": []}])
    monkeypatch.setattr("experiment_execution.run_paired", mock_triage)

    result = execute(manifest, manifest_path, "owasp", source_root, tmp_path / "results",
                     "fixture", scan_config, inference, prompt, {"22": contract}, None)
    run = Path(result["run_directory"])
    assert result["status"] == "completed"
    for repetition in (1, 2):
        assert (run / "sources" / "owasp" / "owasp-benchmark-java-v1.2" / "source" /
                f"A-{repetition}" / "normalized" / "findings.jsonl").is_file()
    for variant in ("B", "C"):
        for repetition in (1, 2, 3):
            assert (run / "sources" / "owasp" / "owasp-benchmark-java-v1.2" / "source" /
                    f"{variant}-{repetition}" / "verdicts.jsonl").is_file()
    assert (run / "sources" / "owasp" / "owasp-benchmark-java-v1.2" / "source" /
            "C-1" / "retrieval-records.jsonl").is_file()
    assert (run / "reports" / "owasp" / "runs.csv").is_file()


def test_mocked_cwe_pair_reports_both_revisions(tmp_path: Path, monkeypatch) -> None:
    source_root = tmp_path / "datasets"
    for role in ("buggy", "fixed"):
        (source_root / "cwe-bench-java" / "sample" / role).mkdir(parents=True)
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    manifest = {"mode": "partial", "cwe_bench": {"selected_slugs": ["sample"]}}
    manifest_path = inputs / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    scan_config = inputs / "scan.json"
    scan_config.write_text(json.dumps({"codeql": "mock", "suite": "mock-suite",
                                      "query_pack": "mock-pack"}), encoding="utf-8")
    (inputs / "schema.json").write_text("{}", encoding="utf-8")
    (inputs / "neutral.json").write_text(json.dumps({"contract_id": "neutral-triage-interface"}), encoding="utf-8")
    inference = inputs / "inference.json"
    inference.write_text(json.dumps({"interface": "neutral-triage", "schema": "schema.json",
                                     "neutral_contract": "neutral.json", "model": "mock",
                                     "model_digest": "mock-digest"}), encoding="utf-8")
    prompt = inputs / "prompt.txt"
    prompt.write_text("fixture", encoding="utf-8")
    contract = inputs / "cwe-22.json"
    contract.write_text(json.dumps({"admitted_retrieval": {"corpus_id": "fixture-corpus"}}), encoding="utf-8")
    units_path = inputs / "reviewed-units.json"
    units_path.write_text(json.dumps([{
        "target_id": f"sample/{role}", "cve_id": "CVE-1", "revision_role": role,
        "cwe": 22, "path_prefixes": ["src/A.java"],
        "symbol_ranges": [{"path": "src/A.java", "start": 20, "end": 30}],
    } for role in ("buggy", "fixed")]), encoding="utf-8")

    def mock_scan(source_path, output, codeql, suite):
        (output / "raw").mkdir(parents=True)
        (output / "raw" / "results.sarif").write_text("{}", encoding="utf-8")
        return {"duration_seconds": 0.1}

    def mock_triage(findings, contexts, prompt_path, config, output, variant, **kwargs):
        (output / "raw").mkdir(parents=True)
        (output / "verdicts.jsonl").write_text(json.dumps({
            "candidate_id": "candidate-1", "effective_verdict": "UNCERTAIN",
        }) + "\n", encoding="utf-8")
        (output / "raw" / "candidate-1.json").write_text(json.dumps({
            "response": "{}", "prompt_eval_count": 10, "eval_count": 5,
            "total_duration": 1000000000}), encoding="utf-8")
        return {"status": "mock_completed"}

    monkeypatch.setattr("experiment_execution.scan_source", mock_scan)
    monkeypatch.setattr("experiment_execution.normalize", lambda *args: [{
        "id": "candidate-1", "path": "src/A.java", "start": 25, "flow": [], "cwes": [22]}])
    monkeypatch.setattr("experiment_execution.build_context", lambda *args: [{
        "candidate_id": "candidate-1", "lines": [], "guards": []}])
    monkeypatch.setattr("experiment_execution.run_paired", mock_triage)
    monkeypatch.setattr("experiment_execution._git_revision", lambda path: "fixture-revision")

    result = execute(manifest, manifest_path, "cwe-bench", source_root, tmp_path / "results",
                     "pair", scan_config, inference, prompt, {"22": contract}, units_path)
    metrics = json.loads((Path(result["run_directory"]) / "reports" / "cwe-bench" / "metrics.json").read_text())
    assert metrics["A"]["pair_count"] == 1
    assert len(metrics["A"]["matches"]) == 2
    assert metrics["B"]["uncertain_count"] == 2
