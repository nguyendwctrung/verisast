import json
from pathlib import Path

import pytest

from ollama_client import OllamaError
from triage import TriageError, run_paired


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    findings = tmp_path / "findings.jsonl"
    contexts = tmp_path / "contexts.jsonl"
    prompt = tmp_path / "prompt.txt"
    config = tmp_path / "config.json"
    schema = tmp_path / "schema.json"
    neutral_contract = tmp_path / "neutral-contract.json"
    findings.write_text(json.dumps({"id": "candidate-1", "cwes": [22]}) + "\n", encoding="utf-8")
    contexts.write_text(json.dumps({"candidate_id": "candidate-1", "lines": [{"id": "F1:L1", "text": "sink();"}], "guards": []}) + "\n", encoding="utf-8")
    prompt.write_text("{guard_packet}\n{finding}\n{context}\n{required_guard_ids}\n{retrieved_knowledge}", encoding="utf-8")
    schema.write_text(json.dumps({"properties": {"knowledge_used": {"maxItems": 4}, "guard_assessments": {"items": {}}}}), encoding="utf-8")
    neutral_contract.write_text(json.dumps({"contract_id": "neutral-triage-interface"}), encoding="utf-8")
    config.write_text(json.dumps({
        "interface": "neutral-triage", "knowledge_slot_max_items": 3,
        "schema": "schema.json", "neutral_contract": "neutral-contract.json",
        "endpoint": "http://x", "model": "m", "model_digest": "digest",
        "timeout_seconds": 1, "max_response_tokens": 1, "context_tokens": 1,
        "keep_alive": "0s",
    }), encoding="utf-8")
    return findings, contexts, prompt, config


@pytest.fixture(autouse=True)
def verified_local_model(monkeypatch) -> None:
    monkeypatch.setattr("triage.metadata", lambda *args: {"model_digest": "digest"})
    monkeypatch.setattr("triage.generate", lambda *args: ({"response": "{}"}, "raw"))


def test_b_runner_uses_empty_knowledge_bundle(tmp_path: Path) -> None:
    findings, contexts, prompt, config = _inputs(tmp_path)

    result = run_paired(findings, contexts, prompt, config, tmp_path / "b-run", "B", None)

    request = json.loads((tmp_path / "b-run" / "requests" / "candidate-1.json").read_text(encoding="utf-8"))
    assert result["variant"] == "B"
    assert request["retrieved_knowledge"] == []


def test_c_runner_writes_validated_retrieval_evidence(tmp_path: Path) -> None:
    findings, contexts, prompt, config = _inputs(tmp_path)

    result = run_paired(
        findings, contexts, prompt, config, tmp_path / "c-run", "C",
        lambda finding, context: {"knowledge_items": [{"knowledge_id": "chunk-v1:one"}]},
    )

    request = json.loads((tmp_path / "c-run" / "requests" / "candidate-1.json").read_text(encoding="utf-8"))
    assert result["variant"] == "C"
    assert request["retrieved_knowledge"] == [{"knowledge_id": "chunk-v1:one"}]
    assert (tmp_path / "c-run" / "retrieval-records.jsonl").exists()


def test_c_runner_converts_retrieval_failure_to_uncertain(tmp_path: Path) -> None:
    findings, contexts, prompt, config = _inputs(tmp_path)

    run_paired(
        findings, contexts, prompt, config, tmp_path / "c-failure", "C",
        lambda finding, context: (_ for _ in ()).throw(RuntimeError("digest mismatch")),
    )

    verdict = json.loads((tmp_path / "c-failure" / "verdicts.jsonl").read_text(encoding="utf-8"))
    error = json.loads((tmp_path / "c-failure" / "retrieval-errors.jsonl").read_text(encoding="utf-8"))
    assert verdict["effective_verdict"] == "UNCERTAIN"
    assert error["candidate_id"] == "candidate-1"


def test_runner_records_raw_response_on_ollama_success(tmp_path: Path, monkeypatch) -> None:
    findings, contexts, prompt, config = _inputs(tmp_path)
    config_data = json.loads(config.read_text(encoding="utf-8"))
    config_data["model_digest"] = "d"
    config.write_text(json.dumps(config_data), encoding="utf-8")
    monkeypatch.setattr("triage.generate", lambda *args: ({"response": "{}"}, "raw"))
    monkeypatch.setattr("triage.metadata", lambda *args: {"model_digest": "d"})

    run_paired(findings, contexts, prompt, config, tmp_path / "run", "B", None)

    assert (tmp_path / "run" / "raw" / "candidate-1.json").read_text(encoding="utf-8") == "raw"


def test_runner_returns_uncertain_on_ollama_transport_failure(tmp_path: Path, monkeypatch) -> None:
    findings, contexts, prompt, config = _inputs(tmp_path)
    config_data = json.loads(config.read_text(encoding="utf-8"))
    config_data["model_digest"] = "digest"
    config.write_text(json.dumps(config_data), encoding="utf-8")
    monkeypatch.setattr("triage.generate", lambda *args: (_ for _ in ()).throw(OllamaError("offline")))
    monkeypatch.setattr("triage.metadata", lambda *args: {"model_digest": "digest"})

    run_paired(findings, contexts, prompt, config, tmp_path / "run", "B", None)

    row = json.loads((tmp_path / "run" / "verdicts.jsonl").read_text(encoding="utf-8"))
    assert row["effective_verdict"] == "UNCERTAIN"
    assert row["error"] == "transport:offline"


def test_c_manifest_records_contract_hash_and_bundle_snapshot(tmp_path: Path) -> None:
    findings, contexts, prompt, config = _inputs(tmp_path)
    contract = tmp_path / "retrieval-contract.json"
    contract.write_text("{}", encoding="utf-8")

    run_paired(
        findings, contexts, prompt, config, tmp_path / "run", "C",
        lambda finding, context: {"knowledge_items": [{"knowledge_id": "chunk-v1:one"}]}, contract,
    )

    manifest = json.loads((tmp_path / "run" / "manifest.json").read_text(encoding="utf-8"))
    snapshot = json.loads((tmp_path / "run" / "retrieval-bundles" / "candidate-1.json").read_text(encoding="utf-8"))
    assert manifest["contracts"]["retrieval"]["path"] == str(contract)
    assert manifest["retrieval_bundle_snapshots"] == "retrieval-bundles"
    assert snapshot["knowledge_items"][0]["knowledge_id"] == "chunk-v1:one"


def test_runner_rejects_model_digest_mismatch(tmp_path: Path, monkeypatch) -> None:
    findings, contexts, prompt, config = _inputs(tmp_path)
    config_data = json.loads(config.read_text(encoding="utf-8"))
    config_data["model_digest"] = "expected"
    config.write_text(json.dumps(config_data), encoding="utf-8")
    monkeypatch.setattr("triage.metadata", lambda *args: {"model_digest": "observed"})

    with pytest.raises(TriageError, match="model digest"):
        run_paired(findings, contexts, prompt, config, tmp_path / "run", "B", None)


def test_runner_rejects_missing_neutral_provenance_before_creating_output(tmp_path: Path) -> None:
    findings, contexts, prompt, config = _inputs(tmp_path)
    config_data = json.loads(config.read_text(encoding="utf-8"))
    del config_data["neutral_contract"]
    config.write_text(json.dumps(config_data), encoding="utf-8")

    with pytest.raises(TriageError, match="neutral_contract"):
        run_paired(findings, contexts, prompt, config, tmp_path / "run", "B", None)

    assert not (tmp_path / "run").exists()
