import json
from pathlib import Path

import pytest

from paired_manifest import PairedManifestError, create, validate


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    findings = tmp_path / "findings.jsonl"
    contexts = tmp_path / "contexts.jsonl"
    prompt = tmp_path / "prompt.txt"
    schema = tmp_path / "schema.json"
    contract = tmp_path / "neutral-contract.json"
    config = tmp_path / "config.json"
    findings.write_text('{"id": "candidate-1"}\n', encoding="utf-8")
    contexts.write_text('{"candidate_id": "candidate-1"}\n', encoding="utf-8")
    prompt.write_text("{retrieved_knowledge}", encoding="utf-8")
    schema.write_text("{}", encoding="utf-8")
    contract.write_text('{"contract_id": "neutral-triage-interface"}', encoding="utf-8")
    config.write_text(json.dumps({
        "interface": "neutral-triage",
        "schema": schema.name,
        "neutral_contract": contract.name,
        "endpoint": "http://example.invalid",
        "model": "qwen",
        "model_digest": "qwen-digest",
        "timeout_seconds": 1,
        "max_response_tokens": 1,
        "context_tokens": 1,
        "keep_alive": "1m",
    }), encoding="utf-8")
    return findings, contexts, prompt, config, tmp_path / "paired.json"


def test_create_and_validate_manifest_with_frozen_inputs(tmp_path: Path) -> None:
    findings, contexts, prompt, config, manifest_path = _inputs(tmp_path)

    manifest = create(
        findings, contexts, prompt, config, manifest_path, "source-revision",
        ["python", "src/main.py", "triage", "--variant", "B"],
    )
    validated = validate(manifest_path, findings, contexts, prompt, config)

    assert manifest["purpose"] == "development_only"
    assert manifest["model"]["digest"] == "qwen-digest"
    assert validated["inputs"]["findings"]["sha256"] == manifest["inputs"]["findings"]["sha256"]


def test_create_refuses_to_overwrite_existing_manifest(tmp_path: Path) -> None:
    findings, contexts, prompt, config, manifest_path = _inputs(tmp_path)
    create(findings, contexts, prompt, config, manifest_path, "source-revision", ["python", "main.py"])

    with pytest.raises(PairedManifestError, match="already exists"):
        create(findings, contexts, prompt, config, manifest_path, "source-revision", ["python", "main.py"])


def test_validate_rejects_changed_frozen_input(tmp_path: Path) -> None:
    findings, contexts, prompt, config, manifest_path = _inputs(tmp_path)
    create(findings, contexts, prompt, config, manifest_path, "source-revision", ["python", "main.py"])
    findings.write_text('{"id": "candidate-2"}\n', encoding="utf-8")

    with pytest.raises(PairedManifestError, match="findings hash"):
        validate(manifest_path, findings, contexts, prompt, config)


def test_validate_rejects_invalid_required_field_and_contract_mismatch(tmp_path: Path) -> None:
    findings, contexts, prompt, config, manifest_path = _inputs(tmp_path)
    create(findings, contexts, prompt, config, manifest_path, "source-revision", ["python", "main.py"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["source_revision"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(PairedManifestError, match="source_revision"):
        validate(manifest_path, findings, contexts, prompt, config)

    create_path = tmp_path / "second.json"
    create(findings, contexts, prompt, config, create_path, "source-revision", ["python", "main.py"])
    contract = tmp_path / "neutral-contract.json"
    contract.write_text('{"contract_id": "neutral-triage-interface", "changed": true}', encoding="utf-8")
    with pytest.raises(PairedManifestError, match="neutral contract hash"):
        validate(create_path, findings, contexts, prompt, config)
