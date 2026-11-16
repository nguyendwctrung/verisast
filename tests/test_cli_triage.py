import json
from pathlib import Path

import pytest

from main import main
from triage import TriageError


def _args(variant: str, *extra: str) -> list[str]:
    return [
        "triage", "--findings", "findings.jsonl", "--contexts", "contexts.jsonl",
        "--prompt", "prompt.txt", "--config", "config.json", "--run", "run",
        "--variant", variant, "--paired-manifest", "paired.json", *extra,
    ]


def test_triage_b_is_valid_without_retrieval_contract(monkeypatch) -> None:
    captured = {}

    def run_paired(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"variant": "B"}

    monkeypatch.setattr("main.run_paired", run_paired)
    monkeypatch.setattr("main.validate_paired_config", lambda path: None)
    monkeypatch.setattr("main.validate_paired_manifest", lambda *args: {})

    assert main(_args("B")) == 0
    assert captured["args"][5] == "B"
    assert captured["kwargs"]["retrieval_contract_path"] is None
    assert captured["kwargs"]["paired_manifest_path"] == Path("paired.json")


def test_triage_requires_paired_manifest(capsys) -> None:
    args = _args("B")
    del args[args.index("--paired-manifest"):args.index("--paired-manifest") + 2]

    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    assert "--paired-manifest" in capsys.readouterr().err


def test_triage_b_rejects_retrieval_contract(capsys) -> None:
    assert main(_args("B", "--retrieval-contract", "contract.json")) == 1
    assert "B does not accept a retrieval contract" in capsys.readouterr().err


def test_triage_validates_paired_provenance_before_dispatch(monkeypatch, capsys) -> None:
    monkeypatch.setattr("main.validate_paired_config", lambda path: (_ for _ in ()).throw(TriageError("model_digest is required")))
    monkeypatch.setattr("main.run_paired", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not dispatch")))

    assert main(_args("B")) == 1
    assert "model_digest is required" in capsys.readouterr().err


def test_triage_c_requires_retrieval_contract(capsys) -> None:
    assert main(_args("C")) == 1
    assert "C requires --retrieval-contract" in capsys.readouterr().err


def test_paired_manifest_cli_creates_and_validates(tmp_path: Path) -> None:
    findings = tmp_path / "findings.jsonl"
    contexts = tmp_path / "contexts.jsonl"
    prompt = tmp_path / "prompt.txt"
    schema = tmp_path / "schema.json"
    contract = tmp_path / "contract.json"
    config = tmp_path / "config.json"
    manifest = tmp_path / "paired.json"
    findings.write_text('{"id": "candidate-1"}\n', encoding="utf-8")
    contexts.write_text('{"candidate_id": "candidate-1"}\n', encoding="utf-8")
    prompt.write_text("{retrieved_knowledge}", encoding="utf-8")
    schema.write_text("{}", encoding="utf-8")
    contract.write_text('{"contract_id": "neutral-triage-interface"}', encoding="utf-8")
    config.write_text(json.dumps({
        "interface": "neutral-triage", "schema": schema.name, "neutral_contract": contract.name,
        "endpoint": "http://example.invalid", "model": "qwen", "model_digest": "digest",
        "timeout_seconds": 1, "max_response_tokens": 1, "context_tokens": 1, "keep_alive": "1m",
    }), encoding="utf-8")

    create_args = [
        "paired-manifest", "create", "--findings", str(findings), "--contexts", str(contexts),
        "--prompt", str(prompt), "--config", str(config), "--source-revision", "revision",
        "--output", str(manifest), "--b-command", "python", "-m", "main", "triage",
        "--variant", "B", "--paired-manifest", str(manifest), "--run", "output",
    ]
    validate_args = [
        "paired-manifest", "validate", "--manifest", str(manifest), "--findings", str(findings),
        "--contexts", str(contexts), "--prompt", str(prompt), "--config", str(config),
    ]

    assert main(create_args) == 0
    assert main(validate_args) == 0
    frozen = json.loads(manifest.read_text(encoding="utf-8"))
    assert frozen["intended_b_command"] == create_args[create_args.index("--b-command") + 1:]
