from pathlib import Path

from main import main
from triage import TriageError


def _args(variant: str, *extra: str) -> list[str]:
    return [
        "triage", "--findings", "findings.jsonl", "--contexts", "contexts.jsonl",
        "--prompt", "prompt.txt", "--config", "config.json", "--run", "run",
        "--variant", variant, *extra,
    ]


def test_triage_b_is_valid_without_retrieval_contract(monkeypatch) -> None:
    captured = {}

    def run_paired(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"variant": "B"}

    monkeypatch.setattr("main.run_paired", run_paired)
    monkeypatch.setattr("main.validate_paired_config", lambda path: None)

    assert main(_args("B")) == 0
    assert captured["args"][5] == "B"
    assert captured["kwargs"]["retrieval_contract_path"] is None


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
