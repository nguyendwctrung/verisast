from pathlib import Path


def test_llm_verifier_wrapper_runs_only_local_contract_tests() -> None:
    script = (Path(__file__).resolve().parents[1] / "scripts" / "test_llm_verifier.ps1").read_text(encoding="utf-8")

    assert "test_llm_prompt.py" in script
    assert "test_ollama_client.py" in script
    assert "test_verdict.py" in script
    assert "/api/generate" not in script
    assert "& ollama " not in script.lower()
