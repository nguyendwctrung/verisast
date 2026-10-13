from pathlib import Path


def test_composite_smoke_wrapper_uses_main_cli() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "scripts" / "run_composite_ruleset_smoke.ps1"
    text = wrapper.read_text(encoding="utf-8")

    assert "rules run-composite-smoke" in text
    assert "--source-root" in text
    assert "--project-root" in text
