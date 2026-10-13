from pathlib import Path


def test_composite_ruleset_wrapper_uses_main_cli() -> None:
    wrapper = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "build_composite_semgrep_ruleset.ps1"
    )
    text = wrapper.read_text(encoding="utf-8")

    assert "rules build-composite-ruleset" in text
    assert "--upstream-rules" in text
    assert "--project-root" in text
    assert "--catalog" in text
    assert "--review" in text
