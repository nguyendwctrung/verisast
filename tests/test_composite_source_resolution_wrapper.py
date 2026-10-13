from pathlib import Path


def test_composite_source_resolution_wrapper_runs_focused_tests() -> None:
    wrapper = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "test_composite_rule_sources.ps1"
    )
    text = wrapper.read_text(encoding="utf-8")

    assert "python" in text
    assert "tests\\test_semgrep_scan.py" in text
    assert "tests\\test_baseline.py" in text
    assert "tests\\test_semgrep_composite_ruleset.py" in text
