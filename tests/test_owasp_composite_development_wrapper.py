from pathlib import Path


def test_composite_development_wrapper_freezes_inputs_and_passes_project_root() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "scripts" / "run_owasp_composite_development.ps1"
    text = wrapper.read_text(encoding="utf-8")

    assert "rules freeze-composite-inputs" in text
    assert "dataset build-owasp-cohort" in text
    assert "baseline run-owasp" in text
    assert "--project-root $projectRoot" in text
