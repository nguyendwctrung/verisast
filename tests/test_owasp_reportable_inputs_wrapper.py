from pathlib import Path


def test_reportable_input_wrappers_do_not_run_a_baseline() -> None:
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    build = (scripts / "freeze_owasp_reportable_inputs.ps1").read_text(encoding="utf-8")
    validate = (scripts / "validate_owasp_reportable_inputs.ps1").read_text(encoding="utf-8")
    test = (scripts / "test_owasp_reportable_inputs.ps1").read_text(encoding="utf-8")
    assert "dataset freeze-owasp-reportable-inputs" in build
    assert "dataset validate-owasp-reportable-inputs" in validate
    assert "baseline run-owasp" not in build
    assert "test_owasp_reportable_inputs" in test
