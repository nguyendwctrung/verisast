from pathlib import Path


def test_reportable_baseline_wrappers_use_one_reportable_run_interface() -> None:
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    run = (scripts / "run_owasp_reportable_baseline.ps1").read_text(encoding="utf-8")
    validate = (scripts / "validate_owasp_reportable_baseline.ps1").read_text(encoding="utf-8")
    test = (scripts / "test_owasp_reportable_baseline.ps1").read_text(encoding="utf-8")
    assert "baseline run-owasp-reportable" in run
    assert "baseline validate-owasp-reportable" in validate
    assert "test_owasp_reportable_baseline" in test
    assert "baseline run-owasp `" not in run
