from pathlib import Path


def test_split_wrappers_expose_build_validation_and_test_interfaces() -> None:
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    build = (scripts / "build_owasp_template_split.ps1").read_text(encoding="utf-8")
    validate = (scripts / "validate_owasp_template_split.ps1").read_text(encoding="utf-8")
    test = (scripts / "test_owasp_template_split.ps1").read_text(encoding="utf-8")
    assert "dataset build-owasp-split" in build
    assert "dataset validate-owasp-split" in validate
    assert "test_owasp_split" in test
    assert "baseline run-owasp" not in build
