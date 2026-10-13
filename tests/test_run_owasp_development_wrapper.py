from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_development_wrapper_composes_existing_baseline_validation() -> None:
    content = (
        PROJECT_ROOT / "scripts" / "run_owasp_development.ps1"
    ).read_text(encoding="utf-8")

    assert '"semgrep"' in content
    assert "run_owasp_baseline.ps1" in content
    assert "validate_baseline_context.ps1" in content
    assert "-Purpose development" in content
    assert "semgrep.exe" not in content.lower()
    assert "pysemgrep_launcher" not in content.lower()
