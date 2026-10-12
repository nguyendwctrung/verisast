from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WRAPPERS = (
    "run_owasp_baseline.ps1",
    "validate_semgrep_rules.ps1",
    "validate_semgrep_fixtures.ps1",
    "validate_semgrep_controls.ps1",
    "test_semgrep_negative_fixtures.ps1",
)


@pytest.mark.parametrize("name", WRAPPERS)
def test_semgrep_wrapper_uses_cli_not_executable_path(name: str) -> None:
    content = (PROJECT_ROOT / "scripts" / name).read_text(encoding="utf-8")
    assert "semgrep.exe" not in content.lower()
    assert '$semgrep = "semgrep"' in content
