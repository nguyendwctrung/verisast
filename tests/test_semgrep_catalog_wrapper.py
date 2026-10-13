from pathlib import Path


def test_catalog_wrapper_calls_the_main_catalog_command() -> None:
    wrapper = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "build_semgrep_catalog.ps1"
    )

    source = wrapper.read_text(encoding="utf-8")

    assert "rules build-catalog" in source
    assert "--upstream-inventory" in source
    assert "--project-manifest" in source
    assert "--project-root" in source
    assert "--output" in source
    assert "catalog output already exists" not in source
    assert 'Write-Output "COMPOSITE_CATALOG=' not in source
