param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $Python -m pytest `
    tests\test_semgrep_ruleset.py `
    tests\test_semgrep_composite_ruleset.py `
    tests\test_semgrep_composite_ruleset_wrapper.py `
    tests\test_semgrep_scan.py `
    tests\test_baseline.py `
    tests\test_main.py `
    tests\test_composite_source_resolution_wrapper.py `
    -q

if ($LASTEXITCODE -ne 0) {
    throw "Composite source-root tests failed. ExitCode=$LASTEXITCODE"
}

Write-Output "COMPOSITE_SOURCE_ROOT_TESTS=PASS"
