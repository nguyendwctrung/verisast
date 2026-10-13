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
    tests\test_semgrep_composite_smoke.py `
    tests\test_semgrep_composite_smoke_wrapper.py `
    tests\test_semgrep_composite_ruleset.py `
    tests\test_semgrep_scan.py `
    tests\test_main.py `
    -q

if ($LASTEXITCODE -ne 0) {
    throw "Composite smoke tests failed. ExitCode=$LASTEXITCODE"
}

Write-Output "COMPOSITE_SMOKE_TESTS=PASS"
