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
    tests\test_semgrep_composite_inputs.py `
    tests\test_owasp_composite_development_wrapper.py `
    tests\test_semgrep_composite_ruleset.py `
    tests\test_baseline.py `
    tests\test_main.py `
    -q

if ($LASTEXITCODE -ne 0) {
    throw "Composite development baseline tests failed. ExitCode=$LASTEXITCODE"
}

Write-Output "COMPOSITE_DEVELOPMENT_TESTS=PASS"
