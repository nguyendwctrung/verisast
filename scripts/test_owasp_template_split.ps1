param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $Python -m pytest tests\test_owasp_split.py tests\test_owasp_split_wrapper.py -q
if ($LASTEXITCODE -ne 0) { throw "OWASP split tests failed. ExitCode=$LASTEXITCODE" }

Write-Output "OWASP_SPLIT_TESTS=PASS"
