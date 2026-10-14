param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $Python -m pytest tests\test_owasp_reportable_inputs.py tests\test_owasp_reportable_inputs_wrapper.py -q
if ($LASTEXITCODE -ne 0) { throw "Reportable input tests failed. ExitCode=$LASTEXITCODE" }

Write-Output "REPORTABLE_INPUT_TESTS=PASS"
