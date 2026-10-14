param([string]$Python = "python")

$ErrorActionPreference = "Stop"
$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
& $Python -m pytest tests\test_owasp_reportable_baseline.py tests\test_owasp_reportable_baseline_wrapper.py -q
if ($LASTEXITCODE -ne 0) { throw "Reportable baseline tests failed. ExitCode=$LASTEXITCODE" }
Write-Output "REPORTABLE_BASELINE_TESTS=PASS"
