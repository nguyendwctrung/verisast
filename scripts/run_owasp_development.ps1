param(
    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [string]$ExpectedSemgrepVersion = "1.179.0"
)

$ErrorActionPreference = "Stop"
$semgrep = "semgrep"

if (-not (Get-Command $semgrep -ErrorAction SilentlyContinue)) {
    throw "Semgrep CLI command not found: $semgrep"
}

& $semgrep --version
if ($LASTEXITCODE -ne 0) {
    throw "Semgrep CLI version check failed."
}

& (Join-Path $PSScriptRoot "run_owasp_baseline.ps1") `
    -RunId $RunId `
    -Purpose development `
    -ExpectedSemgrepVersion $ExpectedSemgrepVersion
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& (Join-Path $PSScriptRoot "validate_baseline_context.ps1") -RunId $RunId
exit $LASTEXITCODE
