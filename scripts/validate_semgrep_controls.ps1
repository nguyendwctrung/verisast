param(
    [string]$Rules = "rules\upstream\semgrep-rules",
    [string]$Manifest = "rules\fixtures\manifest.json",
    [string]$ExpectedVersion = "1.179.0",
    [string]$RunId = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

if (-not $RunId) {
    $RunId = "semgrep-controls-{0}" -f (
        Get-Date -Format "yyyyMMdd-HHmmss"
    )
}

$semgrep = Join-Path `
    $projectRoot `
    ".venv\Scripts\semgrep.exe"

$runDir = Join-Path `
    $projectRoot `
    ("artifacts\semgrep-controls\{0}" -f $RunId)

if (-not (Test-Path -LiteralPath $semgrep)) {
    throw "Semgrep executable not found: $semgrep"
}

& python (Join-Path $projectRoot "src\main.py") `
    rules validate-controls `
    --project-root $projectRoot `
    --rules (Join-Path $projectRoot $Rules) `
    --manifest (Join-Path $projectRoot $Manifest) `
    --run-dir $runDir `
    --semgrep $semgrep `
    --expected-version $ExpectedVersion

exit $LASTEXITCODE
