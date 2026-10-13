param(
    [string]$Rules = "rules\upstream\semgrep-rules",
    [string]$Inventory = (
        "rules\inventory\" +
        "semgrep-java-owasp-inventory.json"
    ),
    [string]$ExpectedVersion = "",
    [string]$RunId = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

if (-not $RunId) {
    $RunId = "semgrep-fixtures-{0}" -f (
        Get-Date -Format "yyyyMMdd-HHmmss"
    )
}

$semgrep = "semgrep"

$runDir = Join-Path `
    $projectRoot `
    ("artifacts\semgrep-fixtures\{0}" -f $RunId)

if (-not (Get-Command $semgrep -ErrorAction SilentlyContinue)) {
    throw "Semgrep CLI command not found: $semgrep"
}
if (-not $ExpectedVersion) { $ExpectedVersion = (& $semgrep --version).Trim() }

& python (Join-Path $projectRoot "src\main.py") `
    rules validate-fixtures `
    --rules (Join-Path $projectRoot $Rules) `
    --inventory (Join-Path $projectRoot $Inventory) `
    --run-dir $runDir `
    --semgrep $semgrep `
    --expected-version $ExpectedVersion

exit $LASTEXITCODE
