param(
    [string]$Rules = "rules\upstream\semgrep-rules",
    [string]$Output = "rules\inventory\semgrep-java-owasp-inventory.json"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

& python (Join-Path $projectRoot "src\main.py") `
    rules inventory-semgrep `
    --rules (Join-Path $projectRoot $Rules) `
    --output (Join-Path $projectRoot $Output)

exit $LASTEXITCODE
