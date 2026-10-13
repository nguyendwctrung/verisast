param(
    [string]$UpstreamRules = "rules\upstream\semgrep-rules",

    [Parameter(Mandatory = $true)]
    [string]$Catalog,

    [Parameter(Mandatory = $true)]
    [string]$Review,

    [string]$RunId = "",

    [ValidateSet("development", "reportable")]
    [string]$Purpose = "development",

    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $RunId) {
    $RunId = "semgrep-ruleset-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")
}

$upstreamRulesPath = Join-Path $projectRoot $UpstreamRules
$catalogPath = Join-Path $projectRoot $Catalog
$reviewPath = Join-Path $projectRoot $Review
$runDir = Join-Path $projectRoot ("artifacts\semgrep-ruleset\{0}" -f $RunId)
$outputPath = Join-Path $runDir "ruleset.json"

foreach ($path in @($upstreamRulesPath, $catalogPath, $reviewPath)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required path not found: $path"
    }
}
if (Test-Path -LiteralPath $runDir) {
    throw "Ruleset run directory already exists: $runDir"
}

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $Python "src\main.py" rules build-composite-ruleset `
    --upstream-rules $upstreamRulesPath `
    --project-root $projectRoot `
    --catalog $catalogPath `
    --review $reviewPath `
    --output $outputPath `
    --purpose $Purpose

if ($LASTEXITCODE -ne 0) {
    throw "Composite ruleset build failed. ExitCode=$LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $outputPath)) {
    throw "Composite ruleset output was not created: $outputPath"
}
