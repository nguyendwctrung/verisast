param(
    [Parameter(Mandatory = $true)]
    [string]$Catalog,

    [Parameter(Mandatory = $true)]
    [string]$Review,

    [Parameter(Mandatory = $true)]
    [string]$Ruleset,

    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [string]$ExpectedSemgrepVersion = "",

    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$upstreamRules = Join-Path $projectRoot "rules\upstream\semgrep-rules"
$sourceRoot = Join-Path $projectRoot "rules\fixtures\java\composite-smoke"
$catalogPath = Join-Path $projectRoot $Catalog
$reviewPath = Join-Path $projectRoot $Review
$rulesetPath = Join-Path $projectRoot $Ruleset
$runDir = Join-Path $projectRoot ("artifacts\semgrep-composite-smoke\{0}" -f $RunId)

foreach ($path in @($upstreamRules, $sourceRoot, $catalogPath, $reviewPath, $rulesetPath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required path not found: $path" }
}
if (Test-Path -LiteralPath $runDir) { throw "Composite smoke run directory already exists: $runDir" }

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
if (-not $ExpectedSemgrepVersion) {
    $ExpectedSemgrepVersion = (& semgrep --version).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $ExpectedSemgrepVersion) {
        throw "Semgrep CLI version check failed."
    }
}

& $Python "src\main.py" rules run-composite-smoke `
    --run-id $RunId `
    --upstream-rules $upstreamRules `
    --project-root $projectRoot `
    --catalog $catalogPath `
    --review $reviewPath `
    --ruleset $rulesetPath `
    --source-root $sourceRoot `
    --run-dir $runDir `
    --semgrep semgrep `
    --expected-version $ExpectedSemgrepVersion

if ($LASTEXITCODE -ne 0) { throw "Composite smoke scan failed. ExitCode=$LASTEXITCODE" }
