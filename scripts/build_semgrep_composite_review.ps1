param(
    [Parameter(Mandatory = $true)]
    [string]$Catalog,

    [string]$UpstreamReview = "rules\review\semgrep-java-owasp-review.json",

    [string]$RunId = "",

    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $RunId) { $RunId = "semgrep-review-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss") }

$catalogPath = Join-Path $projectRoot $Catalog
$upstreamReviewPath = Join-Path $projectRoot $UpstreamReview
$runDir = Join-Path $projectRoot ("artifacts\semgrep-review\{0}" -f $RunId)
$outputPath = Join-Path $runDir "review.json"

foreach ($path in @($catalogPath, $upstreamReviewPath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required path not found: $path" }
}
if (Test-Path -LiteralPath $runDir) { throw "Review run directory already exists: $runDir" }

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $Python "src\semgrep_composite_review.py" `
    --catalog $catalogPath `
    --upstream-review $upstreamReviewPath `
    --output $outputPath
if ($LASTEXITCODE -ne 0) { throw "Composite review build failed. ExitCode=$LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $outputPath)) { throw "Composite review output was not created: $outputPath" }
