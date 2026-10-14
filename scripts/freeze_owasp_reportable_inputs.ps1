param(
    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [Parameter(Mandatory = $true)]
    [string]$Catalog,

    [Parameter(Mandatory = $true)]
    [string]$Review,

    [string]$SplitRunId = "owasp-template-split-20261014-01",

    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$dataset = Join-Path $projectRoot "datasets\raw\owasp-benchmark-java-v1.2"
$datasetManifest = Join-Path $projectRoot "datasets\manifests\owasp-benchmark-java-v1.2.json"
$split = Join-Path $projectRoot ("artifacts\owasp-splits\{0}" -f $SplitRunId)
$upstreamRules = Join-Path $projectRoot "rules\upstream\semgrep-rules"
$catalogPath = Join-Path $projectRoot $Catalog
$reviewPath = Join-Path $projectRoot $Review
$outputDir = Join-Path $projectRoot ("artifacts\owasp-reportable-inputs\{0}" -f $RunId)

foreach ($path in @($dataset, $datasetManifest, $split, $upstreamRules, $catalogPath, $reviewPath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required path not found: $path" }
}
if (Test-Path -LiteralPath $outputDir) { throw "Reportable input output already exists: $outputDir" }

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $Python "src\main.py" dataset freeze-owasp-reportable-inputs `
    --dataset $dataset `
    --dataset-manifest $datasetManifest `
    --split $split `
    --upstream-rules $upstreamRules `
    --project-root $projectRoot `
    --catalog $catalogPath `
    --review $reviewPath `
    --output-dir $outputDir
if ($LASTEXITCODE -ne 0) { throw "Reportable input freeze failed. ExitCode=$LASTEXITCODE" }

Write-Output "REPORTABLE_INPUT_DIR=$outputDir"
