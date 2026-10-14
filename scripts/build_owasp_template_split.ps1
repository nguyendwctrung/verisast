param(
    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$dataset = Join-Path $projectRoot "datasets\raw\owasp-benchmark-java-v1.2"
$datasetManifest = Join-Path $projectRoot "datasets\manifests\owasp-benchmark-java-v1.2.json"
$outputDir = Join-Path $projectRoot ("artifacts\owasp-splits\{0}" -f $RunId)

foreach ($path in @($dataset, $datasetManifest)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required path not found: $path" }
}
if (Test-Path -LiteralPath $outputDir) { throw "Split output already exists: $outputDir" }

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $Python "src\main.py" dataset build-owasp-split `
    --dataset $dataset `
    --dataset-manifest $datasetManifest `
    --output-dir $outputDir
if ($LASTEXITCODE -ne 0) { throw "OWASP split build failed. ExitCode=$LASTEXITCODE" }

Write-Output "OWASP_SPLIT_DIR=$outputDir"
