param(
    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$dataset = Join-Path $projectRoot "datasets\raw\owasp-benchmark-java-v1.2"
$datasetManifest = Join-Path $projectRoot "datasets\manifests\owasp-benchmark-java-v1.2.json"
$splitDir = Join-Path $projectRoot ("artifacts\owasp-splits\{0}" -f $RunId)

foreach ($path in @($dataset, $datasetManifest, $splitDir)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required path not found: $path" }
}

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $Python "src\main.py" dataset validate-owasp-split `
    --dataset $dataset `
    --dataset-manifest $datasetManifest `
    --split-dir $splitDir
if ($LASTEXITCODE -ne 0) { throw "OWASP split validation failed. ExitCode=$LASTEXITCODE" }

Write-Output "OWASP_SPLIT_VALIDATION=PASS"
