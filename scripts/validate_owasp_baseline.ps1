param(
    [Parameter(Mandatory = $true)]
    [string]$RunId
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = "python"
$dataset = Join-Path $projectRoot "datasets\raw\owasp-benchmark-java-v1.2"
$datasetManifest = Join-Path $projectRoot "datasets\manifests\owasp-benchmark-java-v1.2.json"
$rules = Join-Path $projectRoot "rules\upstream\semgrep-rules"
$runDir = Join-Path $projectRoot "artifacts\semgrep-baseline\$RunId"

$env:PYTHONPATH = Join-Path $projectRoot "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $python (Join-Path $projectRoot "src\main.py") baseline validate-run `
    --run-dir $runDir `
    --dataset $dataset `
    --dataset-manifest $datasetManifest `
    --rules $rules `
    --project-root $projectRoot
exit $LASTEXITCODE
