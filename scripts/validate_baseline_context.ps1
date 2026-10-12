param(
    [Parameter(Mandatory = $true)]
    [string]$RunId
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$dataset = Join-Path $projectRoot "datasets\raw\owasp-benchmark-java-v1.2"
$datasetManifest = Join-Path $projectRoot "datasets\manifests\owasp-benchmark-java-v1.2.json"
$rules = Join-Path $projectRoot "rules\upstream\semgrep-rules"
$runDir = Join-Path $projectRoot "artifacts\semgrep-baseline\$RunId"
$manifestPath = Join-Path $runDir "manifest.json"

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Baseline manifest does not exist: $manifestPath"
}

$env:PYTHONPATH = Join-Path $projectRoot "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $python (Join-Path $projectRoot "src\main.py") baseline validate-run `
    --run-dir $runDir `
    --dataset $dataset `
    --dataset-manifest $datasetManifest `
    --rules $rules
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ($manifest.schema_version -ne 2) {
    throw "Expected schema version 2, found $($manifest.schema_version)."
}
if ($manifest.stages.context -ne "completed") {
    throw "Context stage is not completed: $($manifest.stages.context)."
}
if ($null -eq $manifest.context -or $null -eq $manifest.context.artifact) {
    throw "Context manifest record is missing."
}
if ($manifest.counts.contexts -ne $manifest.counts.normalized_findings) {
    throw "Context count does not match normalized finding count."
}

$contextPath = Join-Path $runDir $manifest.context.artifact.path
if (-not (Test-Path -LiteralPath $contextPath)) {
    throw "Context artifact does not exist: $contextPath"
}

Write-Output "BASELINE_CONTEXT_SCHEMA=$($manifest.schema_version)"
Write-Output "BASELINE_CONTEXTS=$($manifest.counts.contexts)"
Write-Output "BASELINE_CONTEXT_ARTIFACT=$contextPath"
Write-Output "BASELINE_CONTEXT_CHECK=PASS"
