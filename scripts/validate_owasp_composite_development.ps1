param(
    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$dataset = Join-Path $projectRoot "datasets\raw\owasp-benchmark-java-v1.2"
$datasetManifest = Join-Path $projectRoot "datasets\manifests\owasp-benchmark-java-v1.2.json"
$upstreamRules = Join-Path $projectRoot "rules\upstream\semgrep-rules"
$inputDir = Join-Path $projectRoot ("artifacts\semgrep-composite-inputs\{0}" -f $RunId)
$runDir = Join-Path $projectRoot ("artifacts\semgrep-baseline\{0}" -f $RunId)

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $Python "src\main.py" rules validate-composite-inputs --input-dir $inputDir
if ($LASTEXITCODE -ne 0) { throw "Composite input validation failed. ExitCode=$LASTEXITCODE" }

& $Python "src\main.py" baseline validate-run `
    --run-dir $runDir `
    --dataset $dataset `
    --dataset-manifest $datasetManifest `
    --rules $upstreamRules `
    --project-root $projectRoot
if ($LASTEXITCODE -ne 0) { throw "Composite baseline validation failed. ExitCode=$LASTEXITCODE" }

Write-Output "COMPOSITE_BASELINE_VALIDATION=PASS"
