param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [string]$BundleRunId = "owasp-reportable-inputs-20261014-01",
    [string]$ExpectedSemgrepVersion = "",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$dataset = Join-Path $projectRoot "datasets\raw\owasp-benchmark-java-v1.2"
$datasetManifest = Join-Path $projectRoot "datasets\manifests\owasp-benchmark-java-v1.2.json"
$bundle = Join-Path $projectRoot ("artifacts\owasp-reportable-inputs\{0}" -f $BundleRunId)
$rules = Join-Path $projectRoot "rules\upstream\semgrep-rules"
$runDir = Join-Path $projectRoot ("artifacts\semgrep-reportable-baseline\{0}" -f $RunId)
foreach ($path in @($dataset, $datasetManifest, $bundle, $rules)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required path not found: $path" }
}
if (Test-Path -LiteralPath $runDir) { throw "Run directory already exists: $runDir" }
$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
if (-not $ExpectedSemgrepVersion) {
    $ExpectedSemgrepVersion = (& semgrep --version).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $ExpectedSemgrepVersion) { throw "Semgrep CLI version check failed." }
}
& $Python "src\main.py" baseline run-owasp-reportable `
    --run-id $RunId --dataset $dataset --dataset-manifest $datasetManifest `
    --bundle-dir $bundle --rules $rules --project-root $projectRoot `
    --run-dir $runDir --semgrep semgrep --expected-version $ExpectedSemgrepVersion
if ($LASTEXITCODE -ne 0) { throw "Reportable baseline failed. ExitCode=$LASTEXITCODE" }
Write-Output "REPORTABLE_BASELINE_RUN=$runDir"
