param(
    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [Parameter(Mandatory = $true)]
    [string]$Catalog,

    [Parameter(Mandatory = $true)]
    [string]$Review,

    [Parameter(Mandatory = $true)]
    [string]$Ruleset,

    [string]$ExpectedSemgrepVersion = "",

    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$dataset = Join-Path $projectRoot "datasets\raw\owasp-benchmark-java-v1.2"
$datasetManifest = Join-Path $projectRoot "datasets\manifests\owasp-benchmark-java-v1.2.json"
$upstreamRules = Join-Path $projectRoot "rules\upstream\semgrep-rules"
$catalogPath = Join-Path $projectRoot $Catalog
$reviewPath = Join-Path $projectRoot $Review
$rulesetPath = Join-Path $projectRoot $Ruleset
$inputDir = Join-Path $projectRoot ("artifacts\semgrep-composite-inputs\{0}" -f $RunId)
$cohortPath = Join-Path $inputDir "cohort.json"
$runDir = Join-Path $projectRoot ("artifacts\semgrep-baseline\{0}" -f $RunId)

foreach ($path in @($dataset, $datasetManifest, $upstreamRules, $catalogPath, $reviewPath, $rulesetPath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required path not found: $path" }
}
foreach ($path in @($inputDir, $runDir)) {
    if (Test-Path -LiteralPath $path) { throw "Run path already exists: $path" }
}

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
if (-not $ExpectedSemgrepVersion) {
    $ExpectedSemgrepVersion = (& semgrep --version).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $ExpectedSemgrepVersion) { throw "Semgrep CLI version check failed." }
}

& $Python "src\main.py" rules freeze-composite-inputs `
    --catalog $catalogPath `
    --review $reviewPath `
    --ruleset $rulesetPath `
    --output-dir $inputDir
if ($LASTEXITCODE -ne 0) { throw "Composite input freeze failed. ExitCode=$LASTEXITCODE" }

& $Python "src\main.py" dataset build-owasp-cohort `
    --dataset $dataset `
    --dataset-manifest $datasetManifest `
    --ruleset (Join-Path $inputDir "ruleset.json") `
    --output $cohortPath `
    --purpose development
if ($LASTEXITCODE -ne 0) { throw "Composite cohort build failed. ExitCode=$LASTEXITCODE" }

& $Python "src\main.py" baseline run-owasp `
    --run-id $RunId `
    --purpose development `
    --dataset $dataset `
    --dataset-manifest $datasetManifest `
    --rules $upstreamRules `
    --project-root $projectRoot `
    --ruleset (Join-Path $inputDir "ruleset.json") `
    --cohort $cohortPath `
    --run-dir $runDir `
    --semgrep semgrep `
    --expected-version $ExpectedSemgrepVersion
if ($LASTEXITCODE -ne 0) { throw "Composite development baseline failed. ExitCode=$LASTEXITCODE" }

Write-Output "COMPOSITE_BASELINE_INPUTS=$inputDir"
Write-Output "COMPOSITE_BASELINE_RUN=$runDir"
