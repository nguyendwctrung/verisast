param(
    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [ValidateSet("development", "reportable")]
    [string]$Purpose = "development",

    [string]$ExpectedSemgrepVersion = "1.179.0"
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$semgrep = Join-Path $projectRoot "scripts\pysemgrep_launcher.py"
$dataset = Join-Path $projectRoot "datasets\raw\owasp-benchmark-java-v1.2"
$datasetManifest = Join-Path $projectRoot "datasets\manifests\owasp-benchmark-java-v1.2.json"
$rules = Join-Path $projectRoot "rules\upstream\semgrep-rules"
$inventory = Join-Path $projectRoot "rules\inventory\semgrep-java-owasp-inventory.json"
$review = Join-Path $projectRoot "rules\review\semgrep-java-owasp-review.json"
$inputDir = Join-Path $projectRoot "artifacts\semgrep-baseline-inputs\$RunId"
$runDir = Join-Path $projectRoot "artifacts\semgrep-baseline\$RunId"
$ruleset = Join-Path $inputDir "ruleset.json"
$cohort = Join-Path $inputDir "cohort.json"

if (Test-Path -LiteralPath $inputDir) {
    throw "Baseline input directory already exists: $inputDir"
}
if (Test-Path -LiteralPath $runDir) {
    throw "Baseline run directory already exists: $runDir"
}

New-Item -ItemType Directory -Path $inputDir | Out-Null
$logDir = Join-Path $projectRoot "artifacts\semgrep-logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$env:PYTHONPATH = Join-Path $projectRoot "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:SEMGREP_LOG_FILE = Join-Path $logDir "$RunId.log"

& $python (Join-Path $projectRoot "src\main.py") rules build-ruleset `
    --rules $rules `
    --inventory $inventory `
    --review $review `
    --output $ruleset `
    --purpose $Purpose
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $python (Join-Path $projectRoot "src\main.py") dataset build-owasp-cohort `
    --dataset $dataset `
    --dataset-manifest $datasetManifest `
    --ruleset $ruleset `
    --output $cohort `
    --purpose $Purpose
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $python (Join-Path $projectRoot "src\main.py") baseline run-owasp `
    --run-id $RunId `
    --purpose $Purpose `
    --dataset $dataset `
    --dataset-manifest $datasetManifest `
    --rules $rules `
    --ruleset $ruleset `
    --cohort $cohort `
    --run-dir $runDir `
    --semgrep $semgrep `
    --expected-version $ExpectedSemgrepVersion
exit $LASTEXITCODE
