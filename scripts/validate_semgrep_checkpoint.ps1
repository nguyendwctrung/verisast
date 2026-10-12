param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(327, 328, 330)]
    [int[]]$Cwe,

    [string]$Python = ".venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$pythonPath = Join-Path $projectRoot $Python
$inventoryPath = Join-Path $projectRoot `
    "rules\inventory\semgrep-java-owasp-inventory.json"
$reviewPath = Join-Path $projectRoot `
    "rules\review\semgrep-java-owasp-review.json"
$datasetPath = Join-Path $projectRoot `
    "datasets\raw\owasp-benchmark-java-v1.2"
$fixturePath = Join-Path $projectRoot `
    "artifacts\semgrep-fixtures\semgrep-fixtures-1.179.0-01\fixtures.json"
$compatibilityPath = Join-Path $projectRoot `
    "artifacts\semgrep-compat\semgrep-compat-1.179.0-fix1\compatibility.json"
$cweLabel = ($Cwe | Sort-Object -Unique) -join "-"
$pytestBaseTemp = Join-Path $projectRoot `
    "artifacts\pytest\cwe$cweLabel-checkpoint"

function Assert-LastExitCode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($LASTEXITCODE -ne 0) {
        throw "$Message ExitCode=$LASTEXITCODE"
    }
}

foreach ($requiredPath in @(
    $pythonPath,
    $inventoryPath,
    $reviewPath,
    $datasetPath,
    $fixturePath,
    $compatibilityPath
)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required path not found: $requiredPath"
    }
}

Write-Output "=== REVIEW VALIDATION ==="
& $pythonPath "src\main.py" `
    rules validate-review `
    --inventory $inventoryPath `
    --review $reviewPath
Assert-LastExitCode "Review validation failed."

foreach ($selectedCwe in ($Cwe | Sort-Object -Unique)) {
    Write-Output "=== CWE-$selectedCwe CHECKPOINT ==="
    & $pythonPath "src\main.py" `
        rules validate-checkpoint `
        --cwe $selectedCwe `
        --dataset $datasetPath `
        --review $reviewPath `
        --fixtures $fixturePath `
        --compatibility $compatibilityPath
    Assert-LastExitCode "CWE-$selectedCwe checkpoint validation failed."
}

Write-Output "=== FOCUSED TESTS ==="
New-Item `
    -ItemType Directory `
    -Path (Join-Path $projectRoot "artifacts\pytest") `
    -Force |
Out-Null

& $pythonPath -m pytest `
    "tests\test_semgrep_checkpoint.py" `
    "tests\test_semgrep_review.py" `
    "tests\test_semgrep_ruleset.py" `
    "tests\test_main.py" `
    -q `
    --basetemp $pytestBaseTemp
Assert-LastExitCode "Pytest failed."

Write-Output "=== RUFF ==="
& $pythonPath -m ruff check `
    "src\main.py" `
    "src\semgrep_checkpoint.py" `
    "src\semgrep_review.py" `
    "src\semgrep_ruleset.py" `
    "tests\test_semgrep_checkpoint.py" `
    "tests\test_main.py" `
    "tests\test_semgrep_review.py" `
    "tests\test_semgrep_ruleset.py"
Assert-LastExitCode "Ruff failed."

Write-Output "=== MYPY ==="
& $pythonPath -m mypy `
    "src\main.py" `
    "src\semgrep_checkpoint.py" `
    "src\semgrep_review.py" `
    "src\semgrep_ruleset.py"
Assert-LastExitCode "Mypy failed."

Write-Output "=== DEPENDENCIES ==="
& $pythonPath -m pip check
Assert-LastExitCode "pip check failed."

Write-Output "=== DIFF CHECK ==="
git diff --check
Assert-LastExitCode "git diff --check failed."

Write-Output "=== WORKTREE ==="
git status --short
git diff --stat

Write-Output "VALIDATION_CWES_$cweLabel=PASS"
