param(
    [Parameter(Mandatory = $true)]
    [string]$Findings,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [int]$Before = 20,
    [int]$After = 20,
    [int]$MaxLines = 120,
    [string]$Python = ".venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$pythonPath = Join-Path $projectRoot $Python
$datasetPath = Join-Path $projectRoot `
    "datasets\raw\owasp-benchmark-java-v1.2"

& $pythonPath "src\main.py" `
    context build `
    --dataset $datasetPath `
    --findings $Findings `
    --output $Output `
    --before $Before `
    --after $After `
    --max-lines $MaxLines

if ($LASTEXITCODE -ne 0) {
    throw "Source-context build failed. ExitCode=$LASTEXITCODE"
}
