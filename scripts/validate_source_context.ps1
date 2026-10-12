param(
    [Parameter(Mandatory = $true)]
    [string]$Findings,

    [Parameter(Mandatory = $true)]
    [string]$Contexts,

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
    context validate `
    --dataset $datasetPath `
    --findings $Findings `
    --contexts $Contexts `
    --before $Before `
    --after $After `
    --max-lines $MaxLines

if ($LASTEXITCODE -ne 0) {
    throw "Source-context validation failed. ExitCode=$LASTEXITCODE"
}
