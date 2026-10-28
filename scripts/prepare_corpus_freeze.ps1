param(
    [Parameter(Mandatory)]
    [string]$Sources,

    [Parameter(Mandatory)]
    [string]$AuditScope,

    [Parameter(Mandatory)]
    [string]$Output
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    $python = "python"
}

$env:PYTHONPATH = Join-Path $root "src"
Push-Location $root
try {
    & $python -m main corpus --sources $Sources --audit-scope $AuditScope --output $Output
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
