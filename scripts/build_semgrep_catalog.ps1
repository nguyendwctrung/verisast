param(
    [string]$UpstreamInventory = (
        "rules\inventory\semgrep-java-owasp-inventory.json"
    ),

    [string]$ProjectManifest = "rules\project\manifest.json",

    [string]$RunId = "",

    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

if (-not $RunId) {
    $RunId = "semgrep-catalog-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")
}

$inventoryPath = Join-Path $projectRoot $UpstreamInventory
$manifestPath = Join-Path $projectRoot $ProjectManifest
$runDir = Join-Path $projectRoot ("artifacts\semgrep-catalog\{0}" -f $RunId)
$outputPath = Join-Path $runDir "catalog.json"

foreach ($requiredPath in @($inventoryPath, $manifestPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required path not found: $requiredPath"
    }
}

if (Test-Path -LiteralPath $runDir) {
    throw "Catalog run directory already exists: $runDir"
}

$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

& $Python "src\main.py" rules build-catalog `
    --upstream-inventory $inventoryPath `
    --project-manifest $manifestPath `
    --project-root $projectRoot `
    --output $outputPath

if ($LASTEXITCODE -ne 0) {
    throw "Composite catalog build failed. ExitCode=$LASTEXITCODE"
}

if (-not (Test-Path -LiteralPath $outputPath)) {
    throw "Composite catalog output was not created: $outputPath"
}
