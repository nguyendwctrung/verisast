param(
    [ValidateSet("Initialize", "Validate")]
    [string]$Action = "Validate",
    [string]$Inventory = (
        "rules\inventory\" +
        "semgrep-java-owasp-inventory.json"
    ),
    [string]$Review = (
        "rules\review\" +
        "semgrep-java-owasp-review.json"
    )
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$inventoryPath = Join-Path $projectRoot $Inventory
$reviewPath = Join-Path $projectRoot $Review

if ($Action -eq "Initialize") {
    & python (Join-Path $projectRoot "src\main.py") `
        rules init-review `
        --inventory $inventoryPath `
        --output $reviewPath
} else {
    & python (Join-Path $projectRoot "src\main.py") `
        rules validate-review `
        --inventory $inventoryPath `
        --review $reviewPath
}

exit $LASTEXITCODE
