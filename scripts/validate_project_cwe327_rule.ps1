param(
    [string]$Semgrep = "semgrep"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$rulePath = Join-Path $projectRoot `
    "rules\project\java\security\project-cwe327-desede-ecb-default.yaml"
$positiveFixture = Join-Path $projectRoot `
    "rules\fixtures\java\project-cwe327-desede-ecb-default.java"
$negativeFixture = Join-Path $projectRoot `
    "rules\fixtures\java\project-cwe327-desede-ecb-default-negative.java"

function Assert-LastExitCode {
    param([string]$Message)

    if ($LASTEXITCODE -ne 0) {
        throw "$Message ExitCode=$LASTEXITCODE"
    }
}

function Assert-FindingCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedCount
    )

    $output = & $Semgrep scan `
        --config $rulePath `
        --json `
        --metrics=off `
        $Target
    Assert-LastExitCode "Semgrep scan failed for $Target."

    try {
        $report = $output | ConvertFrom-Json
    }
    catch {
        throw "Semgrep JSON output could not be parsed for $Target."
    }

    $actualCount = @($report.results).Count
    if ($actualCount -ne $ExpectedCount) {
        throw "Unexpected finding count for $Target. Expected=$ExpectedCount Actual=$actualCount"
    }
}

foreach ($requiredPath in @($rulePath, $positiveFixture, $negativeFixture)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required path not found: $requiredPath"
    }
}

if (-not (Get-Command $Semgrep -ErrorAction SilentlyContinue)) {
    throw "Semgrep CLI command not found: $Semgrep"
}

Write-Output "=== SEMGREP VERSION ==="
& $Semgrep --version
Assert-LastExitCode "Semgrep version check failed."

Write-Output "=== CONTENT HASHES ==="
Get-FileHash -Algorithm SHA256 -LiteralPath $rulePath, $positiveFixture, $negativeFixture |
    Select-Object Path, Hash |
    Format-Table -AutoSize

Write-Output "=== POSITIVE FIXTURE ==="
Assert-FindingCount -Target $positiveFixture -ExpectedCount 1

Write-Output "=== NEGATIVE FIXTURE ==="
Assert-FindingCount -Target $negativeFixture -ExpectedCount 0

Write-Output "PROJECT_CWE327_RULE_SMOKE=PASS"
