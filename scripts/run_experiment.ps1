param(
    [ValidateSet("preflight", "run", "mock", "prepare")]
    [string] $Action = "preflight",
    [ValidateSet("partial", "full")]
    [string] $Mode = "partial",
    [ValidateSet("owasp", "cwe-bench", "both")]
    [string] $Dataset = "both",
    [string] $SourceRoot,
    [string] $OutputDir,
    [Parameter(Mandatory)] [string] $ResultName,
    [string] $Manifest,
    [string] $GateEvidence,
    [string] $ReviewedUnits,
    [string] $RetrievalContracts,
    [string] $FeasibilityManifest,
    [string] $ScanConfig,
    [string] $InferenceConfig,
    [string] $Prompt
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "Project Python environment not found: $python"
}

function Resolve-ProjectPath([string] $Value) {
    if ([System.IO.Path]::IsPathRooted($Value)) {
        return $Value
    }
    return Join-Path $projectRoot $Value
}

$targetOutput = if ($OutputDir) { Resolve-ProjectPath $OutputDir } else { Join-Path $projectRoot "artifacts\experiments" }
$arguments = @((Join-Path $projectRoot "src\run_experiment.py"), $Action,
    "--output-dir", $targetOutput, "--result-name", $ResultName)
if ($Action -eq "prepare") {
    $targetSource = if ($SourceRoot) { Resolve-ProjectPath $SourceRoot } else { Join-Path $projectRoot "datasets\raw" }
    $arguments += @("--source-root", $targetSource)
}
elseif ($Action -ne "mock") {
    $targetManifest = if ($Manifest) { Resolve-ProjectPath $Manifest } else {
        Join-Path $projectRoot "inventory\experiment-v1\$Mode.json"
    }
    $targetSource = if ($SourceRoot) { Resolve-ProjectPath $SourceRoot } else { Join-Path $projectRoot "datasets\raw" }
    $arguments += @("--mode", $Mode, "--dataset", $Dataset,
        "--source-root", $targetSource, "--manifest", $targetManifest)
    $optionalPaths = @{
        "--gate-evidence" = $GateEvidence
        "--reviewed-units" = $ReviewedUnits
        "--retrieval-contracts" = $RetrievalContracts
        "--feasibility-manifest" = $FeasibilityManifest
        "--scan-config" = $ScanConfig
        "--inference-config" = $InferenceConfig
        "--prompt" = $Prompt
    }
    foreach ($option in $optionalPaths.Keys) {
        if ($optionalPaths[$option]) {
            $arguments += @($option, (Resolve-ProjectPath $optionalPaths[$option]))
        }
    }
    if (-not $ScanConfig) { $arguments += @("--scan-config", (Join-Path $projectRoot "configs\scan.json")) }
    if (-not $InferenceConfig) { $arguments += @("--inference-config", (Join-Path $projectRoot "configs\inference.json")) }
    if (-not $Prompt) { $arguments += @("--prompt", (Join-Path $projectRoot "prompts\triage.txt")) }
}

Push-Location $projectRoot
try {
    & $python @arguments
    $status = $LASTEXITCODE
}
finally {
    Pop-Location
}
exit $status
