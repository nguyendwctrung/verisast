param(
    [Parameter(Mandatory)] [string] $Source,
    [Parameter(Mandatory)] [string] $Revision,
    [Parameter(Mandatory)] [string] $Run,
    [string] $Codeql = "codeql",
    [string] $Suite = "codeql/java-queries:codeql-suites/java-security-extended.qls",
    [string] $Pack = "codeql/java-queries",
    [string] $Labels
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
$runDir = Join-Path $root "artifacts\codeql\$Run"

function Invoke-Step([string[]] $Arguments) {
    & $python (Join-Path $root "src\main.py") @Arguments
    if ($LASTEXITCODE) { throw "Pipeline step failed: $($Arguments[0])" }
}

Invoke-Step @("scan", "--source", $Source, "--run", $runDir, "--codeql", $Codeql, "--suite", $Suite)
Invoke-Step @("normalize", "--sarif", (Join-Path $runDir "raw\results.sarif"), "--source-revision", $Revision, "--pack", $Pack, "--suite", $Suite, "--output", (Join-Path $runDir "normalized\findings.jsonl"))
Invoke-Step @("context", "--source", $Source, "--findings", (Join-Path $runDir "normalized\findings.jsonl"), "--output", (Join-Path $runDir "context\contexts.jsonl"))
if ($Labels) {
    $units = Join-Path $runDir "evaluation\units.json"
    Invoke-Step @("units", "--labels", $Labels, "--output", $units)
    Invoke-Step @("evaluate", "--units", $units, "--findings", (Join-Path $runDir "normalized\findings.jsonl"), "--output", (Join-Path $runDir "evaluation\metrics.json"))
}

