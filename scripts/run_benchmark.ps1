param(
    [Parameter(Mandatory)] [string] $Source,
    [Parameter(Mandatory)] [string] $Revision,
    [Parameter(Mandatory)] [string] $Run,
    [string] $Codeql = "codeql",
    [string] $Suite = "codeql/java-queries:codeql-suites/java-security-extended.qls",
    [string] $Pack = "codeql/java-queries",
    [string] $Config = "configs\llm.json",
    [string] $Labels
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = Join-Path $root "src"
$runDir = Join-Path $root "artifacts\codeql\$Run"
$configPath = if ([System.IO.Path]::IsPathRooted($Config)) { $Config } else { Join-Path $root $Config }
$ollamaPreflight = & (Join-Path $PSScriptRoot "ensure_ollama_optimized.ps1") -Config $configPath
Write-Host "OLLAMA_PREFLIGHT full_gpu=$($ollamaPreflight.observed.fully_gpu_loaded) context=$($ollamaPreflight.observed.context_length) launcher_pid=$($ollamaPreflight.launcher_pid)"

function Invoke-Step([string[]] $Arguments) {
    & python (Join-Path $root "src\main.py") @Arguments
    if ($LASTEXITCODE) { throw "Pipeline step failed: $($Arguments[0])" }
}

Invoke-Step @("scan", "--source", $Source, "--run", $runDir, "--codeql", $Codeql, "--suite", $Suite)
$runtimeDir = Join-Path $runDir "runtime"
New-Item -ItemType Directory -Path $runtimeDir -ErrorAction Stop | Out-Null
$ollamaPreflight | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runtimeDir "ollama-preflight.json") -Encoding utf8
Invoke-Step @("normalize", "--sarif", (Join-Path $runDir "raw\results.sarif"), "--source-revision", $Revision, "--pack", $Pack, "--suite", $Suite, "--output", (Join-Path $runDir "normalized\findings.jsonl"))
Invoke-Step @("context", "--source", $Source, "--findings", (Join-Path $runDir "normalized\findings.jsonl"), "--output", (Join-Path $runDir "context\contexts.jsonl"))
if ($Labels) {
    $units = Join-Path $runDir "evaluation\units.json"
    Invoke-Step @("units", "--labels", $Labels, "--output", $units)
    Invoke-Step @("evaluate", "--units", $units, "--findings", (Join-Path $runDir "normalized\findings.jsonl"), "--output", (Join-Path $runDir "evaluation\metrics.json"))
}

