param(
    [Parameter(Mandatory)] [string] $Findings,
    [Parameter(Mandatory)] [string] $Contexts,
    [Parameter(Mandatory)] [string] $Run,
    [string] $Prompt = "prompts\triage.txt",
    [string] $Config = "configs\llm.json"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = Join-Path $root "src"
$runDir = Join-Path $root "artifacts\llm\$Run"
$promptPath = if ([System.IO.Path]::IsPathRooted($Prompt)) { $Prompt } else { Join-Path $root $Prompt }
$configPath = if ([System.IO.Path]::IsPathRooted($Config)) { $Config } else { Join-Path $root $Config }
$ollamaPreflight = & (Join-Path $PSScriptRoot "ensure_ollama_optimized.ps1") -Config $configPath
Write-Host "OLLAMA_PREFLIGHT full_gpu=$($ollamaPreflight.observed.fully_gpu_loaded) context=$($ollamaPreflight.observed.context_length) launcher_pid=$($ollamaPreflight.launcher_pid)"
& python (Join-Path $root "src\main.py") triage --findings $Findings --contexts $Contexts --prompt $promptPath --config $configPath --run $runDir
if ($LASTEXITCODE) { throw "Triage failed" }
$runtimeDir = Join-Path $runDir "runtime"
New-Item -ItemType Directory -Path $runtimeDir -ErrorAction Stop | Out-Null
$ollamaPreflight | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runtimeDir "ollama-preflight.json") -Encoding utf8

