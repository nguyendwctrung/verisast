param(
    [Parameter(Mandatory)] [string] $Findings,
    [Parameter(Mandatory)] [string] $Contexts,
    [Parameter(Mandatory)] [string] $Run,
    [string] $Prompt = "prompts\triage.txt",
    [string] $Config = "configs\llm.json"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
$runDir = Join-Path $root "artifacts\llm\$Run"
& $python (Join-Path $root "src\main.py") triage --findings $Findings --contexts $Contexts --prompt (Join-Path $root $Prompt) --config (Join-Path $root $Config) --run $runDir
if ($LASTEXITCODE) { throw "Triage failed" }

