param(
    [string]$Destination = "rules\upstream\semgrep-rules"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$target = Join-Path $projectRoot $Destination
$remote = "https://github.com/semgrep/semgrep-rules.git"

if (-not (Test-Path -LiteralPath $target)) {
    New-Item -ItemType Directory -Force (Split-Path -Parent $target) | Out-Null
    git clone --no-tags $remote $target
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$observedRemote = git -C $target remote get-url origin
if ($LASTEXITCODE -ne 0 -or $observedRemote.TrimEnd("/") -ne $remote.TrimEnd("/")) {
    throw "Unexpected Semgrep rules remote: $observedRemote"
}

$status = git -C $target status --porcelain
if ($LASTEXITCODE -ne 0 -or $status) {
    throw "Semgrep rules checkout is not clean"
}

$commit = git -C $target rev-parse HEAD
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

git -C $target checkout --detach $commit
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Output "RULES_STATUS=ready"
Write-Output "RULES_REMOTE=$observedRemote"
Write-Output "RULES_COMMIT=$commit"
Write-Output "RULES_PATH=$target"
