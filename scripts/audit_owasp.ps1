param(
    [string]$Dataset = "datasets\raw\owasp-benchmark-java-v1.2",
    [string]$Manifest = "datasets\manifests\owasp-benchmark-java-v1.2.json",
    [string]$ExpectedCommit = "8b67a88d73b2594570fc21150705283de884620b"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

& python (Join-Path $projectRoot "src\main.py") `
    dataset audit-owasp `
    --dataset (Join-Path $projectRoot $Dataset) `
    --manifest (Join-Path $projectRoot $Manifest) `
    --expected-commit $ExpectedCommit

exit $LASTEXITCODE
