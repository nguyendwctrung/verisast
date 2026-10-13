$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $projectRoot "rules\project\manifest.json"

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Project rule manifest not found: $manifestPath"
}

$manifest = Get-Content -Raw -LiteralPath $manifestPath |
    ConvertFrom-Json

if ($manifest.schema_version -ne 1) {
    throw "Unsupported manifest schema version."
}

if ($manifest.source_type -ne "project_authored") {
    throw "Manifest source_type must be project_authored."
}

if (@($manifest.rules).Count -ne 1) {
    throw "Manifest must contain exactly one project rule."
}

$rule = $manifest.rules[0]

if ($rule.rule_id -ne "project-cwe327-desede-ecb-default") {
    throw "Unexpected project rule ID."
}

if (-not (@($rule.cwes) -contains 327)) {
    throw "Project rule must declare CWE-327."
}

$paths = @(
    [pscustomobject]@{
        Label = "rule"
        Path = $rule.source_path
        ExpectedHash = $rule.source_sha256
    }
)

foreach ($fixture in $rule.fixtures) {
    $paths += [pscustomobject]@{
        Label = "fixture:$($fixture.kind)"
        Path = $fixture.path
        ExpectedHash = $fixture.sha256
    }
}

foreach ($item in $paths) {
    $fullPath = Join-Path $projectRoot $item.Path

    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw "Missing $($item.Label): $fullPath"
    }

    $actualHash = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $fullPath
    ).Hash.ToLowerInvariant()

    if ($actualHash -ne $item.ExpectedHash) {
        throw (
            "Hash mismatch for $($item.Label). " +
            "Expected=$($item.ExpectedHash) Actual=$actualHash"
        )
    }

    Write-Output "HASH_OK $($item.Label) $($item.Path)"
}

Write-Output "PROJECT_RULE_PROVENANCE=PASS"