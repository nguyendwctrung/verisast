param(
    [string]$RunId = "corpus-local-validation-$(Get-Date -Format yyyyMMdd-HHmmss)"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    $python = "python"
}

$env:PYTHONPATH = Join-Path $root "src"
Push-Location $root
try {
    $run = Join-Path $root "artifacts\rag\validation\$RunId"
    if (Test-Path -LiteralPath $run) {
        throw "validation output already exists: $run"
    }
    New-Item -ItemType Directory -Path $run | Out-Null

    $pytestBase = Join-Path $run "pytest"
    & $python -m pytest .\tests\test_corpus.py -q --basetemp $pytestBase
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $source = Join-Path $run "guidance.txt"
    $license = Join-Path $run "license.txt"
    [System.IO.File]::WriteAllText($source, "Resolve an archive entry against a base directory and reject paths outside it.`n", [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($license, "Creative Commons Attribution 4.0 International`n", [System.Text.UTF8Encoding]::new($false))
    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    $sources = Join-Path $run "sources.jsonl"
    $record = [ordered]@{
        source_id = "local-guidance"
        path = "guidance.txt"
        publisher = "Local validation fixture"
        source_url = "https://example.invalid/local-guidance"
        source_locator = "section:mitigations"
        source_revision_or_release = "fixture-v1"
        retrieved_at_utc = "2026-10-27T00:00:00Z"
        expected_raw_sha256 = $sourceHash
        license_id = "CC-BY-4.0"
        license_url = "https://creativecommons.org/licenses/by/4.0/"
        copyright_notice = "Local validation fixture"
        license_snapshot_reference = "license.txt"
        selection_reason = "bounded ingestion validation"
        document_id = "fixture:canonical-path-guidance"
        title = "Canonical Path Guidance"
        section_path = @("Mitigations")
        cwe_ids = @(22)
        programming_languages = @("Java")
    }
    [System.IO.File]::WriteAllText($sources, (($record | ConvertTo-Json -Compress -Depth 8) + "`n"), [System.Text.UTF8Encoding]::new($false))
    $scope = Join-Path $run "audit-scope.json"
    [System.IO.File]::WriteAllText($scope, '{"target_identifiers":["plexus utils","cve-2022-4244"]}', [System.Text.UTF8Encoding]::new($false))

    $corpus = Join-Path $run "corpus"
    & $python -m main corpus --sources $sources --audit-scope $scope --output $corpus
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    Get-Content -LiteralPath (Join-Path $corpus "manifest.json")
    Get-Content -LiteralPath (Join-Path $corpus "leakage-audit.json")
    Get-Content -LiteralPath (Join-Path $corpus "sources.jsonl")
    Get-ChildItem -LiteralPath (Join-Path $corpus "licenses") | Select-Object Name, Length
} finally {
    Pop-Location
}
