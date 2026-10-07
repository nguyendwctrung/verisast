param(
    [string]$ExpectedVersion = "1.179.0"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$semgrep = Join-Path $projectRoot ".venv\Scripts\semgrep.exe"

if (-not (Test-Path -LiteralPath $semgrep)) {
    throw "Semgrep executable not found: $semgrep"
}

$observedVersion = (& $semgrep --version).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Failed to read Semgrep version"
}

if ($observedVersion -ne $ExpectedVersion) {
    throw (
        "Unexpected Semgrep version: " +
        "expected $ExpectedVersion, observed $observedVersion"
    )
}

$cases = @(
    @{
        Name = "use-of-sha1"
        Rule = (
            "rules\upstream\semgrep-rules\" +
            "java\lang\security\audit\crypto\use-of-sha1.yaml"
        )
        Fixture = "rules\fixtures\java\use-of-sha1.java"
    },
    @{
        Name = "use-of-sha224"
        Rule = (
            "rules\upstream\semgrep-rules\" +
            "java\lang\security\audit\crypto\use-of-sha224.yaml"
        )
        Fixture = "rules\fixtures\java\use-of-sha224.java"
    },
    @{
        Name = "java-reverse-shell"
        Rule = (
            "rules\upstream\semgrep-rules\" +
            "java\lang\security\audit\java-reverse-shell.yaml"
        )
        Fixture = "rules\fixtures\java\java-reverse-shell.java"
    },
    @{
        Name = "ldap-entry-poisoning"
        Rule = (
            "rules\upstream\semgrep-rules\" +
            "java\lang\security\audit\ldap-entry-poisoning.yaml"
        )
        Fixture = "rules\fixtures\java\ldap-entry-poisoning.java"
    },
    @{
        Name = "xssrequestwrapper-is-insecure"
        Rule = (
            "rules\upstream\semgrep-rules\" +
            "java\lang\security\audit\xssrequestwrapper-is-insecure.yaml"
        )
        Fixture = (
            "rules\fixtures\java\" +
            "xssrequestwrapper-is-insecure.java"
        )
    }
)

$passed = 0
$falsePositives = 0
$errorCount = 0

foreach ($case in $cases) {
    $rule = Join-Path $projectRoot $case.Rule
    $fixture = Join-Path $projectRoot $case.Fixture

    if (-not (Test-Path -LiteralPath $rule)) {
        throw "Rule not found: $rule"
    }

    if (-not (Test-Path -LiteralPath $fixture)) {
        throw "Fixture not found: $fixture"
    }

    Write-Output "===== NEGATIVE FIXTURE: $($case.Name) ====="

    $outputPath = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) (
        "verisast-semgrep-{0}.json" -f [guid]::NewGuid()
    )

    try {
        & $semgrep scan `
            --config $rule `
            --json `
            --metrics=off `
            --disable-version-check `
            --no-git-ignore `
            --output $outputPath `
            $fixture

        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0) {
            $errorCount += 1
            Write-Output "NEGATIVE_FIXTURE_RESULT=error"
            Write-Output "EXIT_CODE=$exitCode"
            continue
        }

        if (-not (Test-Path -LiteralPath $outputPath)) {
            $errorCount += 1
            Write-Output "NEGATIVE_FIXTURE_RESULT=error"
            Write-Output "ERROR=Semgrep JSON output was not created"
            continue
        }

        try {
            $scan = Get-Content $outputPath -Raw | ConvertFrom-Json
        } catch {
            $errorCount += 1
            Write-Output "NEGATIVE_FIXTURE_RESULT=error"
            Write-Output "ERROR=Invalid Semgrep JSON output"
            continue
        }

        $scannerErrors = @($scan.errors).Count
        $findingCount = @($scan.results).Count

        Write-Output "EXIT_CODE=$exitCode"
        Write-Output "SCANNER_ERRORS=$scannerErrors"
        Write-Output "FINDINGS=$findingCount"

        if ($scannerErrors -ne 0) {
            $errorCount += 1
            Write-Output "NEGATIVE_FIXTURE_RESULT=error"
        } elseif ($findingCount -eq 0) {
            $passed += 1
            Write-Output "NEGATIVE_FIXTURE_RESULT=passed"
        } else {
            $falsePositives += 1
            Write-Output "NEGATIVE_FIXTURE_RESULT=false_positive"

            foreach ($finding in $scan.results) {
                Write-Output (
                    "FINDING={0}:{1}:{2}" -f
                    $finding.check_id,
                    $finding.start.line,
                    $finding.extra.message
                )
            }
        }
    } finally {
        if (Test-Path -LiteralPath $outputPath) {
            Remove-Item -LiteralPath $outputPath -Force
        }
    }
}

Write-Output "NEGATIVE_FIXTURE_STATUS=completed"
Write-Output "SEMGREP_VERSION=$observedVersion"
Write-Output "TOTAL=$($cases.Count)"
Write-Output "PASSED=$passed"
Write-Output "FALSE_POSITIVES=$falsePositives"
Write-Output "ERRORS=$errorCount"

if ($falsePositives -ne 0 -or $errorCount -ne 0) {
    exit 1
}

exit 0
