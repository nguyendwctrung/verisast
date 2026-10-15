param([string]$Python = "python")

$ErrorActionPreference = "Stop"
$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
& $Python -m pytest tests\test_llm_prompt.py tests\test_ollama_client.py tests\test_verdict.py tests\test_llm_verifier_wrapper.py -q
if ($LASTEXITCODE -ne 0) { throw "LLM verifier tests failed. ExitCode=$LASTEXITCODE" }
Write-Output "LLM_VERIFIER_TESTS=PASS"
