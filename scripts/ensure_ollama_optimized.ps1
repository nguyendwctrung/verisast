param(
    [Parameter(Mandatory)] [string] $Config,
    [int] $StartupTimeoutSeconds = 60
)

$ErrorActionPreference = "Stop"
$configData = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
$endpoint = [uri]$configData.endpoint
$port = if ($endpoint.IsDefaultPort) { 11434 } else { $endpoint.Port }
$environment = $configData.server_environment

if ($null -eq $environment -or -not $configData.model -or -not $configData.context_tokens) {
    throw "Ollama configuration lacks model, context_tokens, or server_environment"
}

$startedAt = (Get-Date).ToUniversalTime().ToString("o")
$listeners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
foreach ($processId in ($listeners | Select-Object -ExpandProperty OwningProcess -Unique)) {
    $listenerProcess = Get-Process -Id $processId -ErrorAction Stop
    if ($listenerProcess.ProcessName -ne "ollama") {
        throw "Port $port is owned by $($listenerProcess.ProcessName), not Ollama"
    }
    Stop-Process -Id $processId -Force -ErrorAction Stop
}

$deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
do {
    $stillListening = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if (-not $stillListening) { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)

if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    throw "Cannot stop the existing Ollama listener on port $port"
}

$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = "ollama"
$startInfo.Arguments = "serve"
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
if ($startInfo.PSObject.Properties.Match("Environment").Count) {
    $processEnvironment = $startInfo.Environment
} else {
    $processEnvironment = $startInfo.EnvironmentVariables
}
foreach ($property in $environment.PSObject.Properties) {
    $processEnvironment[$property.Name] = [string]$property.Value
}
$processEnvironment["OLLAMA_HOST"] = [string]$configData.endpoint
$server = [System.Diagnostics.Process]::Start($startInfo)

do {
    try {
        $null = Invoke-RestMethod -Uri "$($configData.endpoint)/api/version" -TimeoutSec 2
        break
    } catch {
        Start-Sleep -Milliseconds 500
    }
} while ((Get-Date) -lt $deadline)

try {
    $null = Invoke-RestMethod -Uri "$($configData.endpoint)/api/version" -TimeoutSec 2
} catch {
    throw "Ollama did not become ready within $StartupTimeoutSeconds seconds: $($_.Exception.Message)"
}

$body = @{
    model = [string]$configData.model
    prompt = "{}"
    stream = $false
    keep_alive = [string]$configData.keep_alive
    options = @{
        temperature = [double]$configData.temperature
        num_predict = 1
        num_ctx = [int]$configData.context_tokens
    }
} | ConvertTo-Json -Depth 8

try {
    $null = Invoke-RestMethod `
        -Uri "$($configData.endpoint)/api/generate" `
        -Method Post `
        -ContentType "application/json; charset=utf-8" `
        -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
        -TimeoutSec ([int]$configData.timeout_seconds)
    $running = Invoke-RestMethod -Uri "$($configData.endpoint)/api/ps" -TimeoutSec 5
} catch {
    throw "Cannot preload the configured Ollama model: $($_.Exception.Message)"
}

$model = $running.models | Where-Object { $_.name -eq $configData.model } | Select-Object -First 1
if ($null -eq $model) {
    throw "Configured Ollama model is not loaded: $($configData.model)"
}

$fullyGpuLoaded = ([int64]$model.size -gt 0) -and ([int64]$model.size -eq [int64]$model.size_vram)
if (-not $fullyGpuLoaded -or [int]$model.context_length -ne [int]$configData.context_tokens) {
    throw "Ollama optimization verification failed: size=$($model.size), size_vram=$($model.size_vram), context_length=$($model.context_length)"
}

[pscustomobject]@{
    schema_version = 1
    status = "verified"
    started_at = $startedAt
    verified_at = (Get-Date).ToUniversalTime().ToString("o")
    endpoint = [string]$configData.endpoint
    model = [string]$configData.model
    launcher_pid = $server.Id
    server_environment = $environment
    observed = [pscustomobject]@{
        name = $model.name
        size = [int64]$model.size
        size_vram = [int64]$model.size_vram
        context_length = [int]$model.context_length
        fully_gpu_loaded = $fullyGpuLoaded
    }
}
