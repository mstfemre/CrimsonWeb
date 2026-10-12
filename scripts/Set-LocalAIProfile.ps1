[CmdletBinding()]
param(
    [ValidateSet('gemma-web', 'qwen-web')]
    [string]$Profile = 'gemma-web',
    [switch]$PassThru
)

# Process environment only: no .env writes, API start, model loads or downloads.
# Get the settings from Python so profile limits have one source of truth.
$taskProjectRoot = Split-Path -Parent $PSScriptRoot
$taskPython = Join-Path $taskProjectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $taskPython -PathType Leaf)) {
    throw 'Project virtualenv required'
}
$taskProfileJson = & $taskPython -c 'import sys; from crimsonweb.api.ai.provider import AISettings; print(AISettings.for_web_profile(sys.argv[1]).model_dump_json())' $Profile
if ($LASTEXITCODE -ne 0) {
    throw 'Local AI profile validation failed'
}
$taskProfileSettings = $taskProfileJson | ConvertFrom-Json

$env:CRIMSON_AI_PROFILE = $Profile
$env:CRIMSON_AI_ENABLED = 'true'
$env:CRIMSON_OLLAMA_URL = 'http://127.0.0.1:11434'
$env:CRIMSON_OLLAMA_MODEL = $taskProfileSettings.model
$env:CRIMSON_OLLAMA_THINK = 'false'
$env:CRIMSON_AI_CONTEXT_TOKENS = [string]$taskProfileSettings.context_tokens
$env:CRIMSON_AI_MAX_OUTPUT_TOKENS = [string]$taskProfileSettings.max_output_tokens
$env:CRIMSON_AI_TIMEOUT = [string]$taskProfileSettings.timeout_seconds
$env:CRIMSON_AI_MAX_CONCURRENCY = [string]$taskProfileSettings.max_concurrency

if ($PassThru) {
    # Only fixed, nonsensitive settings; never print the environment or API token.
    [ordered]@{
        profile = $Profile
        model = $env:CRIMSON_OLLAMA_MODEL
        enabled = $true
        thinking = $false
        context_tokens = [int]$env:CRIMSON_AI_CONTEXT_TOKENS
        max_output_tokens = [int]$env:CRIMSON_AI_MAX_OUTPUT_TOKENS
        timeout_seconds = [double]$env:CRIMSON_AI_TIMEOUT
        max_concurrency = [int]$env:CRIMSON_AI_MAX_CONCURRENCY
    } | ConvertTo-Json -Compress
} else {
    Write-Output "Local AI profile set for this process: $Profile ($env:CRIMSON_OLLAMA_MODEL)"
}
