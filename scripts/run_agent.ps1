#!/usr/bin/env pwsh
# Kestrel ReAct Agent runner — sets env from MCP config and launches headless engagement.
# Usage:
#   .\scripts\run_agent.ps1 -Machine kobold
#   .\scripts\run_agent.ps1 -Machine kobold -Mode guided -BudgetTokens 600000
#   .\scripts\run_agent.ps1 -Machine kobold -Model claude-opus-4-5

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Machine,

    [string]$Mode        = "blind",
    [string]$Model       = "claude-sonnet-5",
    [int]   $BudgetTokens = 500000,
    [int]   $MaxIter      = 80
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Load env from MCP config ─────────────────────────────────────────────────
$claudeJson = "$env:USERPROFILE\.claude.json"
if (Test-Path $claudeJson) {
    $cfg = Get-Content $claudeJson -Raw | ConvertFrom-Json
    $kestrelServer = $cfg.mcpServers.PSObject.Properties |
        Where-Object { $_.Name -match "kestrel" } |
        Select-Object -First 1

    if ($kestrelServer) {
        $serverEnv = $kestrelServer.Value.env
        foreach ($prop in $serverEnv.PSObject.Properties) {
            if (-not [System.Environment]::GetEnvironmentVariable($prop.Name)) {
                [System.Environment]::SetEnvironmentVariable($prop.Name, $prop.Value, "Process")
            }
        }
        Write-Host "[run_agent] Loaded env from MCP config: $($kestrelServer.Name)" -ForegroundColor Cyan
    }
}

# ── Validate required env vars ────────────────────────────────────────────────
$required = @("ANTHROPIC_API_KEY", "KESTREL_KALI_HOST")
$missing = $required | Where-Object { -not [System.Environment]::GetEnvironmentVariable($_) }
if ($missing) {
    Write-Error "Missing env vars: $($missing -join ', '). Set them or add to MCP config."
    exit 1
}

# ── Launch agent ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║  Kestrel ReAct Agent — Autonomous HTB Engagement         ║" -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host "  Machine      : $Machine" -ForegroundColor Green
Write-Host "  Mode         : $Mode"
Write-Host "  Model        : $Model"
Write-Host "  Budget tokens: $BudgetTokens"
Write-Host "  Max iter     : $MaxIter"
Write-Host "  Kali host    : $env:KESTREL_KALI_HOST"
Write-Host ""
Write-Host "HITL gates will pause and ask for your input." -ForegroundColor Cyan
Write-Host "Press Ctrl+C at any time to abort gracefully." -ForegroundColor Cyan
Write-Host ""

kestrel agent $Machine `
    --mode $Mode `
    --model $Model `
    --budget-tokens $BudgetTokens `
    --max-iter $MaxIter `
    --verbose
