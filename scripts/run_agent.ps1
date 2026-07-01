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
    [string]$Model       = "claude-sonnet-4-5",
    [int]   $BudgetTokens = 500000,
    [int]   $MaxIter      = 80,
    [string]$LogFile      = "",    # if set, tee output to this file
    [switch]$Headless              # pipe NUL → stdin; HITL gates auto-confirm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Load env from MCP config ─────────────────────────────────────────────────
$claudeJson = "$env:USERPROFILE\.claude.json"
if (Test-Path $claudeJson) {
    try {
        $cfg = Get-Content $claudeJson -Raw | ConvertFrom-Json -AsHashtable
        $mcpServers = $cfg["mcpServers"]
        if ($mcpServers) {
            $kestrelKey = ($mcpServers.Keys | Where-Object { $_ -match "kestrel" } | Select-Object -First 1)
            if ($kestrelKey) {
                $serverEnv = $mcpServers[$kestrelKey]["env"]
                if ($serverEnv) {
                    foreach ($key in $serverEnv.Keys) {
                        if (-not [System.Environment]::GetEnvironmentVariable($key)) {
                            [System.Environment]::SetEnvironmentVariable($key, $serverEnv[$key], "Process")
                        }
                    }
                    Write-Host "[run_agent] Loaded env from MCP config: $kestrelKey" -ForegroundColor Cyan
                }
            }
        }
    } catch {
        Write-Warning "[run_agent] Could not parse MCP config: $_"
    }
}

# ── Check ANTHROPIC_API_KEY specifically (required by kestrel agent) ─────────
if (-not $env:ANTHROPIC_API_KEY) {
    Write-Warning "[run_agent] ANTHROPIC_API_KEY not set. kestrel agent will fail. Set it with:"
    Write-Warning '  $env:ANTHROPIC_API_KEY = "sk-ant-..."'
    Write-Warning "  or add it to the kestrel MCP server env in ~/.claude.json"
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

if ($Headless) {
    Write-Host "[run_agent] Headless mode — HITL gates auto-confirm (stdin non-TTY)" -ForegroundColor Yellow
}

if ($LogFile) {
    $logDir = Split-Path $LogFile -Parent
    if ($logDir -and -not (Test-Path $logDir)) { New-Item -ItemType Directory -Force $logDir | Out-Null }
    Write-Host "[run_agent] Logging to $LogFile" -ForegroundColor Cyan
    kestrel agent $Machine --mode $Mode --model $Model --budget-tokens $BudgetTokens --max-iter $MaxIter --verbose 2>&1 | Tee-Object -FilePath $LogFile
} else {
    kestrel agent $Machine --mode $Mode --model $Model --budget-tokens $BudgetTokens --max-iter $MaxIter --verbose
}
