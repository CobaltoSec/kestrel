"""MCP tools — stuck detection + heartbeat dashboard (wrap core modules)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kestrel.core import heartbeat as core_heartbeat
from kestrel.core import stuck as core_stuck
from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.mcp.tools.state import _resolve_session_dir


@registry.tool(
    name="stuck_check",
    description=(
        "Run stuck signal detection over a machine's session_dir. Returns ranked signals + recommendation + alternatives. "
        "Recommendations: continue / switch_vpn_server / reset_listener / escalate_gpu / switch_vector."
    ),
    category="heartbeat",
)
async def stuck_check(machine: str) -> dict[str, Any]:
    session_dir = _resolve_session_dir(machine)
    estado_path = session_dir / "estado.md"
    findings_path = session_dir / "findings.md"
    jsonl_path = session_dir / "sessions.jsonl"

    def _do() -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        estado = core_stuck.read_file_safe(estado_path)
        findings = core_stuck.read_file_safe(findings_path)
        jsonl = core_stuck.read_jsonl(jsonl_path)

        signals: list[str] = []
        if core_stuck.detect_lab_unstable(jsonl, now):
            signals.append("lab_unstable")
        if core_stuck.detect_shell_lost(estado, findings):
            signals.append("shell_lost")
        if core_stuck.detect_hash_stuck(estado, jsonl):
            signals.append("hash_stuck")
        if core_stuck.detect_cred_exhausted(estado, jsonl):
            signals.append("cred_exhausted")
        if core_stuck.detect_progress_stalled(estado_path, findings_path, jsonl_path, now):
            signals.append("progress_stalled")

        recommendation, alternatives, rationale = core_stuck.recommend(signals, findings, session_dir)
        return {
            "session_dir": str(session_dir),
            "signals": signals,
            "recommendation": recommendation,
            "alternatives": alternatives,
            "rationale": rationale,
        }

    return await asyncio.to_thread(_do)


@registry.tool(
    name="heartbeat_status",
    description=(
        "Compute the full session dashboard: elapsed_min, budget_min, idle_min, top_time_sinks, suggestion. "
        "Wraps core.heartbeat.emit_dashboard_data. Returns the dashboard dict."
    ),
    category="heartbeat",
)
async def heartbeat_status(machine: str) -> dict[str, Any]:
    ctx = mcp_context.get_context()
    session_dir = _resolve_session_dir(machine)
    state_file = ctx.state_dir / "last-cycle.json"

    def _do() -> dict[str, Any]:
        return core_heartbeat.emit_dashboard_data(
            session_dir=session_dir,
            state_file=state_file,
        )

    return await asyncio.to_thread(_do)
