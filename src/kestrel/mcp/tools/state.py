"""MCP tools — state read/write + session events.

These are the foundational tools every other Kestrel tool depends on. They
expose the StateStore to MCP clients (LLMs) without letting them write the
JSON files directly.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry

_MACHINE_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{0,48}$')


def _resolve_session_dir(machine: str | None = None) -> Path:
    """Resolve <session_root>/<session_slug> for the given machine.

    Rules:
        - If ``machine`` given and has ``session_slug`` set → use it.
        - If ``machine`` given but no slug → generate ``htb-YYYY-MM-DD-<machine>``.
        - If ``machine`` is None → fall back to ``state.data.current_session``.
        - If neither resolves → raise ValueError (caller must supply context).
    """
    ctx = mcp_context.get_context()
    if machine is None:
        state = ctx.state_store.read()
        sess = state.data.current_session
        if sess:
            return ctx.session_root / sess
        raise ValueError("No machine specified and no current_session set in state")
    m = ctx.state_store.get_machine(machine)
    if m and m.session_slug:
        return ctx.session_root / m.session_slug
    slug = f"htb-{datetime.now().strftime('%Y-%m-%d')}-{machine}"
    ctx.state_store.update_machine(machine, {"session_slug": slug})
    return ctx.session_root / slug


@registry.tool(
    name="state_read",
    description=(
        "Read current Kestrel state. If `machine` is given, returns just that machine's slice; "
        "otherwise returns a top-level summary (run_count, phase, machine list)."
    ),
    category="state",
)
async def state_read(machine: str | None = None) -> dict[str, Any]:
    ctx = mcp_context.get_context()
    state = ctx.state_store.read()
    if machine:
        m = state.data.machines.get(machine)
        if m is None:
            return {"error": "machine_not_found", "machine": machine}
        return {"machine": machine, "state": m.model_dump(mode="json", exclude_none=True)}
    return {
        "agent": state.agent,
        "last_run": state.last_run,
        "cycle_id": state.cycle_id,
        "run_count": state.run_count,
        "current_phase": state.data.current_phase,
        "current_session": state.data.current_session,
        "machines": list(state.data.machines.keys()),
    }


@registry.tool(
    name="state_write_machine",
    description=(
        "Patch a machine's state by shallow-merging `patch` into machines[machine]. "
        "Creates the entry if absent. Returns the merged state."
    ),
    category="state",
    input_schema={
        "type": "object",
        "properties": {
            "machine": {
                "type": "string",
                "description": "Machine slug (e.g. 'lame').",
                "pattern": "^[a-z0-9][a-z0-9\\-]{0,48}$",
            },
            "patch": {
                "type": "object",
                "description": "Partial MachineState fields to merge (e.g. target_ip, htb_mode, user_owned).",
            },
        },
        "required": ["machine", "patch"],
    },
)
async def state_write_machine(machine: str, patch: dict[str, Any]) -> dict[str, Any]:
    if not _MACHINE_SLUG_RE.match(machine):
        return {
            "error": "invalid_machine_name",
            "reason": f"Machine name '{machine[:50]}' contiene caracteres inválidos. Usar solo [a-z0-9-] max 49 chars.",
            "machine": machine[:50],
        }
    ctx = mcp_context.get_context()
    merged = ctx.state_store.update_machine(machine, patch)
    return {
        "machine": machine,
        "state": merged.model_dump(mode="json", exclude_none=True),
    }


@registry.tool(
    name="state_append_event",
    description=(
        "Append an audit event to <session_dir>/sessions.jsonl. session_dir is resolved from "
        "the given `machine` (via its session_slug) or, if absent, from state.current_session."
    ),
    category="state",
)
async def state_append_event(
    phase: str,
    event: str,
    detail: str | None = None,
    machine: str | None = None,
) -> dict[str, Any]:
    ctx = mcp_context.get_context()
    session_dir = _resolve_session_dir(machine)
    evt = ctx.state_store.append_session_event(
        session_dir, phase=phase, event=event, detail=detail
    )
    return {
        "session_dir": str(session_dir),
        "event": evt.model_dump(mode="json", exclude_none=True),
    }


@registry.tool(
    name="state_session_dir",
    description="Resolve the session directory for a machine and ensure it exists. Returns the absolute path.",
    category="state",
)
async def state_session_dir(machine: str) -> dict[str, Any]:
    session_dir = _resolve_session_dir(machine)
    session_dir.mkdir(parents=True, exist_ok=True)
    return {"machine": machine, "session_dir": str(session_dir)}
