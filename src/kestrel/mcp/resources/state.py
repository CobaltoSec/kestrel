"""MCP resources — state introspection (last-cycle, sessions-jsonl, profile)."""

from __future__ import annotations

import json
from pathlib import Path

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry


@registry.resource(
    uri="kestrel://state/last-cycle",
    name="last-cycle",
    description="Top-level Kestrel state (LastCycle JSON — run_count, machines, current_phase, etc.).",
)
async def state_last_cycle(uri: str) -> str:
    ctx = mcp_context.get_context()
    state = ctx.state_store.read()
    return json.dumps(state.model_dump(mode="json", exclude_none=True), indent=2, ensure_ascii=False)


@registry.resource(
    uri="kestrel://state/sessions-jsonl",
    name="sessions-jsonl",
    description="Last 100 entries from current session's sessions.jsonl (audit log).",
)
async def state_sessions_jsonl(uri: str) -> str:
    ctx = mcp_context.get_context()
    state = ctx.state_store.read()
    sess = state.data.current_session
    if not sess:
        return json.dumps({"error": "no_current_session", "events": []})
    session_dir = ctx.session_root / sess
    events = ctx.state_store.read_session_events(session_dir, limit=100)
    return json.dumps(
        {"session": sess, "events": [e.model_dump(mode="json", exclude_none=True) for e in events]},
        indent=2,
        ensure_ascii=False,
    )


@registry.resource(
    uri="kestrel://state/profile",
    name="profile",
    description="HTB user profile snapshot (from state_dir/profile.json).",
)
async def state_profile(uri: str) -> str:
    ctx = mcp_context.get_context()
    profile_path = ctx.state_dir / "profile.json"
    if not profile_path.exists():
        return json.dumps({"error": "profile_not_fetched", "hint": "Call htb_profile_update first."})
    return profile_path.read_text(encoding="utf-8")
