"""MCP tool — narrative emission (📡 🔍 💡 ➡) to estado.md + sessions.jsonl.

The 4-stream narration is Kestrel's continuous-progress signal: the LLM emits
a line per beat, persistent for both the live operator and post-engagement
forensic reading.

Streams:
    📡  discover  — saw a new fact (port open, banner, header, file path).
    🔍  analyze   — examining / probing / parsing.
    💡  decide    — concluding / picking next step / forming hypothesis.
    ➡  advance   — moving to next action / transition.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.mcp.tools.state import _resolve_session_dir


VALID_STREAMS = ("📡", "🔍", "💡", "➡")


@registry.tool(
    name="narrate_emit",
    description=(
        "Emit a narration line (📡 discover / 🔍 analyze / 💡 decide / ➡ advance) "
        "to <session_dir>/estado.md AND <session_dir>/sessions.jsonl. "
        "machine defaults to state.current_session if omitted."
    ),
    category="narrate",
)
async def narrate_emit(
    stream: str,
    text: str,
    machine: str | None = None,
) -> dict[str, Any]:
    if stream not in VALID_STREAMS:
        return {
            "error": "invalid_stream",
            "valid": list(VALID_STREAMS),
            "got": stream,
        }
    ctx = mcp_context.get_context()
    session_dir = _resolve_session_dir(machine)
    session_dir.mkdir(parents=True, exist_ok=True)

    estado_md = session_dir / "estado.md"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"- `{ts}` {stream} {text}\n"
    with estado_md.open("a", encoding="utf-8") as f:
        f.write(line)

    state = ctx.state_store.read()
    phase = state.data.current_phase or "unknown"
    ctx.state_store.append_session_event(
        session_dir,
        phase=phase,
        event="narrate",
        detail=text,
        stream=stream,
    )
    return {
        "session_dir": str(session_dir),
        "estado_md": str(estado_md),
        "stream": stream,
        "text": text,
        "ts": ts,
    }
