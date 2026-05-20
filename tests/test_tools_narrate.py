"""Tests for kestrel.mcp.tools.narrate — narrate_emit (📡 🔍 💡 ➡)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp.tools import narrate as narrate_tools
from kestrel.mcp.tools import state as state_tools


@pytest.fixture
def fresh_ctx(tmp_path: Path):
    mcp_context.reset_context()
    ctx = mcp_context.ServerContext.from_paths(
        state_dir=tmp_path / "state",
        session_root=tmp_path / "sessions",
    )
    mcp_context.set_context(ctx)
    # Pre-create a machine so narrate can resolve session_dir
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test-lame"}
        )
    )
    yield ctx
    mcp_context.reset_context()


def test_narrate_emit_writes_estado_md(fresh_ctx):
    result = asyncio.run(
        narrate_tools.narrate_emit(stream="📡", text="descubierto smb 445", machine="lame")
    )
    estado = Path(result["estado_md"])
    assert estado.exists()
    content = estado.read_text(encoding="utf-8")
    assert "📡" in content
    assert "descubierto smb 445" in content


def test_narrate_emit_appends_session_event(fresh_ctx):
    asyncio.run(narrate_tools.narrate_emit(stream="🔍", text="testing", machine="lame"))
    jsonl = Path(fresh_ctx.session_root) / "htb-test-lame" / "sessions.jsonl"
    assert jsonl.exists()
    lines = [ln for ln in jsonl.read_text(encoding="utf-8").strip().split("\n") if ln]
    assert len(lines) == 1
    evt = json.loads(lines[0])
    assert evt["event"] == "narrate"
    assert evt["stream"] == "🔍"
    assert evt["detail"] == "testing"


def test_narrate_emit_invalid_stream(fresh_ctx):
    result = asyncio.run(narrate_tools.narrate_emit(stream="X", text="bogus", machine="lame"))
    assert result["error"] == "invalid_stream"
    assert "📡" in result["valid"]
    assert result["got"] == "X"


def test_narrate_emit_all_four_streams(fresh_ctx):
    for stream in ("📡", "🔍", "💡", "➡"):
        result = asyncio.run(
            narrate_tools.narrate_emit(stream=stream, text=f"test {stream}", machine="lame")
        )
        assert "error" not in result, f"stream {stream} failed: {result}"


def test_narrate_emit_multiple_calls_appended(fresh_ctx):
    asyncio.run(narrate_tools.narrate_emit(stream="📡", text="line1", machine="lame"))
    asyncio.run(narrate_tools.narrate_emit(stream="💡", text="line2", machine="lame"))
    asyncio.run(narrate_tools.narrate_emit(stream="➡", text="line3", machine="lame"))
    estado = Path(fresh_ctx.session_root) / "htb-test-lame" / "estado.md"
    lines = [ln for ln in estado.read_text(encoding="utf-8").strip().split("\n") if ln]
    assert len(lines) == 3
    assert "line1" in lines[0]
    assert "line2" in lines[1]
    assert "line3" in lines[2]


def test_narrate_uses_current_session_when_no_machine(fresh_ctx):
    fresh_ctx.state_store.set_current_phase("p3_exploit", session_slug="htb-test-lame")
    result = asyncio.run(narrate_tools.narrate_emit(stream="💡", text="no-machine-arg"))
    assert "htb-test-lame" in result["session_dir"]
