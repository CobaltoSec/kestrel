"""Tests for kestrel.mcp.tools.state — state_read/write/append/session_dir."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp.tools import state as state_tools


@pytest.fixture
def fresh_ctx(tmp_path: Path):
    mcp_context.reset_context()
    ctx = mcp_context.ServerContext.from_paths(
        state_dir=tmp_path / "state",
        session_root=tmp_path / "sessions",
    )
    mcp_context.set_context(ctx)
    yield ctx
    mcp_context.reset_context()


# ── state_read ──────────────────────────────────────────────────────────────


def test_state_read_empty_top_level(fresh_ctx):
    result = asyncio.run(state_tools.state_read())
    assert result["agent"] == "htb"
    assert result["machines"] == []
    assert result["run_count"] == 0
    assert result["current_phase"] is None


def test_state_read_specific_missing_machine(fresh_ctx):
    result = asyncio.run(state_tools.state_read(machine="ghost"))
    assert result["error"] == "machine_not_found"
    assert result["machine"] == "ghost"


# ── state_write_machine ─────────────────────────────────────────────────────


def test_state_write_machine_creates_new(fresh_ctx):
    result = asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "machine_os": "Linux"}
        )
    )
    assert result["machine"] == "lame"
    assert result["state"]["machine_id"] == 1
    assert result["state"]["machine_os"] == "Linux"


def test_state_write_machine_merges_existing(fresh_ctx):
    asyncio.run(state_tools.state_write_machine(machine="lame", patch={"machine_id": 1}))
    result = asyncio.run(
        state_tools.state_write_machine(machine="lame", patch={"target_ip": "10.10.10.3"})
    )
    assert result["state"]["machine_id"] == 1
    assert result["state"]["target_ip"] == "10.10.10.3"


def test_state_read_after_write_shows_machine(fresh_ctx):
    asyncio.run(state_tools.state_write_machine(machine="lame", patch={"machine_id": 1}))
    top = asyncio.run(state_tools.state_read())
    assert "lame" in top["machines"]
    specific = asyncio.run(state_tools.state_read(machine="lame"))
    assert specific["state"]["machine_id"] == 1


# ── state_session_dir ───────────────────────────────────────────────────────


def test_state_session_dir_creates_with_generated_slug(fresh_ctx):
    result = asyncio.run(state_tools.state_session_dir(machine="lame"))
    assert Path(result["session_dir"]).exists()
    assert "lame" in result["session_dir"]
    assert result["machine"] == "lame"


def test_state_session_dir_uses_existing_slug(fresh_ctx):
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-custom-slug"}
        )
    )
    result = asyncio.run(state_tools.state_session_dir(machine="lame"))
    assert result["session_dir"].endswith("htb-custom-slug")
    assert Path(result["session_dir"]).exists()


# ── state_append_event ──────────────────────────────────────────────────────


def test_state_append_event_no_context_raises(fresh_ctx):
    with pytest.raises(ValueError, match="No machine specified"):
        asyncio.run(state_tools.state_append_event(phase="p0", event="test"))


def test_state_append_event_writes_jsonl(fresh_ctx):
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test-lame"}
        )
    )
    result = asyncio.run(
        state_tools.state_append_event(
            phase="p1_recon", event="nmap_start", detail="-sV -p-", machine="lame"
        )
    )
    assert "session_dir" in result
    jsonl = Path(result["session_dir"]) / "sessions.jsonl"
    assert jsonl.exists()
    lines = [ln for ln in jsonl.read_text(encoding="utf-8").strip().split("\n") if ln]
    assert len(lines) == 1
    evt = json.loads(lines[0])
    assert evt["event"] == "nmap_start"
    assert evt["detail"] == "-sV -p-"
    assert evt["phase"] == "p1_recon"


def test_state_append_event_uses_current_session_fallback(fresh_ctx):
    # Write a machine + set current_session to its slug
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-fallback-test"}
        )
    )
    fresh_ctx.state_store.set_current_phase("p1", session_slug="htb-fallback-test")
    result = asyncio.run(state_tools.state_append_event(phase="p1", event="fallback_test"))
    assert "htb-fallback-test" in result["session_dir"]


# ── state_write_machine validation (IMP-04) ─────────────────────────────────


def test_state_write_machine_invalid_name_xss(fresh_ctx):
    result = asyncio.run(
        state_tools.state_write_machine(
            machine="<script>alert(1)</script>", patch={"machine_id": 1}
        )
    )
    assert result["error"] == "invalid_machine_name"


def test_state_write_machine_invalid_name_ssti(fresh_ctx):
    result = asyncio.run(
        state_tools.state_write_machine(
            machine="{{7*7}}", patch={"machine_id": 1}
        )
    )
    assert result["error"] == "invalid_machine_name"


def test_state_write_machine_invalid_name_empty(fresh_ctx):
    result = asyncio.run(
        state_tools.state_write_machine(
            machine="", patch={"machine_id": 1}
        )
    )
    assert result["error"] == "invalid_machine_name"


def test_state_write_machine_valid_name(fresh_ctx):
    result = asyncio.run(
        state_tools.state_write_machine(
            machine="reactor", patch={"machine_id": 900}
        )
    )
    assert "error" not in result
    assert result["machine"] == "reactor"


def test_state_write_machine_valid_name_with_dash(fresh_ctx):
    result = asyncio.run(
        state_tools.state_write_machine(
            machine="my-machine", patch={"machine_id": 42}
        )
    )
    assert "error" not in result
    assert result["machine"] == "my-machine"


# ── V08: session_slug persistence ───────────────────────────────────────────


def test_resolve_session_dir_persists_generated_slug(fresh_ctx):
    """_resolve_session_dir auto-persists the generated slug to machine state."""
    asyncio.run(state_tools.state_session_dir(machine="lame"))
    m = fresh_ctx.state_store.get_machine("lame")
    assert m is not None
    assert m.session_slug is not None
    assert "lame" in m.session_slug


def test_resolve_session_dir_stable_across_calls(fresh_ctx):
    """Second call returns same slug (reads from persisted state)."""
    r1 = asyncio.run(state_tools.state_session_dir(machine="lame"))
    r2 = asyncio.run(state_tools.state_session_dir(machine="lame"))
    assert r1["session_dir"] == r2["session_dir"]
