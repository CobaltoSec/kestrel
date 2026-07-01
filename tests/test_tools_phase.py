"""Tests for kestrel.mcp.tools.phase — phase_current / phase_enter."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp.tools import phase as phase_tools
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


def test_phase_current_initial_state(fresh_ctx):
    result = asyncio.run(phase_tools.phase_current())
    assert result["current_phase"] is None
    assert result["current_session"] is None
    assert result["active_machines"] == []


def test_phase_enter_valid_returns_guidance(fresh_ctx):
    result = asyncio.run(phase_tools.phase_enter(phase="p1_recon"))
    assert result["phase"] == "p1_recon"
    assert "recon_nmap_scan" in result["suggested_tools"]
    assert result["hitl_gates"] == []
    assert "Reconnaissance" in result["description"]


def test_phase_enter_persists_to_state(fresh_ctx):
    asyncio.run(phase_tools.phase_enter(phase="p2_vector"))
    result = asyncio.run(phase_tools.phase_current())
    assert result["current_phase"] == "p2_vector"


def test_phase_enter_invalid_phase(fresh_ctx):
    result = asyncio.run(phase_tools.phase_enter(phase="p99_bogus"))
    assert result["error"] == "invalid_phase"
    assert "p0_setup" in result["valid"]
    assert result["got"] == "p99_bogus"


def test_phase_enter_p2_includes_vector_confirm_hitl(fresh_ctx):
    result = asyncio.run(phase_tools.phase_enter(phase="p2_vector"))
    assert "vector_confirm" in result["hitl_gates"]
    assert "intel_cve_lookup" in result["suggested_tools"]


def test_phase_enter_p5_includes_submit_hitl(fresh_ctx):
    result = asyncio.run(phase_tools.phase_enter(phase="p5_close"))
    assert "submit_confirm" in result["hitl_gates"]
    assert "debrief" in result["hitl_gates"]
    assert "flag_extract" in result["suggested_tools"]
    assert "writeup_generate" in result["suggested_tools"]


def test_phase_current_excludes_owned_machines(fresh_ctx):
    asyncio.run(state_tools.state_write_machine(machine="active", patch={"machine_id": 1}))
    asyncio.run(
        state_tools.state_write_machine(
            machine="done", patch={"machine_id": 2, "user_owned": True, "root_owned": True}
        )
    )
    result = asyncio.run(phase_tools.phase_current())
    assert "active" in result["active_machines"]
    assert "done" not in result["active_machines"]


def test_phase_current_excludes_abandoned_machines(fresh_ctx):
    asyncio.run(
        state_tools.state_write_machine(
            machine="abandoned", patch={"machine_id": 1, "abandoned": True}
        )
    )
    result = asyncio.run(phase_tools.phase_current())
    assert "abandoned" not in result["active_machines"]


def test_phase_enter_all_six_valid_phases(fresh_ctx):
    for phase in ("p0_setup", "p1_recon", "p2_vector", "p3_exploit", "p4_privesc", "p5_close"):
        result = asyncio.run(phase_tools.phase_enter(phase=phase))
        assert "error" not in result, f"{phase} failed: {result}"
        assert result["phase"] == phase
        assert len(result["suggested_tools"]) > 0


# ── V08: progress tracking ──────────────────────────────────────────────────


def test_phase_enter_with_machine_writes_progress(fresh_ctx):
    """V08: phase_enter writes progress[phase] + last_phase_completed to machine state."""
    asyncio.run(state_tools.state_write_machine(
        machine="reactor", patch={"machine_id": 5, "session_slug": "htb-test-reactor"}
    ))
    asyncio.run(phase_tools.phase_enter(phase="p1_recon", machine="reactor"))
    m = fresh_ctx.state_store.get_machine("reactor")
    assert m is not None
    assert "p1_recon" in m.progress
    assert m.last_phase_completed == "p1_recon"


def test_phase_enter_with_machine_emits_lifecycle_event(fresh_ctx):
    """V08: phase_enter appends a phase_enter event to sessions.jsonl."""
    import json
    asyncio.run(state_tools.state_write_machine(
        machine="reactor", patch={"machine_id": 5, "session_slug": "htb-test-reactor"}
    ))
    asyncio.run(phase_tools.phase_enter(phase="p2_vector", machine="reactor"))
    session_dir = fresh_ctx.session_root / "htb-test-reactor"
    jsonl = session_dir / "sessions.jsonl"
    assert jsonl.exists()
    events = [json.loads(ln) for ln in jsonl.read_text().splitlines() if ln.strip()]
    assert any(e.get("event") == "phase_enter" and e.get("phase") == "p2_vector" for e in events)


def test_phase_enter_without_machine_still_works(fresh_ctx):
    """V08: omitting machine param behaves like before (no regression)."""
    result = asyncio.run(phase_tools.phase_enter(phase="p3_exploit"))
    assert result["phase"] == "p3_exploit"
    assert "error" not in result
