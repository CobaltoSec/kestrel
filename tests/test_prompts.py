"""Tests for kestrel.mcp.prompts.* — verify all prompts registered + render."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.mcp.server import _load_handler_modules
from kestrel.mcp.tools import state as state_tools


@pytest.fixture
def fresh_ctx_loaded(tmp_path: Path):
    mcp_context.reset_context()
    ctx = mcp_context.ServerContext.from_paths(
        state_dir=tmp_path / "state",
        session_root=tmp_path / "sessions",
    )
    mcp_context.set_context(ctx)
    _load_handler_modules()
    yield ctx
    mcp_context.reset_context()


EXPECTED_PROMPTS = (
    "kestrel_kickoff",
    "p0_setup",
    "p1_recon",
    "p2_vector",
    "p3_exploit",
    "p4_privesc",
    "p5_close",
    "intel_synthesis_template",
    "hint_generation",
    "debrief_template",
)


def test_all_expected_prompts_registered(fresh_ctx_loaded):
    names = {p.name for p in registry.all_prompts()}
    missing = [n for n in EXPECTED_PROMPTS if n not in names]
    assert not missing, f"missing prompts: {missing}"


def test_kickoff_includes_kestrel_brand_and_phases(fresh_ctx_loaded):
    spec = registry.get_prompt("kestrel_kickoff")
    text = asyncio.run(spec.handler())
    assert "Kestrel" in text
    assert "p0_setup" in text
    assert "📡" in text


def test_kickoff_with_no_machines_shows_empty_state(fresh_ctx_loaded):
    text = asyncio.run(registry.get_prompt("kestrel_kickoff").handler())
    assert "ninguna máquina" in text or "ninguna" in text


def test_kickoff_includes_machine_state_when_present(fresh_ctx_loaded):
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame",
            patch={"machine_id": 1, "htb_mode": "guided", "machine_retired": True},
        )
    )
    text = asyncio.run(registry.get_prompt("kestrel_kickoff").handler())
    assert "lame" in text
    assert "guided" in text


def test_p0_setup_lists_recon_and_intel_tools(fresh_ctx_loaded):
    text = asyncio.run(registry.get_prompt("p0_setup").handler())
    assert "htb_list_machines" in text
    assert "intel_save_synthesis" in text
    assert "machine_pick" in text


def test_p2_vector_includes_vector_confirm_hitl(fresh_ctx_loaded):
    text = asyncio.run(registry.get_prompt("p2_vector").handler())
    assert "vector_confirm" in text
    assert "intel_cve_lookup" in text


def test_p5_close_lists_flag_extract_and_writeup(fresh_ctx_loaded):
    text = asyncio.run(registry.get_prompt("p5_close").handler())
    assert "flag_extract" in text
    assert "writeup_generate" in text
    assert "submit_confirm" in text


def test_intel_synthesis_template_includes_anti_spoiler(fresh_ctx_loaded):
    text = asyncio.run(registry.get_prompt("intel_synthesis_template").handler())
    assert "anti-spoiler" in text or "Prohibido" in text
    assert "confidence" in text


def test_hint_generation_uses_state_context(fresh_ctx_loaded):
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test-lame"}
        )
    )
    fresh_ctx_loaded.state_store.set_current_phase("p3_exploit", session_slug="htb-test-lame")
    text = asyncio.run(registry.get_prompt("hint_generation").handler())
    assert "p3_exploit" in text
    assert "lame" in text


def test_hint_generation_with_no_session(fresh_ctx_loaded):
    text = asyncio.run(registry.get_prompt("hint_generation").handler())
    assert "ninguna" in text or "sin sesión activa" in text


def test_debrief_template_5_sections(fresh_ctx_loaded):
    text = asyncio.run(registry.get_prompt("debrief_template").handler())
    assert "## 1." in text
    assert "## 2." in text
    assert "## 3." in text
    assert "## 4." in text
    assert "## 5." in text
