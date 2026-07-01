"""Tests for kestrel.agent — bridge, metrics, loop basics."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kestrel.agent.bridge import load_tools_for_anthropic
from kestrel.agent.metrics import RunMetrics
from kestrel.mcp import context as mcp_context
from kestrel.mcp.server import _load_handler_modules


@pytest.fixture(autouse=True)
def fresh_registry(tmp_path):
    mcp_context.reset_context()
    ctx = mcp_context.ServerContext.from_paths(
        state_dir=tmp_path / "state",
        session_root=tmp_path / "sessions",
    )
    mcp_context.set_context(ctx)
    _load_handler_modules()
    yield ctx
    mcp_context.reset_context()


# ── bridge ────────────────────────────────────────────────────────────────────


def test_bridge_returns_tool_list(fresh_registry):
    tools = load_tools_for_anthropic()
    assert len(tools) > 10, "Should expose most registered MCP tools"
    names = {t["name"] for t in tools}
    # request_user_confirmation must be excluded (loop handles HITL natively)
    assert "request_user_confirmation" not in names
    # Core tools must be present
    for required in ("recon_nmap_scan", "intel_classify_blind", "stuck_check", "htb_spawn"):
        assert required in names, f"{required} missing from agent tool list"


def test_bridge_tool_schema_shape(fresh_registry):
    tools = load_tools_for_anthropic()
    for t in tools:
        assert "name" in t
        assert "description" in t
        assert "input_schema" in t
        assert t["input_schema"]["type"] == "object"


def test_bridge_custom_exclude(fresh_registry):
    tools = load_tools_for_anthropic(exclude={"recon_nmap_scan"})
    names = {t["name"] for t in tools}
    assert "recon_nmap_scan" not in names


# ── metrics ───────────────────────────────────────────────────────────────────


def test_metrics_record_flag_user(tmp_path):
    m = RunMetrics(machine="kobold", mode="blind", provider="anthropic")
    m.record_flag("user")
    assert m.user_flag_at is not None
    assert m.time_to_user_flag_min is not None
    assert m.time_to_user_flag_min >= 0.0


def test_metrics_finish(tmp_path):
    m = RunMetrics(machine="kobold", mode="blind", provider="anthropic")
    m.finish("owned")
    assert m.outcome == "owned"
    assert m.finished_at is not None


def test_metrics_save_and_load(tmp_path):
    m = RunMetrics(machine="kobold", mode="blind", provider="anthropic")
    m.tools_called = 12
    m.stuck_events = 2
    m.finish("owned")
    path = m.save(tmp_path / "runs", "htb-2026-07-01-kobold")
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["machine"] == "kobold"
    assert data["tools_called"] == 12
    assert data["outcome"] == "owned"


def test_metrics_to_dict_complete():
    m = RunMetrics(machine="lame", mode="blind", provider="anthropic")
    d = m.to_dict()
    for key in ("machine", "mode", "provider", "started_at", "iterations",
                "tools_called", "stuck_events", "hitl_gates", "tokens_input",
                "tokens_output", "outcome", "vector_chosen"):
        assert key in d, f"Missing key: {key}"


# ── loop (unit — no real API calls) ──────────────────────────────────────────


def test_react_agent_init(tmp_path, fresh_registry):
    from kestrel.agent.loop import ReActAgent

    with patch("anthropic.Anthropic"):
        ag = ReActAgent(
            machine="lame",
            mode="blind",
            state_dir=tmp_path / "state",
            session_root=tmp_path / "sessions",
            api_key="sk-test",
        )
    assert ag.machine == "lame"
    assert ag.mode == "blind"
    assert len(ag._tools) > 10


def test_react_agent_initial_prompt(tmp_path, fresh_registry):
    from kestrel.agent.loop import ReActAgent

    with patch("anthropic.Anthropic"):
        ag = ReActAgent(
            machine="lame",
            state_dir=tmp_path / "state",
            session_root=tmp_path / "sessions",
            api_key="sk-test",
        )
    prompt = ag._initial_prompt()
    assert "lame" in prompt
    assert "phase_enter" in prompt


def test_react_agent_parse_inline_hitl(tmp_path, fresh_registry):
    from kestrel.agent.loop import ReActAgent

    with patch("anthropic.Anthropic"):
        ag = ReActAgent(
            machine="lame",
            state_dir=tmp_path / "state",
            session_root=tmp_path / "sessions",
            api_key="sk-test",
        )

    text_with_hitl = (
        'I need confirmation before exploiting.\n'
        '{"_agent_hitl": true, "gate": "vector_confirm", "question": "Proceed?", "options": ["yes", "no"]}\n'
        'Waiting for operator.'
    )
    hitl = ag._parse_inline_hitl(text_with_hitl)
    assert hitl is not None
    assert hitl["gate"] == "vector_confirm"

    text_no_hitl = "Let me run nmap first."
    assert ag._parse_inline_hitl(text_no_hitl) is None


def test_react_agent_execute_tool_unknown(tmp_path, fresh_registry):
    from kestrel.agent.loop import ReActAgent

    with patch("anthropic.Anthropic"):
        ag = ReActAgent(
            machine="lame",
            state_dir=tmp_path / "state",
            session_root=tmp_path / "sessions",
            api_key="sk-test",
        )
    result = asyncio.run(ag._execute_tool("nonexistent_tool", {}))
    assert "error" in result
    assert "unknown_tool" in result["error"]


def test_react_agent_run_budget_exceeded(tmp_path, fresh_registry):
    """Agent exits immediately when budget is 0 tokens."""
    from kestrel.agent.loop import ReActAgent

    # Fake Anthropic response that uses tokens
    fake_usage = MagicMock()
    fake_usage.input_tokens = 999_999
    fake_usage.output_tokens = 1

    fake_resp = MagicMock()
    fake_resp.content = []
    fake_resp.usage = fake_usage
    fake_resp.stop_reason = "end_turn"

    with patch("anthropic.Anthropic") as MockAnthropicClass:
        mock_client = MagicMock()
        mock_client.messages.create.return_value = fake_resp
        MockAnthropicClass.return_value = mock_client

        ag = ReActAgent(
            machine="lame",
            mode="blind",
            budget_tokens=1,  # immediate exhaustion
            state_dir=tmp_path / "state",
            session_root=tmp_path / "sessions",
            api_key="sk-test",
        )
        # Pre-seed tokens so first check triggers
        ag._metrics.tokens_input = 1
        metrics = ag.run()

    assert metrics.outcome in ("budget_exceeded", "abandoned", "error", "max_iterations")


# ── _result_has_new_findings (M3) ────────────────────────────────────────────


def test_result_has_new_findings_zero_success_count():
    from kestrel.agent.loop import _result_has_new_findings
    assert _result_has_new_findings({"success_count": 0, "successes": []}) is False


def test_result_has_new_findings_zero_discovered():
    from kestrel.agent.loop import _result_has_new_findings
    assert _result_has_new_findings({"discovered_count": 0}) is False


def test_result_has_new_findings_found_none():
    from kestrel.agent.loop import _result_has_new_findings
    assert _result_has_new_findings({"found": None, "tries": []}) is False


def test_result_has_new_findings_error():
    from kestrel.agent.loop import _result_has_new_findings
    assert _result_has_new_findings({"error": "ssh timeout"}) is False


def test_result_has_new_findings_real_hit():
    from kestrel.agent.loop import _result_has_new_findings
    assert _result_has_new_findings({"success_count": 1, "hits": [{"user": "admin", "password": "x"}]}) is True


def test_result_has_new_findings_text_result():
    from kestrel.agent.loop import _result_has_new_findings
    assert _result_has_new_findings({"output": "nmap scan complete", "ports": [22, 80]}) is True


def test_result_has_new_findings_nmap_no_open_ports():
    from kestrel.agent.loop import _result_has_new_findings
    nmap_all_closed = {
        "hosts": [{"address": "10.10.10.1", "status": "up", "ports": [
            {"port": 80, "state": "filtered"},
            {"port": 443, "state": "closed"},
        ]}],
        "host_count": 1,
    }
    assert _result_has_new_findings(nmap_all_closed) is False


def test_result_has_new_findings_nmap_with_open_port():
    from kestrel.agent.loop import _result_has_new_findings
    nmap_has_open = {
        "hosts": [{"address": "10.10.10.1", "status": "up", "ports": [
            {"port": 22, "state": "open", "service": "ssh"},
            {"port": 80, "state": "open", "service": "http"},
        ]}],
        "host_count": 1,
    }
    assert _result_has_new_findings(nmap_has_open) is True
