"""Tests for kestrel.mcp.tools.vpn + kestrel.mcp.tools.kali (mocked via_kali)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp.tools import kali as kali_tools
from kestrel.mcp.tools import state as state_tools
from kestrel.mcp.tools import vpn as vpn_tools
from kestrel.transport.base import ExecResult


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


@pytest.fixture
def mock_via_kali(monkeypatch):
    """Replace kali_proxy.via_kali with a controllable mock for both modules."""
    calls: list[tuple[str, float]] = []
    return_value = {"result": ExecResult(stdout="ok", stderr="", rc=0, duration_s=0.1)}

    def fake_via_kali(cmd: str, timeout: float = 120.0, **kwargs):
        calls.append((cmd, timeout))
        return return_value["result"]

    # Patch both modules' references
    monkeypatch.setattr("kestrel.mcp.tools.vpn.kali_proxy.via_kali", fake_via_kali)
    monkeypatch.setattr("kestrel.mcp.tools.kali.kali_proxy.via_kali", fake_via_kali)
    return {"calls": calls, "return": return_value}


# ── vpn ──────────────────────────────────────────────────────────────────────


def test_vpn_up_invokes_kali(fresh_ctx, mock_via_kali):
    result = asyncio.run(vpn_tools.vpn_up())
    assert result["rc"] == 0
    assert "up" in mock_via_kali["calls"][0][0]


def test_vpn_up_with_server(fresh_ctx, mock_via_kali):
    asyncio.run(vpn_tools.vpn_up(server="eu-vip-1"))
    cmd = mock_via_kali["calls"][0][0]
    assert "up" in cmd
    assert "eu-vip-1" in cmd


def test_vpn_up_persists_iface_state_on_success(fresh_ctx, mock_via_kali):
    # Set up a machine + current_session
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test"}
        )
    )
    fresh_ctx.state_store.set_current_phase("p0", session_slug="htb-test")
    asyncio.run(vpn_tools.vpn_up())
    m = fresh_ctx.state_store.get_machine("lame")
    assert m is not None
    assert m.vpn_iface_state == "up"


def test_vpn_down_invokes_kali(fresh_ctx, mock_via_kali):
    result = asyncio.run(vpn_tools.vpn_down())
    assert result["rc"] == 0
    assert "down" in mock_via_kali["calls"][0][0]


def test_vpn_down_persists_iface_state_on_success(fresh_ctx, mock_via_kali):
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test"}
        )
    )
    fresh_ctx.state_store.set_current_phase("p0", session_slug="htb-test")
    asyncio.run(vpn_tools.vpn_down())
    m = fresh_ctx.state_store.get_machine("lame")
    assert m is not None
    assert m.vpn_iface_state == "down"


def test_vpn_status_returns_rc_stdout(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout="tun0 UP 10.10.16.5", stderr="", rc=0, duration_s=0.05
    )
    result = asyncio.run(vpn_tools.vpn_status())
    assert "tun0 UP" in result["stdout"]
    assert result["rc"] == 0


def test_vpn_up_failure_does_not_persist(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout="", stderr="auth failed", rc=1, duration_s=0.1
    )
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test"}
        )
    )
    fresh_ctx.state_store.set_current_phase("p0", session_slug="htb-test")
    asyncio.run(vpn_tools.vpn_up())
    m = fresh_ctx.state_store.get_machine("lame")
    assert m is not None
    # vpn_iface_state should NOT have been set to "up" since rc != 0
    assert m.vpn_iface_state is None


# ── kali ─────────────────────────────────────────────────────────────────────


def test_kali_status_invokes_id_uname(fresh_ctx, mock_via_kali):
    result = asyncio.run(kali_tools.kali_status())
    assert result["rc"] == 0
    cmd = mock_via_kali["calls"][0][0]
    assert "hostname" in cmd and "uname" in cmd


def test_kali_ping_target_reachable(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout="3 received", stderr="", rc=0, duration_s=2.1
    )
    result = asyncio.run(kali_tools.kali_ping_target(target_ip="10.10.10.3"))
    assert result["reachable"] is True
    cmd = mock_via_kali["calls"][0][0]
    assert "10.10.10.3" in cmd
    assert "ping" in cmd


def test_kali_ping_target_unreachable(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout="0 received, 3 errors", stderr="", rc=1, duration_s=6.0
    )
    result = asyncio.run(kali_tools.kali_ping_target(target_ip="10.10.10.99"))
    assert result["reachable"] is False
    assert result["rc"] == 1
