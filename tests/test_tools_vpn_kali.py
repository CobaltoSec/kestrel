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


# ── kali vm lifecycle ────────────────────────────────────────────────────────


@pytest.fixture
def mock_vmrun(monkeypatch):
    """Mock _vmrun_exec and kali_proxy for VM lifecycle tools."""
    calls: list[list[str]] = []
    return_map: dict[str, dict] = {}

    def fake_vmrun(args: list[str]) -> dict:
        calls.append(args)
        key = args[0] if args else ""
        return return_map.get(key, {"rc": 0, "stdout": "", "stderr": ""})

    monkeypatch.setattr("kestrel.mcp.tools.kali._vmrun_exec", fake_vmrun)
    monkeypatch.setattr("kestrel.mcp.tools.kali.kali_proxy.close_default_session", lambda: None)
    return {"calls": calls, "map": return_map}


def test_kali_vm_status_running(fresh_ctx, mock_vmrun):
    vmx = kali_tools._get_vmx()
    mock_vmrun["map"]["list"] = {"rc": 0, "stdout": f"Total running VMs: 1\n{vmx}", "stderr": ""}
    mock_vmrun["map"]["getGuestIPAddress"] = {"rc": 0, "stdout": "192.168.179.137", "stderr": ""}
    result = asyncio.run(kali_tools.kali_vm_status())
    assert result["running"] is True
    assert result["ip"] == "192.168.179.137"


def test_kali_vm_status_not_running(fresh_ctx, mock_vmrun):
    mock_vmrun["map"]["list"] = {"rc": 0, "stdout": "Total running VMs: 0", "stderr": ""}
    result = asyncio.run(kali_tools.kali_vm_status())
    assert result["running"] is False
    assert result["ip"] is None


def test_kali_vm_up_already_running(fresh_ctx, mock_vmrun, monkeypatch):
    vmx = kali_tools._get_vmx()
    mock_vmrun["map"]["list"] = {"rc": 0, "stdout": vmx, "stderr": ""}
    # Mock via_kali to succeed immediately
    monkeypatch.setattr(
        "kestrel.mcp.tools.kali.kali_proxy.via_kali",
        lambda cmd, timeout=5.0: __import__("kestrel.transport.base", fromlist=["ExecResult"]).ExecResult(
            stdout="ok", stderr="", rc=0, duration_s=0.1
        ),
    )
    result = asyncio.run(kali_tools.kali_vm_up())
    assert result["started"] is True
    assert result["reachable"] is True
    assert result["stdout"] == "already_running"
    # vmrun start should NOT have been called
    assert not any(a[0] == "start" for a in mock_vmrun["calls"])


def test_kali_vm_up_boots_and_waits(fresh_ctx, mock_vmrun, monkeypatch):
    mock_vmrun["map"]["list"] = {"rc": 0, "stdout": "Total running VMs: 0", "stderr": ""}
    mock_vmrun["map"]["start"] = {"rc": 0, "stdout": "", "stderr": ""}

    from kestrel.transport.base import ExecResult
    monkeypatch.setattr(
        "kestrel.mcp.tools.kali.kali_proxy.via_kali",
        lambda cmd, timeout=5.0: ExecResult(stdout="ok", stderr="", rc=0, duration_s=0.1),
    )
    monkeypatch.setattr("kestrel.mcp.tools.kali.asyncio.sleep", lambda _: asyncio.coroutine(lambda: None)())

    result = asyncio.run(kali_tools.kali_vm_up())
    assert result["started"] is True
    assert result["reachable"] is True
    assert any(a[0] == "start" for a in mock_vmrun["calls"])


def test_kali_vm_up_start_fails(fresh_ctx, mock_vmrun):
    mock_vmrun["map"]["list"] = {"rc": 0, "stdout": "Total running VMs: 0", "stderr": ""}
    mock_vmrun["map"]["start"] = {"rc": 1, "stdout": "", "stderr": "Error: VM not found"}
    result = asyncio.run(kali_tools.kali_vm_up())
    assert result["started"] is False
    assert result["reachable"] is False


def test_kali_vm_down(fresh_ctx, mock_vmrun):
    mock_vmrun["map"]["stop"] = {"rc": 0, "stdout": "", "stderr": ""}
    result = asyncio.run(kali_tools.kali_vm_down())
    assert result["stopped"] is True
    assert any(a[0] == "stop" for a in mock_vmrun["calls"])


def test_kali_vm_down_failure(fresh_ctx, mock_vmrun):
    mock_vmrun["map"]["stop"] = {"rc": 255, "stdout": "", "stderr": "VM not powered on"}
    result = asyncio.run(kali_tools.kali_vm_down())
    assert result["stopped"] is False


# ── kali SSH health ───────────────────────────────────────────────────────────


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
