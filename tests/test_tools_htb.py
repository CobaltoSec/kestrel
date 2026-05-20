"""Tests for kestrel.mcp.tools.htb — HTB API v4 wrappers (mocked)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp.tools import htb as htb_tools


@pytest.fixture
def fresh_ctx(tmp_path: Path):
    mcp_context.reset_context()
    ctx = mcp_context.ServerContext.from_paths(
        state_dir=tmp_path / "state",
        session_root=tmp_path / "sessions",
    )
    mcp_context.set_context(ctx)
    htb_tools._reset_client_for_tests()
    yield ctx
    mcp_context.reset_context()
    htb_tools._reset_client_for_tests()


@pytest.fixture
def mock_client(monkeypatch):
    """Inject a MagicMock HTBClient. Tests configure return values."""
    m = MagicMock()
    monkeypatch.setattr(htb_tools, "_get_client", lambda: m)
    return m


# ── htb_list_machines ───────────────────────────────────────────────────────


def test_htb_list_machines_returns_count(fresh_ctx, mock_client):
    mock_client.list_machines.return_value = [
        {"id": 1, "name": "Lame", "os": "Linux", "difficultyText": "Easy"},
        {"id": 2, "name": "Legacy", "os": "Windows", "difficultyText": "Easy"},
    ]
    result = asyncio.run(htb_tools.htb_list_machines(status="retired"))
    assert result["count"] == 2
    assert result["machines"][0]["name"] == "Lame"
    mock_client.list_machines.assert_called_once_with("retired".lower() == "retired", None, None)


def test_htb_list_machines_passes_filters(fresh_ctx, mock_client):
    mock_client.list_machines.return_value = []
    asyncio.run(htb_tools.htb_list_machines(status="retired", difficulty="Easy", os="Linux"))
    mock_client.list_machines.assert_called_once_with(True, "Easy", "Linux")


def test_htb_list_machines_active_status_sets_retired_false(fresh_ctx, mock_client):
    mock_client.list_machines.return_value = []
    asyncio.run(htb_tools.htb_list_machines(status="active"))
    mock_client.list_machines.assert_called_once_with(False, None, None)


# ── htb_machine_info ────────────────────────────────────────────────────────


def test_htb_machine_info_returns_info(fresh_ctx, mock_client):
    mock_client.get_machine.return_value = {
        "id": 1, "name": "Lame", "os": "Linux", "ip": "10.10.10.3"
    }
    result = asyncio.run(htb_tools.htb_machine_info(slug="lame"))
    assert result["slug"] == "lame"
    assert result["info"]["ip"] == "10.10.10.3"


def test_htb_machine_info_propagates_error(fresh_ctx, mock_client):
    mock_client.get_machine.side_effect = Exception("HTB API error on /machine/profile/x: 404")
    result = asyncio.run(htb_tools.htb_machine_info(slug="ghost"))
    assert result["error"] == "htb_api_error"
    assert "404" in result["message"]


# ── htb_spawn ───────────────────────────────────────────────────────────────


def test_htb_spawn_resolves_slug_and_persists(fresh_ctx, mock_client):
    mock_client.get_machine.return_value = {
        "id": 1, "name": "Lame", "os": "Linux", "difficultyText": "Easy",
        "ip": "10.10.10.3", "retired": True,
    }
    mock_client.spawn_machine.return_value = {"message": "Playing machine."}
    result = asyncio.run(htb_tools.htb_spawn(slug="lame"))
    assert result["machine_id"] == 1
    assert result["target_ip"] == "10.10.10.3"
    mock_client.spawn_machine.assert_called_once_with(1)
    # State persisted
    m = fresh_ctx.state_store.get_machine("lame")
    assert m is not None
    assert m.machine_id == 1
    assert m.target_ip == "10.10.10.3"
    assert m.machine_os == "Linux"


def test_htb_spawn_machine_not_found(fresh_ctx, mock_client):
    mock_client.get_machine.return_value = {"name": "ghost"}  # no id
    result = asyncio.run(htb_tools.htb_spawn(slug="ghost"))
    assert result["error"] == "machine_not_found"


# ── htb_release ─────────────────────────────────────────────────────────────


def test_htb_release_resolves_and_calls(fresh_ctx, mock_client):
    mock_client.get_machine.return_value = {"id": 1, "name": "Lame"}
    mock_client.release_machine.return_value = {"message": "Terminated."}
    result = asyncio.run(htb_tools.htb_release(slug="lame"))
    assert result["machine_id"] == 1
    mock_client.release_machine.assert_called_once_with(1)


# ── htb_submit_flag ─────────────────────────────────────────────────────────


def test_htb_submit_flag_user_marks_owned(fresh_ctx, mock_client):
    mock_client.get_machine.return_value = {"id": 1, "name": "Lame"}
    mock_client.submit_flag.return_value = {"status": "owned"}
    result = asyncio.run(
        htb_tools.htb_submit_flag(slug="lame", flag="abc123", flag_type="user")
    )
    assert result["flag_type"] == "user"
    m = fresh_ctx.state_store.get_machine("lame")
    assert m is not None and m.user_owned is True
    assert m.root_owned is False


def test_htb_submit_flag_root_marks_owned(fresh_ctx, mock_client):
    mock_client.get_machine.return_value = {"id": 1, "name": "Lame"}
    mock_client.submit_flag.return_value = {"status": "owned"}
    asyncio.run(htb_tools.htb_submit_flag(slug="lame", flag="root123", flag_type="root"))
    m = fresh_ctx.state_store.get_machine("lame")
    assert m is not None and m.root_owned is True


def test_htb_submit_flag_passes_difficulty(fresh_ctx, mock_client):
    mock_client.get_machine.return_value = {"id": 1, "name": "Lame"}
    mock_client.submit_flag.return_value = {}
    asyncio.run(htb_tools.htb_submit_flag(slug="lame", flag="x", flag_type="user", difficulty=80))
    mock_client.submit_flag.assert_called_once_with(1, "x", 80)


# ── htb_profile_update ──────────────────────────────────────────────────────


def test_htb_profile_update_persists_to_state_dir(fresh_ctx, mock_client):
    mock_client.get_profile.return_value = {
        "id": 42, "name": "Cobalt0", "rank": "Hacker", "points": 1000, "user_owns": 10
    }
    result = asyncio.run(htb_tools.htb_profile_update())
    assert result["profile"]["name"] == "Cobalt0"
    profile_path = Path(result["profile_path"])
    assert profile_path.exists()
    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert data["name"] == "Cobalt0"
    assert data["points"] == 1000


# ── Error wrapping ──────────────────────────────────────────────────────────


def test_error_wrap_token_missing(fresh_ctx, mock_client):
    mock_client.list_machines.side_effect = Exception("HTB token not found at ~/.htb/token")
    result = asyncio.run(htb_tools.htb_list_machines())
    assert result["error"] == "htb_token_missing"
