"""Tests for kestrel.mcp.tools.session — open/exec/close/list with stub session class."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp.tools import session as session_tools
from kestrel.transport.base import ExecResult, Session


class StubSession(Session):
    """Pure-Python session for testing — no network."""

    def __init__(self, handle_id: str = "stub-1") -> None:
        self.handle_id = handle_id
        self.opened = False
        self.closed = False
        self.last_cmd: str | None = None

    def open(self) -> None:
        self.opened = True

    def exec(self, cmd: str, timeout: float = 120.0) -> ExecResult:
        self.last_cmd = cmd
        return ExecResult(stdout=f"executed:{cmd}", stderr="", rc=0, duration_s=0.01)

    def close(self) -> None:
        self.closed = True


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


def test_session_open_ssh_with_mock_session_class(fresh_ctx, monkeypatch):
    # Replace SSHSession with our StubSession so we don't open a real socket
    captured: dict[str, Any] = {}

    class FakeSSH(StubSession):
        def __init__(self, **kwargs):
            super().__init__(handle_id="ssh-fake")
            captured.update(kwargs)

    monkeypatch.setattr(session_tools, "SSHSession", FakeSSH)
    result = asyncio.run(
        session_tools.session_open(
            transport="ssh",
            params={"host": "kali", "user": "kali", "key_path": "~/.ssh/x"},
        )
    )
    assert result["handle_id"] == "ssh-fake"
    assert result["transport"] == "ssh"
    assert captured["host"] == "kali"


def test_session_open_invalid_transport(fresh_ctx):
    result = asyncio.run(session_tools.session_open(transport="telnet", params={}))
    assert result["error"] == "invalid_transport"


def test_session_open_handles_open_failure(fresh_ctx, monkeypatch):
    class BrokenSSH(StubSession):
        def __init__(self, **kwargs):
            super().__init__(handle_id="ssh-broken")

        def open(self):
            raise ConnectionRefusedError("nope")

    monkeypatch.setattr(session_tools, "SSHSession", BrokenSSH)
    result = asyncio.run(
        session_tools.session_open(
            transport="ssh", params={"host": "down", "user": "u"}
        )
    )
    assert result["error"] == "open_failed"


def test_session_exec_unknown_handle(fresh_ctx):
    result = asyncio.run(session_tools.session_exec(handle_id="ghost", cmd="id"))
    assert result["error"] == "unknown_handle"


def test_session_exec_returns_execresult_fields(fresh_ctx, monkeypatch):
    class FakeSSH(StubSession):
        def __init__(self, **kwargs):
            super().__init__(handle_id="ssh-x")

    monkeypatch.setattr(session_tools, "SSHSession", FakeSSH)
    asyncio.run(
        session_tools.session_open(transport="ssh", params={"host": "x", "user": "x"})
    )
    res = asyncio.run(session_tools.session_exec(handle_id="ssh-x", cmd="whoami"))
    assert res["rc"] == 0
    assert res["stdout"] == "executed:whoami"


def test_session_list_starts_empty(fresh_ctx):
    result = asyncio.run(session_tools.session_list())
    assert result["count"] == 0


def test_session_list_after_open(fresh_ctx, monkeypatch):
    class FakeSSH(StubSession):
        def __init__(self, **kwargs):
            super().__init__(handle_id="ssh-list")

    monkeypatch.setattr(session_tools, "SSHSession", FakeSSH)
    asyncio.run(session_tools.session_open(transport="ssh", params={"host": "h", "user": "u"}))
    listed = asyncio.run(session_tools.session_list())
    assert listed["count"] == 1
    assert listed["handles"][0]["handle_id"] == "ssh-list"


def test_session_close_removes_from_registry(fresh_ctx, monkeypatch):
    class FakeSSH(StubSession):
        def __init__(self, **kwargs):
            super().__init__(handle_id="ssh-close")

    monkeypatch.setattr(session_tools, "SSHSession", FakeSSH)
    asyncio.run(session_tools.session_open(transport="ssh", params={"host": "h", "user": "u"}))
    close_res = asyncio.run(session_tools.session_close(handle_id="ssh-close"))
    assert close_res["closed"] is True
    listed = asyncio.run(session_tools.session_list())
    assert listed["count"] == 0


def test_session_close_unknown_handle(fresh_ctx):
    result = asyncio.run(session_tools.session_close(handle_id="ghost"))
    assert result["error"] == "unknown_handle"


def test_session_exec_timeout_string_coercion(fresh_ctx, monkeypatch):
    """session_exec must accept timeout as string (MCP JSON delivers numbers as strings sometimes)."""
    received_timeout: list[float] = []

    class FakeSSH(StubSession):
        def __init__(self, **kwargs):
            super().__init__(handle_id="ssh-coerce")

        def exec(self, cmd: str, timeout: float = 120.0) -> ExecResult:
            received_timeout.append(timeout)
            return ExecResult(stdout="ok", stderr="", rc=0, duration_s=0.01)

    monkeypatch.setattr(session_tools, "SSHSession", FakeSSH)
    asyncio.run(session_tools.session_open(transport="ssh", params={"host": "h", "user": "u"}))
    res = asyncio.run(session_tools.session_exec(handle_id="ssh-coerce", cmd="id", timeout="30"))
    assert res["rc"] == 0
    assert isinstance(received_timeout[0], float)
    assert received_timeout[0] == 30.0


def test_session_upload_success(fresh_ctx, monkeypatch):
    uploaded: dict = {}

    class FakeSSH(StubSession):
        def __init__(self, **kwargs):
            super().__init__(handle_id="ssh-upload")

        def upload_string(self, content: str, remote_path: str) -> None:
            uploaded["content"] = content
            uploaded["path"] = remote_path

    monkeypatch.setattr(session_tools, "SSHSession", FakeSSH)
    asyncio.run(session_tools.session_open(transport="ssh", params={"host": "h", "user": "u"}))
    res = asyncio.run(session_tools.session_upload(
        handle_id="ssh-upload", content="print('hello')", remote_path="/tmp/test.py"
    ))
    assert res["uploaded"] is True
    assert res["remote_path"] == "/tmp/test.py"
    assert uploaded["content"] == "print('hello')"


def test_session_upload_unknown_handle(fresh_ctx):
    res = asyncio.run(session_tools.session_upload(
        handle_id="ghost", content="x", remote_path="/tmp/x"
    ))
    assert res["error"] == "unknown_handle"


def test_session_upload_unsupported_transport(fresh_ctx, monkeypatch):
    """Sessions without upload_string return upload_not_supported."""

    class FakeSSH(StubSession):
        def __init__(self, **kwargs):
            super().__init__(handle_id="ssh-noup")

    monkeypatch.setattr(session_tools, "SSHSession", FakeSSH)
    asyncio.run(session_tools.session_open(transport="ssh", params={"host": "h", "user": "u"}))
    res = asyncio.run(session_tools.session_upload(
        handle_id="ssh-noup", content="x", remote_path="/tmp/x"
    ))
    assert res["error"] == "upload_not_supported"
