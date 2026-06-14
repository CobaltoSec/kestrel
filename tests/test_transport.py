"""Tests for kestrel.transport — Session ABC, SSH, MSF RPC (mocked).

Real SSH/WinRM/MSF integration tests are gated behind ``@pytest.mark.kali``
and ``@pytest.mark.msf`` markers (env: KESTREL_KALI=1 / KESTREL_MSF=1).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from kestrel.transport import ExecResult, Session, SessionRegistry
from kestrel.transport.base import ExecResult as _ExecResult  # alias check
from kestrel.transport.msf import DEFAULT_SECRET_PATH, MSFRPCConfig, MSFRPCSession
from kestrel.transport.ssh import SSHSession, quote_cmd


# ── ExecResult + Session abstract ────────────────────────────────────────────


def test_exec_result_dataclass_fields():
    r = ExecResult(stdout="out", stderr="err", rc=0, duration_s=1.2)
    assert r.stdout == "out"
    assert r.stderr == "err"
    assert r.rc == 0
    assert r.duration_s == 1.2


def test_exec_result_alias_identity():
    assert ExecResult is _ExecResult


def test_session_is_abstract():
    with pytest.raises(TypeError):
        Session()  # type: ignore[abstract]


# ── SessionRegistry ──────────────────────────────────────────────────────────


class _DummySession(Session):
    def __init__(self, handle_id: str = "dummy-1"):
        self.handle_id = handle_id
        self.opened = False
        self.closed = False

    def open(self):
        self.opened = True

    def exec(self, cmd, timeout=120.0):
        return ExecResult(stdout=f"ran:{cmd}", stderr="", rc=0, duration_s=0.0)

    def close(self):
        self.closed = True


def test_registry_add_and_get():
    reg = SessionRegistry()
    s = _DummySession("h1")
    reg.add(s)
    assert reg.get("h1") is s
    assert reg.get("missing") is None


def test_registry_remove():
    reg = SessionRegistry()
    s = _DummySession("h2")
    reg.add(s)
    removed = reg.remove("h2")
    assert removed is s
    assert reg.get("h2") is None


def test_registry_list_handles():
    reg = SessionRegistry()
    reg.add(_DummySession("a"))
    reg.add(_DummySession("b"))
    handles = reg.list_handles()
    ids = {h["handle_id"] for h in handles}
    assert ids == {"a", "b"}


# ── SSHSession ───────────────────────────────────────────────────────────────


def test_quote_cmd_basic():
    assert quote_cmd("ls", "-la", "/tmp") == "ls -la /tmp"


def test_quote_cmd_escapes_special_chars():
    quoted = quote_cmd("cat", "/tmp/file with spaces", "&& rm -rf /")
    # shlex.quote wraps args with shell metachars in single quotes
    assert "'/tmp/file with spaces'" in quoted
    assert "'&& rm -rf /'" in quoted
    # the literal command starts with "cat " (the first arg has no special chars)
    assert quoted.startswith("cat ")


def test_ssh_session_init_defaults():
    s = SSHSession(host="10.0.0.1", user="kali")
    assert s.host == "10.0.0.1"
    assert s.user == "kali"
    assert s.port == 22
    assert s.key_path is None
    assert s.password is None
    assert s.handle_id.startswith("ssh-")


def test_ssh_session_handle_id_explicit():
    s = SSHSession(host="x", user="y", handle_id="my-handle")
    assert s.handle_id == "my-handle"


@patch("kestrel.transport.ssh.paramiko.SSHClient")
def test_ssh_open_connects_with_key(mock_client_cls, tmp_path):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    key_file = tmp_path / "id_ed25519"
    key_file.write_text("dummy", encoding="utf-8")
    s = SSHSession(host="kali.local", user="kali", key_path=str(key_file))
    s.open()

    mock_client.connect.assert_called_once()
    kwargs = mock_client.connect.call_args.kwargs
    assert kwargs["hostname"] == "kali.local"
    assert kwargs["username"] == "kali"
    assert kwargs["key_filename"] == str(key_file)
    assert kwargs["allow_agent"] is False
    assert kwargs["look_for_keys"] is False


@patch("kestrel.transport.ssh.paramiko.SSHClient")
def test_ssh_open_is_idempotent(mock_client_cls):
    s = SSHSession(host="h", user="u")
    s.open()
    s.open()
    assert mock_client_cls.call_count == 1


@patch("kestrel.transport.ssh.paramiko.SSHClient")
def test_ssh_exec_returns_exec_result(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_stdin = MagicMock()
    mock_stdout = MagicMock()
    mock_stderr = MagicMock()
    mock_stdout.read.return_value = b"hello\n"
    mock_stderr.read.return_value = b""
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

    s = SSHSession(host="h", user="u")
    s.open()
    result = s.exec("echo hello")
    assert isinstance(result, ExecResult)
    assert result.stdout == "hello\n"
    assert result.stderr == ""
    assert result.rc == 0
    assert result.duration_s >= 0


@patch("kestrel.transport.ssh.paramiko.SSHClient")
def test_ssh_exec_propagates_nonzero_rc(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_stdout = MagicMock()
    mock_stderr = MagicMock()
    mock_stdout.read.return_value = b""
    mock_stderr.read.return_value = b"boom\n"
    mock_stdout.channel.recv_exit_status.return_value = 42
    mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

    s = SSHSession(host="h", user="u")
    s.open()
    result = s.exec("false")
    assert result.rc == 42
    assert result.stderr == "boom\n"


@patch("kestrel.transport.ssh.paramiko.SSHClient")
def test_ssh_close_cleans_client(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    s = SSHSession(host="h", user="u")
    s.open()
    s.close()
    mock_client.close.assert_called_once()
    assert s._client is None


# ── MSFRPCConfig + MSFRPCSession ─────────────────────────────────────────────


def test_msfrpc_config_defaults():
    c = MSFRPCConfig()
    assert c.host == "127.0.0.1"
    assert c.port == 55553
    assert c.user == "msf"
    assert c.ssl is True
    assert c.password == ""


def test_msfrpc_config_from_secret_file_reads_password(tmp_path, monkeypatch):
    secret_file = tmp_path / "msfrpc.secret"
    secret_file.write_text("supersecret123\n", encoding="utf-8")
    # Clear env so file is the source
    monkeypatch.delenv("KESTREL_MSF_PASSWORD", raising=False)
    monkeypatch.delenv("KESTREL_MSF_HOST", raising=False)
    monkeypatch.delenv("KESTREL_MSF_PORT", raising=False)
    monkeypatch.delenv("KESTREL_MSF_USER", raising=False)
    monkeypatch.delenv("KESTREL_MSF_SSL", raising=False)
    c = MSFRPCConfig.from_secret_file(secret_file)
    assert c.password == "supersecret123"


def test_msfrpc_config_env_overrides_file(tmp_path, monkeypatch):
    secret_file = tmp_path / "msfrpc.secret"
    secret_file.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("KESTREL_MSF_PASSWORD", "from-env")
    monkeypatch.setenv("KESTREL_MSF_HOST", "1.2.3.4")
    monkeypatch.setenv("KESTREL_MSF_PORT", "9999")
    monkeypatch.setenv("KESTREL_MSF_SSL", "false")
    c = MSFRPCConfig.from_secret_file(secret_file)
    assert c.password == "from-env"
    assert c.host == "1.2.3.4"
    assert c.port == 9999
    assert c.ssl is False


def test_msfrpc_config_missing_secret_file_no_password(tmp_path, monkeypatch):
    monkeypatch.delenv("KESTREL_MSF_PASSWORD", raising=False)
    c = MSFRPCConfig.from_secret_file(tmp_path / "no-such-file")
    assert c.password == ""


def test_msf_session_handle_id():
    cfg = MSFRPCConfig(password="x")
    s = MSFRPCSession(cfg)
    assert s.handle_id.startswith("msf-")


def test_msf_session_client_unopened_raises():
    cfg = MSFRPCConfig(password="x")
    s = MSFRPCSession(cfg)
    with pytest.raises(RuntimeError, match="not opened"):
        _ = s.client


@patch("kestrel.transport.msf.MSFRPCSession.open")
@patch("kestrel.transport.msf.MSFRPCSession.client", new_callable=lambda: property(lambda self: self._mocked_client))
def test_msf_session_ping_returns_true_on_success(mock_client_prop, mock_open):
    s = MSFRPCSession(MSFRPCConfig(password="x"))
    s._mocked_client = MagicMock()
    s._mocked_client.core.version = "6.4.0"
    assert s.ping() is True


def test_msf_session_ping_returns_false_on_exception():
    s = MSFRPCSession(MSFRPCConfig(password="bad"))
    # open() will fail because pymetasploit3 cannot connect to 127.0.0.1:55553
    # in the test env. ping() must swallow the exception.
    assert s.ping() is False


def test_default_secret_path_in_home():
    assert str(DEFAULT_SECRET_PATH).endswith(".kestrel/msfrpc.secret") or str(
        DEFAULT_SECRET_PATH
    ).endswith(".kestrel\\msfrpc.secret")


# ── IMP-12: infrastructure_error field ──────────────────────────────────────


def test_exec_result_infrastructure_error_defaults_false():
    r = ExecResult(stdout="out", stderr="", rc=0, duration_s=0.1)
    assert r.infrastructure_error is False


def test_exec_result_infrastructure_error_can_be_set():
    r = ExecResult(stdout="", stderr="err", rc=-1, duration_s=0.0, infrastructure_error=True)
    assert r.infrastructure_error is True


# ── IMP-01 + IMP-12: socket.timeout in exec() → infrastructure_error ────────


@patch("kestrel.transport.ssh.paramiko.SSHClient")
def test_ssh_exec_socket_timeout_returns_infrastructure_error(mock_client_cls):
    import socket as _socket

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    # Simulate channel settimeout raising socket.timeout on read
    mock_stdout = MagicMock()
    mock_stdout.channel.settimeout = MagicMock()
    mock_stdout.read.side_effect = _socket.timeout("timed out")
    mock_stderr = MagicMock()
    mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

    s = SSHSession(host="h", user="u")
    s.open()
    # First call triggers reconnect attempt (attempt 1), second hits the cap
    # We open a fresh session to avoid state from previous tests
    s2 = SSHSession(host="h", user="u")
    s2._client = mock_client
    s2._reconnect_attempts = 1  # Already at max → should return error immediately
    result = s2.exec("sleep 999", timeout=0.01)

    assert result.rc == -1
    assert result.infrastructure_error is True
    assert "timeout" in result.stderr


@patch("kestrel.transport.ssh.paramiko.SSHClient")
def test_ssh_exec_resets_reconnect_attempts_on_success(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_stdin = MagicMock()
    mock_stdout = MagicMock()
    mock_stderr = MagicMock()
    mock_stdout.read.return_value = b"ok"
    mock_stderr.read.return_value = b""
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

    s = SSHSession(host="h", user="u")
    s._client = mock_client
    s._reconnect_attempts = 1  # Pre-set as if a reconnect was in progress
    result = s.exec("echo ok")

    assert result.rc == 0
    assert s._reconnect_attempts == 0
    assert result.infrastructure_error is False
