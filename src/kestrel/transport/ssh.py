"""SSH Session implementation (paramiko-based, persistent transport).

The SSHSession opens an authenticated paramiko.SSHClient once and reuses it for
multiple ``exec`` calls — much cheaper than a fresh SSH handshake per command.

Used as the primary transport to Kali VM for nmap/nuclei/MSF execution,
and to HTB foothold targets for post-exploitation enumeration.
"""

from __future__ import annotations

import io
import shlex
import time
import uuid
from pathlib import Path

import paramiko

from kestrel.transport.base import ExecResult, Session


class SSHSession(Session):
    """Persistent SSH session over paramiko."""

    def __init__(
        self,
        host: str,
        user: str,
        port: int = 22,
        key_path: str | Path | None = None,
        password: str | None = None,
        timeout: float = 10.0,
        handle_id: str | None = None,
    ) -> None:
        self.host = host
        self.user = user
        self.port = port
        self.key_path = Path(key_path).expanduser() if key_path else None
        self.password = password
        self.connect_timeout = timeout
        self.handle_id = handle_id or f"ssh-{uuid.uuid4().hex[:8]}"
        self._client: paramiko.SSHClient | None = None

    def open(self) -> None:
        if self._client is not None:
            return
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = {
            "hostname": self.host,
            "username": self.user,
            "port": self.port,
            "timeout": self.connect_timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.key_path is not None:
            kwargs["key_filename"] = str(self.key_path)
        if self.password is not None:
            kwargs["password"] = self.password
        client.connect(**kwargs)
        self._client = client

    def exec(self, cmd: str, timeout: float = 120.0) -> ExecResult:
        if self._client is None:
            self.open()
        assert self._client is not None
        started = time.monotonic()
        stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        out_data = stdout.read().decode("utf-8", errors="replace")
        err_data = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return ExecResult(
            stdout=out_data,
            stderr=err_data,
            rc=rc,
            duration_s=round(time.monotonic() - started, 3),
        )

    def upload(self, local_path: str | Path, remote_path: str) -> None:
        """SCP-style upload via SFTP."""
        if self._client is None:
            self.open()
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            sftp.put(str(local_path), remote_path)
        finally:
            sftp.close()

    def upload_string(self, content: str, remote_path: str) -> None:
        """Upload an in-memory string to a remote file."""
        if self._client is None:
            self.open()
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            with sftp.file(remote_path, "w") as f:
                f.write(content)
        finally:
            sftp.close()

    def download(self, remote_path: str, local_path: str | Path) -> None:
        if self._client is None:
            self.open()
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            sftp.get(remote_path, str(local_path))
        finally:
            sftp.close()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


def quote_cmd(*parts: str) -> str:
    """Shell-quote a command for safe SSH execution."""
    return " ".join(shlex.quote(p) for p in parts)
