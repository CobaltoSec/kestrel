"""WinRM Session implementation (pypsrp).

Used for post-foothold Windows target interaction (PowerShell remoting). Typically
acquired after credentials are discovered or via evil-winrm-equivalent auth.

Auth modes:
- NTLM with username/password
- NTLM with username/NT-hash (pass-the-hash via cred_ssp + spnego nthash)
- Kerberos (when domain context available)
"""

from __future__ import annotations

import time
import uuid

from kestrel.transport.base import ExecResult, Session


class WinRMSession(Session):
    """PowerShell remoting over WinRM (HTTP/5985 or HTTPS/5986)."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str | None = None,
        nt_hash: str | None = None,
        port: int = 5985,
        ssl: bool = False,
        auth: str = "ntlm",  # ntlm | kerberos | basic | credssp
        cert_validation: bool = False,
        timeout: float = 30.0,
        handle_id: str | None = None,
    ) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.nt_hash = nt_hash
        self.port = port
        self.ssl = ssl
        self.auth = auth
        self.cert_validation = cert_validation
        self.timeout = timeout
        self.handle_id = handle_id or f"winrm-{uuid.uuid4().hex[:8]}"
        self._wsman = None
        self._pool = None

    def open(self) -> None:
        if self._pool is not None:
            return
        # Lazy import to keep pypsrp optional at module-load time
        from pypsrp.powershell import RunspacePool
        from pypsrp.wsman import WSMan

        # If NT hash provided, the pypsrp NTLM stack accepts password-as-hash with auth=ntlm
        password = self.password if self.password is not None else self.nt_hash

        self._wsman = WSMan(
            server=self.host,
            port=self.port,
            ssl=self.ssl,
            auth=self.auth,
            username=self.user,
            password=password,
            cert_validation=self.cert_validation,
            connection_timeout=int(self.timeout),
            operation_timeout=int(self.timeout),
        )
        self._wsman.__enter__()
        self._pool = RunspacePool(self._wsman)
        self._pool.open()

    def exec(self, cmd: str, timeout: float = 120.0) -> ExecResult:
        if self._pool is None:
            self.open()
        from pypsrp.powershell import PowerShell

        started = time.monotonic()
        ps = PowerShell(self._pool)
        ps.add_script(cmd)
        output = ps.invoke()
        stdout = "\n".join(str(o) for o in output)
        stderr_streams = []
        # pypsrp exposes errors via the PowerShell object
        if ps.had_errors:
            stderr_streams = [str(e) for e in ps.streams.error]
        rc = 1 if ps.had_errors else 0
        return ExecResult(
            stdout=stdout,
            stderr="\n".join(stderr_streams),
            rc=rc,
            duration_s=round(time.monotonic() - started, 3),
        )

    def close(self) -> None:
        if self._pool is not None:
            try:
                self._pool.close()
            finally:
                self._pool = None
        if self._wsman is not None:
            try:
                self._wsman.__exit__(None, None, None)
            finally:
                self._wsman = None
