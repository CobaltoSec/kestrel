"""Helper for executing tools on the Kali VM via SSH.

Common pattern across recon/vuln/exploit tools: open SSH to Kali, run a command,
read output, close. The SSHSession itself is persistent for efficiency, but most
callers want a simple ``via_kali(cmd)`` one-liner.

This module owns a process-global default SSHSession to Kali so tools don't
repeatedly reconnect. Callers can override with explicit ``session=`` arg.
"""

from __future__ import annotations

import os
import socket
import threading
from pathlib import Path
from typing import Optional

import paramiko

from kestrel.transport.base import ExecResult
from kestrel.transport.ssh import SSHSession

_default_session: Optional[SSHSession] = None
_lock = threading.Lock()


def get_default_kali_session(
    host: str | None = None,
    user: str | None = None,
    key_path: str | Path | None = None,
) -> SSHSession:
    """Return the process-global Kali SSH session, creating it on first call.

    Reads defaults from env vars:
        KESTREL_KALI_HOST (default: "kali-pentest")
        KESTREL_KALI_USER (default: "kali")
        KESTREL_KALI_KEY  (default: "~/.ssh/kali-pentest")
    """
    global _default_session
    with _lock:
        if _default_session is None:
            _default_session = SSHSession(
                host=host or os.environ.get("KESTREL_KALI_HOST", "kali-pentest"),
                user=user or os.environ.get("KESTREL_KALI_USER", "kali"),
                key_path=key_path or os.environ.get("KESTREL_KALI_KEY", "~/.ssh/kali-pentest"),
                handle_id="kali-default",
            )
        return _default_session


def via_kali(
    cmd: str,
    timeout: float = 120.0,
    session: SSHSession | None = None,
) -> ExecResult:
    """Run ``cmd`` on the Kali VM and return its ExecResult.

    Reuses the process-global session by default; pass ``session=`` to override.
    On connection/auth errors returns a structured ExecResult with infrastructure_error=True.
    """
    sess = session or get_default_kali_session()
    try:
        return sess.exec(cmd, timeout=timeout)
    except (paramiko.AuthenticationException, paramiko.NoValidConnectionsError) as e:
        reason = "auth_failed" if "Authentication" in str(e) else "connect_failed"
    except socket.timeout:
        reason = "socket_timeout"
    except Exception as e:
        reason = f"unknown:{type(e).__name__}"
    return ExecResult(stdout="", stderr=f"kali_unreachable:{reason}", rc=-1,
                      duration_s=0.0, infrastructure_error=True)


def close_default_session() -> None:
    """Close the global Kali session (for cleanup at exit)."""
    global _default_session
    with _lock:
        if _default_session is not None:
            _default_session.close()
            _default_session = None
