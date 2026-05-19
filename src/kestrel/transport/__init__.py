"""Transport layer — unified Session abstraction over SSH (paramiko), WinRM (pypsrp), and MSF RPC (pymetasploit3)."""

from kestrel.transport.base import ExecResult, Session, SessionRegistry

__all__ = ["ExecResult", "Session", "SessionRegistry"]
