"""Session abstraction base classes — STUB (filled in Fase 4).

Will define Session ABC (open/exec/close), ExecResult, SessionRegistry (thread-safe handle dict).
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ExecResult:
    """Result of executing a command in a Session."""

    stdout: str
    stderr: str
    rc: int
    duration_s: float


class Session(ABC):
    """Abstract base for SSH / WinRM / MSF sessions."""

    handle_id: str

    @abstractmethod
    def open(self) -> None: ...

    @abstractmethod
    def exec(self, cmd: str, timeout: float = 120.0) -> ExecResult: ...

    @abstractmethod
    def close(self) -> None: ...


class SessionRegistry:
    """Thread-safe registry of active session handles."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def add(self, session: Session) -> str:
        with self._lock:
            self._sessions[session.handle_id] = session
            return session.handle_id

    def get(self, handle_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(handle_id)

    def remove(self, handle_id: str) -> Session | None:
        with self._lock:
            return self._sessions.pop(handle_id, None)

    def list_handles(self) -> list[dict[str, Any]]:
        with self._lock:
            return [{"handle_id": s.handle_id, "type": type(s).__name__} for s in self._sessions.values()]
