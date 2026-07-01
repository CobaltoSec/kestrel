"""Filelock-protected state store for Kestrel.

Manages atomic read/write of ``last-cycle.json`` (top-level agent state) plus
append-only ``sessions.jsonl`` (audit log).

Concurrency model:
    - Advisory ``filelock`` is acquired around every write and around the
      read-modify-write of update_machine().
    - Atomic writes via temp file + ``os.replace`` (cross-platform).
    - ``append_session_event`` opens with "a" + uses the lock to serialize.

The store is the single source of truth for state mutations — MCP tools must
go through it, never write the JSON files directly.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout

from kestrel.state.schema import LastCycle, MachineState, SessionEvent


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    """Atomic, filelock-protected state file manager.

    Args:
        path: Path to ``last-cycle.json``. Parent directory will be created on first write.
        lock_timeout_s: Seconds to wait for the advisory lock before raising filelock.Timeout.
    """

    def __init__(self, path: Path | str, lock_timeout_s: float = 10.0) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self.lock_timeout_s = lock_timeout_s

    # ── Internal lock helper ─────────────────────────────────────────────────

    def _lock(self) -> FileLock:
        return FileLock(str(self.lock_path), timeout=self.lock_timeout_s)

    # ── last-cycle.json read/write ───────────────────────────────────────────

    def read(self) -> LastCycle:
        """Read and validate last-cycle.json. Returns an empty LastCycle if file does not exist."""
        if not self.path.exists():
            return LastCycle()
        with self.path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
        return LastCycle.model_validate(raw)

    def _write_unlocked(self, state: LastCycle) -> None:
        """Atomic write WITHOUT acquiring the lock. Caller must hold ``self._lock()``."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = state.model_dump(mode="json", exclude_none=False)
        fd, tmp_path = tempfile.mkstemp(
            prefix=self.path.name + ".",
            suffix=".tmp",
            dir=self.path.parent,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def write(self, state: LastCycle) -> None:
        """Atomic write: temp file in same dir + os.replace. Holds the advisory lock."""
        with self._lock():
            self._write_unlocked(state)

    # ── Top-level mutations ──────────────────────────────────────────────────

    def update_top_level(self, **patch: Any) -> LastCycle:
        """Update top-level LastCycle fields (last_run, cycle_id, run_count, etc).

        Returns the updated state.
        """
        with self._lock():
            state = self.read()
            for key, value in patch.items():
                if hasattr(state, key):
                    setattr(state, key, value)
                else:
                    # forward-compat: stash in extras via model_dump round-trip
                    raise ValueError(f"Unknown top-level field: {key}")
            state.last_run = _now_iso()
            self._write_unlocked(state)
            return state

    def bump_run_count(self) -> int:
        """Increment run_count and update last_run. Returns new count."""
        with self._lock():
            state = self.read()
            state.run_count += 1
            state.last_run = _now_iso()
            state.cycle_id = f"HTB-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
            self._write_unlocked(state)
            return state.run_count

    # ── Machine state mutations ──────────────────────────────────────────────

    def get_machine(self, slug: str) -> MachineState | None:
        """Return the MachineState for the given slug, or None if absent."""
        state = self.read()
        return state.data.machines.get(slug)

    def upsert_machine(self, slug: str, machine: MachineState) -> None:
        """Replace the entire MachineState for slug (used on initial spawn)."""
        with self._lock():
            state = self.read()
            state.data.machines[slug] = machine
            self._write_unlocked(state)

    def update_machine(self, slug: str, patch: dict[str, Any]) -> MachineState:
        """Merge ``patch`` keys into machines[slug]. Returns the merged MachineState.

        - If slug doesn't exist, creates it from the patch.
        - Patch keys override existing fields shallowly.
        - For list/dict fields, the patch fully replaces (callers must merge manually if needed).
        """
        with self._lock():
            state = self.read()
            existing = state.data.machines.get(slug)
            if existing is None:
                merged = MachineState.model_validate(patch)
            else:
                # Merge: take the model dump, apply patch, re-validate
                base = existing.model_dump(mode="json")
                base.update(patch)
                merged = MachineState.model_validate(base)
            state.data.machines[slug] = merged
            self._write_unlocked(state)
            return merged

    def set_current_phase(self, phase: str, session_slug: str | None = None) -> None:
        """Set data.current_phase and optionally data.current_session."""
        with self._lock():
            state = self.read()
            state.data.current_phase = phase
            if session_slug is not None:
                state.data.current_session = session_slug
            self._write_unlocked(state)

    def set_current_session(self, session_slug: str) -> None:
        """Set data.current_session to the given slug."""
        with self._lock():
            state = self.read()
            state.data.current_session = session_slug
            self._write_unlocked(state)

    def clear_current_session(self) -> None:
        """Clear current_session (called at end of p6/p5-close)."""
        with self._lock():
            state = self.read()
            state.data.current_session = None
            self._write_unlocked(state)

    # ── Sessions.jsonl append-only audit log ─────────────────────────────────

    def append_session_event(
        self,
        session_dir: Path | str,
        phase: str,
        event: str,
        detail: str | None = None,
        **extra: Any,
    ) -> SessionEvent:
        """Append a structured event to <session_dir>/sessions.jsonl."""
        session_dir_path = Path(session_dir)
        session_dir_path.mkdir(parents=True, exist_ok=True)
        jsonl_path = session_dir_path / "sessions.jsonl"

        evt = SessionEvent(ts=_now_iso(), phase=phase, event=event, detail=detail)
        payload = evt.model_dump(mode="json", exclude_none=True)
        payload.update(extra)

        # Per-session jsonl lock (separate from main state lock to avoid contention)
        jsonl_lock = FileLock(str(jsonl_path) + ".lock", timeout=self.lock_timeout_s)
        with jsonl_lock:
            with jsonl_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return evt

    def read_session_events(
        self,
        session_dir: Path | str,
        limit: int | None = None,
    ) -> list[SessionEvent]:
        """Read sessions.jsonl. If ``limit`` is set, returns the last N events."""
        jsonl_path = Path(session_dir) / "sessions.jsonl"
        if not jsonl_path.exists():
            return []
        lines = [ln for ln in jsonl_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if limit is not None and limit > 0:
            lines = lines[-limit:]
        return [SessionEvent.model_validate(json.loads(ln)) for ln in lines]


__all__ = ["StateStore", "Timeout"]
