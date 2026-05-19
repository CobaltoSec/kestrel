"""Filelock-protected state store — STUB (filled in Fase 3).

Will provide StateStore(path) with .read(), .write(), .update_machine(), .append_session_event().
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kestrel.state.schema import LastCycle


class StateStore:
    """Placeholder implementation — to be replaced with filelock + atomic write in Fase 3."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def read(self) -> LastCycle:
        if not self.path.exists():
            return LastCycle()
        with self.path.open("r", encoding="utf-8") as f:
            return LastCycle.model_validate(json.load(f))

    def write(self, state: LastCycle) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as f:
            json.dump(state.model_dump(mode="json"), f, indent=2)

    def update_machine(self, machine: str, patch: dict[str, Any]) -> None:
        state = self.read()
        machines = state.data.setdefault("machines", {})
        machines.setdefault(machine, {}).update(patch)
        self.write(state)
