"""Pydantic schemas for state — STUB (filled in Fase 3).

Will define LastCycle, MachineState, CurrentVector, AttackPlan, BlindFingerprint,
TriedCredential, TriedHash, TriedEndpoint, KaliListener, HashJob.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class MachineState(BaseModel):
    """Placeholder — to be expanded in Fase 3."""

    model_config = ConfigDict(extra="allow")

    machine_id: int | None = None
    machine_os: str | None = None
    machine_difficulty: str | None = None
    machine_retired: bool | None = None
    session_slug: str | None = None
    htb_mode: str | None = None
    intel_confidence: str | None = None


class LastCycle(BaseModel):
    """Placeholder — to be expanded in Fase 3."""

    model_config = ConfigDict(extra="allow")

    agent: str = "htb"
    last_run: str | None = None
    cycle_id: str | None = None
    run_count: int = 0
    data: dict[str, Any] = {}
