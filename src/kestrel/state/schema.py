"""Pydantic schemas for Kestrel state — full v0.3 schema match.

Mirrors `.claude/skills/kestrel/phases/shared/state-schema.md` exactly. All optional
fields (v0.2 cross-session arrays, v0.2.1 attack_plan/current_vector/hash_jobs,
v0.3 session_budget_*) are modeled as Optional with sensible defaults. Forward-compat
via ``extra="allow"`` — unknown fields are preserved on roundtrip.

Used by:
    kestrel.state.store.StateStore  — atomic file I/O with filelock
    kestrel.mcp.tools.state         — MCP tools state_read/state_write_machine
    kestrel.mcp.resources           — read-only resource exposure
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

# ── Sessions audit log ────────────────────────────────────────────────────────


class SessionEvent(BaseModel):
    """One line in sessions.jsonl."""

    model_config = ConfigDict(extra="allow")

    ts: str  # ISO8601 with tz
    phase: str
    event: str
    detail: str | None = None
    duration_s: float | None = None
    exit_code: int | None = None


# ── HTB profile (profile.json) ────────────────────────────────────────────────


class OwnedMachine(BaseModel):
    model_config = ConfigDict(extra="allow")

    machine_id: int
    machine_name: str
    machine_os: str | None = None
    machine_difficulty: str | None = None
    owned_user_at: str | None = None
    owned_root_at: str | None = None
    session_slug: str | None = None


class Profile(BaseModel):
    """fleet/agents/htb/state/profile.json"""

    model_config = ConfigDict(extra="allow")

    handle: str | None = None
    htb_id: int | None = None
    updated_at: str | None = None
    rank_text: str | None = None
    ranking: int | None = None
    points: int | None = None
    user_owns: int | None = None
    system_owns: int | None = None
    machines_owned: list[OwnedMachine] = Field(default_factory=list)


# ── Cross-session tracking (v0.2) ─────────────────────────────────────────────


class TriedCredential(BaseModel):
    model_config = ConfigDict(extra="allow")
    user: str
    password: str | None = None
    service: str
    result: str  # success | auth_failed | error | account_locked
    ts: str


class TriedEndpoint(BaseModel):
    model_config = ConfigDict(extra="allow")
    path: str
    method: str = "GET"
    vhost: str | None = None
    status: int | None = None
    interesting: bool = False
    ts: str


class TriedHash(BaseModel):
    model_config = ConfigDict(extra="allow")
    hash_preview: str
    type: str
    wordlist: str
    rules: str = "none"
    elapsed_s: int | None = None
    result: str  # match | no_match | timeout | error
    ts: str


# ── Attack plan + vector (v0.2.1) ─────────────────────────────────────────────


class AttackPlan(BaseModel):
    """Copy of blind_fingerprint.py attack_plan output."""

    model_config = ConfigDict(extra="allow")

    primary_chain: list[str] = Field(default_factory=list)
    alternative_chains: list[list[str]] = Field(default_factory=list)
    parallel_tracks: list[str] = Field(default_factory=list)
    execution_hint: str | None = None


class CurrentVector(BaseModel):
    """Active vector being executed with budget timer."""

    model_config = ConfigDict(extra="allow")

    id: str
    started_at: str  # ISO8601
    budget_min: int
    exhausted: bool = False


class HashJob(BaseModel):
    """Async hash crack job (crack-helper.sh --async)."""

    model_config = ConfigDict(extra="allow")

    job_id: str
    hash_preview: str
    type: str
    wordlist: str
    started_at: str
    status: str = "pending_upload"  # pending_upload | running | complete | no_match | timeout | error


# ── Kali listeners ────────────────────────────────────────────────────────────


class KaliListener(BaseModel):
    model_config = ConfigDict(extra="allow")
    pid: int | None = None
    port: int | None = None
    type: str | None = None  # nc | msf | python | other
    cmd: str | None = None


# ── Machine state ─────────────────────────────────────────────────────────────


class MachineState(BaseModel):
    """data.machines.<slug> — per-machine state for one HTB engagement."""

    model_config = ConfigDict(extra="allow")

    # Core HTB metadata
    machine_id: int | None = None
    machine_os: str | None = None
    machine_difficulty: str | None = None
    machine_retired: bool | None = None
    machine_rating: float | None = None
    machine_tags: list[str] = Field(default_factory=list)

    # Session lifecycle
    started_at: str | None = None
    finished_at: str | None = None
    session_slug: str | None = None
    user_owned: bool = False
    root_owned: bool = False
    hints_used: bool = False

    # Mode + intel (set in p1.5)
    htb_mode: str | None = None  # guided | blind
    intel_confidence: str | None = None  # high | medium | low | none
    intel_path: str | None = None
    intel_sources: list[str] = Field(default_factory=list)

    # Networking
    target_ip: str | None = None
    last_machine_ip: str | None = None  # alias of target_ip
    vpn_iface_state: str | None = None  # up | down | expired
    kali_listeners: list[KaliListener] = Field(default_factory=list)

    # Blind fingerprint (p3 PASO 1.5)
    blind_fingerprint_pending: bool = False
    blind_fingerprint_path: str | None = None
    blind_fingerprint_top: str | None = None
    blind_fingerprint_conf: float | None = None

    # Phase resume hints
    next_step_hint: str | None = None
    last_phase_completed: str | None = None
    progress: dict[str, Any] = Field(default_factory=dict)
    next_steps: list[str] = Field(default_factory=list)

    # Pause / abandon
    paused: bool = False
    paused_reason: str | None = None
    abandoned: bool = False
    abandoned_reason: str | None = None

    # v0.2 cross-session arrays (opt)
    tried_credentials: list[TriedCredential] = Field(default_factory=list)
    tried_endpoints: list[TriedEndpoint] = Field(default_factory=list)
    tried_hashes: list[TriedHash] = Field(default_factory=list)

    # v0.2.1 attack plan + vector (opt)
    attack_plan: Optional[AttackPlan] = None
    current_vector: Optional[CurrentVector] = None
    hash_jobs: list[HashJob] = Field(default_factory=list)

    # v0.3 session budget (opt — append-only)
    session_started_at: str | None = None
    session_budget_min: int | None = None
    session_budget_alerts_triggered: list[str] = Field(default_factory=list)


# ── Last-cycle (top-level state file) ─────────────────────────────────────────


class CycleData(BaseModel):
    """data.* in last-cycle.json."""

    model_config = ConfigDict(extra="allow")

    current_phase: str | None = None
    current_session: str | None = None
    paused: bool = False
    paused_reason: str | None = None
    resumed_session_count: int = 0
    machines: dict[str, MachineState] = Field(default_factory=dict)


class LastCycle(BaseModel):
    """fleet/agents/htb/state/last-cycle.json — top-level agent state."""

    model_config = ConfigDict(extra="allow")

    agent: str = "htb"
    last_run: str | None = None
    cycle_id: str | None = None
    run_count: int = 0
    data: CycleData = Field(default_factory=CycleData)


__all__ = [
    "AttackPlan",
    "CurrentVector",
    "CycleData",
    "HashJob",
    "KaliListener",
    "LastCycle",
    "MachineState",
    "OwnedMachine",
    "Profile",
    "SessionEvent",
    "TriedCredential",
    "TriedEndpoint",
    "TriedHash",
]
