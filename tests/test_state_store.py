"""Tests for kestrel.state.store.StateStore — atomic, filelock-protected state I/O."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from kestrel.state.schema import (
    AttackPlan,
    CurrentVector,
    LastCycle,
    MachineState,
    TriedCredential,
)
from kestrel.state.store import StateStore


def test_read_returns_empty_when_file_missing(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    state = store.read()
    assert isinstance(state, LastCycle)
    assert state.agent == "htb"
    assert state.run_count == 0
    assert state.data.machines == {}


def test_write_creates_parent_dir(tmp_path: Path):
    target = tmp_path / "nested" / "dir" / "state.json"
    store = StateStore(target)
    state = LastCycle(cycle_id="HTB-TEST")
    store.write(state)
    assert target.exists()
    assert target.parent.exists()


def test_write_then_read_roundtrip(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    state = LastCycle(run_count=5, cycle_id="HTB-X")
    state.data.machines["lame"] = MachineState(
        machine_id=1,
        machine_os="Linux",
        machine_difficulty="Easy",
        machine_retired=True,
        htb_mode="guided",
        intel_confidence="high",
    )
    store.write(state)
    rt = store.read()
    assert rt.run_count == 5
    assert rt.cycle_id == "HTB-X"
    assert "lame" in rt.data.machines
    assert rt.data.machines["lame"].machine_id == 1
    assert rt.data.machines["lame"].intel_confidence == "high"


def test_write_is_atomic_no_partial_state(tmp_path: Path):
    """Verify temp+rename: after write, no .tmp files left and JSON is valid."""
    store = StateStore(tmp_path / "state.json")
    store.write(LastCycle(run_count=1))
    files = list(tmp_path.iterdir())
    tmps = [f for f in files if f.name.endswith(".tmp") or ".tmp." in f.name]
    assert tmps == [], f"unexpected temp files: {tmps}"
    # JSON must parse
    json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))


def test_update_machine_creates_new(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    store.update_machine("newmachine", {"machine_id": 42, "machine_os": "Windows"})
    m = store.get_machine("newmachine")
    assert m is not None
    assert m.machine_id == 42
    assert m.machine_os == "Windows"


def test_update_machine_merges_existing(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    store.update_machine("lame", {"machine_id": 1, "machine_os": "Linux"})
    store.update_machine("lame", {"user_owned": True, "target_ip": "10.10.10.3"})
    m = store.get_machine("lame")
    assert m is not None
    assert m.machine_id == 1  # preserved
    assert m.machine_os == "Linux"  # preserved
    assert m.user_owned is True  # added
    assert m.target_ip == "10.10.10.3"  # added


def test_bump_run_count_monotonic(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    n1 = store.bump_run_count()
    n2 = store.bump_run_count()
    n3 = store.bump_run_count()
    assert n1 == 1 and n2 == 2 and n3 == 3
    state = store.read()
    assert state.run_count == 3
    assert state.cycle_id is not None
    assert state.cycle_id.startswith("HTB-")
    assert state.last_run is not None


def test_set_current_phase_and_clear(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    store.set_current_phase("p1-recon", session_slug="htb-test")
    assert store.read().data.current_phase == "p1-recon"
    assert store.read().data.current_session == "htb-test"
    store.clear_current_session()
    assert store.read().data.current_session is None
    # current_phase preserved
    assert store.read().data.current_phase == "p1-recon"


def test_session_event_append_and_read(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    session_dir = tmp_path / "session"
    store.append_session_event(session_dir, "p1-recon", "tool_start", detail="nmap")
    store.append_session_event(
        session_dir,
        "p1-recon",
        "tool_end",
        detail="nmap",
        duration_s=12.3,
        exit_code=0,
    )
    events = store.read_session_events(session_dir)
    assert len(events) == 2
    assert events[0].event == "tool_start"
    assert events[1].event == "tool_end"
    assert events[1].duration_s == 12.3
    assert events[1].exit_code == 0


def test_session_event_read_limit(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    session_dir = tmp_path / "session"
    for i in range(20):
        store.append_session_event(session_dir, "p3", f"evt_{i}", detail=str(i))
    events = store.read_session_events(session_dir, limit=5)
    assert len(events) == 5
    assert events[-1].event == "evt_19"


def test_concurrent_update_machine_no_corruption(tmp_path: Path):
    """Two threads updating the same machine — both updates must persist (filelock serializes)."""
    store = StateStore(tmp_path / "state.json", lock_timeout_s=5.0)

    def updater(slug: str, key: str, value: object):
        store.update_machine(slug, {key: value})

    threads = [
        threading.Thread(target=updater, args=("lame", "machine_id", 1)),
        threading.Thread(target=updater, args=("lame", "target_ip", "10.10.10.3")),
        threading.Thread(target=updater, args=("blue", "machine_id", 51)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = store.read()
    assert final.data.machines["lame"].machine_id == 1
    assert final.data.machines["lame"].target_ip == "10.10.10.3"
    assert final.data.machines["blue"].machine_id == 51


def test_real_last_cycle_roundtrip(tmp_path: Path):
    """Load actual production last-cycle.json schema (subset) and roundtrip without loss."""
    payload = {
        "agent": "htb",
        "last_run": "2026-05-17T22:45:00Z",
        "cycle_id": "HTB-20260517T224500Z",
        "run_count": 12,
        "data": {
            "current_phase": "p2-engagement-setup",
            "current_session": "htb-2026-05-17-monitorsfour",
            "paused": False,
            "machines": {
                "monitorsfour": {
                    "machine_id": 814,
                    "machine_os": "Windows",
                    "machine_difficulty": "Easy",
                    "machine_retired": True,
                    "session_slug": "htb-2026-05-17-monitorsfour",
                    "htb_mode": "guided",
                    "intel_confidence": "high",
                    "session_budget_min": 90,
                    "session_budget_alerts_triggered": [],
                }
            },
        },
    }
    target = tmp_path / "state.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    store = StateStore(target)
    state = store.read()
    assert state.run_count == 12
    assert state.data.current_session == "htb-2026-05-17-monitorsfour"
    m = state.data.machines["monitorsfour"]
    assert m.machine_id == 814
    assert m.session_budget_min == 90
    # roundtrip preservation
    store.write(state)
    rt = store.read()
    assert rt.data.machines["monitorsfour"].machine_retired is True


def test_attack_plan_persists(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    plan = AttackPlan(
        primary_chain=["cve-X", "winrm"],
        alternative_chains=[["lfi", "cred-reuse"]],
        parallel_tracks=["docker-escape"],
        execution_hint="multi-path",
    )
    store.update_machine("m4", {"machine_id": 814, "attack_plan": plan.model_dump()})
    m = store.get_machine("m4")
    assert m is not None
    assert m.attack_plan is not None
    assert m.attack_plan.primary_chain == ["cve-X", "winrm"]


def test_current_vector_with_budget(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    vec = CurrentVector(id="cve-2026-X", started_at="2026-05-19T12:00:00+00:00", budget_min=25)
    store.update_machine("m4", {"machine_id": 1, "current_vector": vec.model_dump()})
    m = store.get_machine("m4")
    assert m is not None
    assert m.current_vector is not None
    assert m.current_vector.id == "cve-2026-X"
    assert m.current_vector.budget_min == 25
    assert m.current_vector.exhausted is False


def test_tried_credentials_append_pattern(tmp_path: Path):
    """Caller is responsible for list merge (patch replaces); verify the pattern works."""
    store = StateStore(tmp_path / "state.json")
    cred1 = TriedCredential(
        user="admin", password="admin", service="ssh", result="auth_failed", ts="2026-05-19T12:00:00Z"
    )
    store.update_machine("m", {"tried_credentials": [cred1.model_dump()]})

    # Append second cred (caller-side merge)
    m = store.get_machine("m")
    assert m is not None
    cred2 = TriedCredential(
        user="root", password="toor", service="ssh", result="auth_failed", ts="2026-05-19T12:01:00Z"
    )
    creds = [c.model_dump() for c in m.tried_credentials] + [cred2.model_dump()]
    store.update_machine("m", {"tried_credentials": creds})

    final = store.get_machine("m")
    assert final is not None
    assert len(final.tried_credentials) == 2
    assert final.tried_credentials[1].user == "root"


def test_extra_fields_preserved_on_roundtrip(tmp_path: Path):
    """Unknown fields should survive roundtrip (forward-compat for future schema versions)."""
    payload = {
        "agent": "htb",
        "run_count": 1,
        "data": {
            "machines": {
                "future": {
                    "machine_id": 999,
                    "future_field_v05": "this should survive",
                    "another_unknown": {"nested": True},
                }
            }
        },
    }
    target = tmp_path / "state.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    store = StateStore(target)
    state = store.read()
    store.write(state)
    rt_raw = json.loads(target.read_text(encoding="utf-8"))
    assert rt_raw["data"]["machines"]["future"]["future_field_v05"] == "this should survive"
    assert rt_raw["data"]["machines"]["future"]["another_unknown"]["nested"] is True
