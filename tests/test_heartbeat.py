"""Tests for heartbeat.py — session observability dashboard + budget alerting."""
import json
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "scripts" / "heartbeat.py"


def make_session(tmp_path: Path, jsonl_lines: list[dict] | None = None,
                 estado: str = "") -> Path:
    session = tmp_path / "session"
    session.mkdir(exist_ok=True)
    if jsonl_lines:
        (session / "sessions.jsonl").write_text(
            "\n".join(json.dumps(ln) for ln in jsonl_lines) + "\n"
        )
    if estado:
        (session / "estado.md").write_text(estado)
    return session


def make_state_file(tmp_path: Path, slug: str, *,
                    difficulty: str = "Easy",
                    started_minutes_ago: int = 10,
                    session_budget_min: int | None = None,
                    current_phase: str = "p3-delegate-pentest") -> Path:
    started = (
        datetime.now(timezone.utc) - timedelta(minutes=started_minutes_ago)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    machine: dict = {
        "machine_difficulty": difficulty,
        "session_started_at": started,
    }
    if session_budget_min is not None:
        machine["session_budget_min"] = session_budget_min
    state = {
        "data": {
            "current_phase": current_phase,
            "machines": {slug: machine},
        }
    }
    p = tmp_path / "last-cycle.json"
    p.write_text(json.dumps(state))
    return p


def run(session_dir: Path, *, state_file: Path | None = None,
        no_jsonl: bool = False, timeout: int = 10) -> tuple[int, str, str]:
    args = [sys.executable, str(SCRIPT), "--session-dir", str(session_dir)]
    if state_file:
        args += ["--state-file", str(state_file)]
    if no_jsonl:
        args.append("--no-jsonl")
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


# ─── Basic operation ─────────────────────────────────────────────────────────

def test_basic_run_exits_zero(tmp_path: Path):
    session = make_session(tmp_path)
    code, out, _ = run(session, no_jsonl=True)
    assert code == 0
    assert "HEARTBEAT" in out


def test_appends_heartbeat_event(tmp_path: Path):
    session = make_session(tmp_path)
    run(session)
    events = read_jsonl(session / "sessions.jsonl")
    hb = next(e for e in events if e["event"] == "heartbeat")
    assert hb["phase"] == "heartbeat"
    assert "idle=" in hb["detail"]


def test_no_jsonl_flag_skips_write(tmp_path: Path):
    session = make_session(tmp_path)
    run(session, no_jsonl=True)
    assert not (session / "sessions.jsonl").exists()


def test_missing_session_dir_exits_4(tmp_path: Path):
    code, _, err = run(tmp_path / "nonexistent", no_jsonl=True)
    assert code == 4


# ─── Time-sink dashboard ──────────────────────────────────────────────────────

def test_top_time_sinks_shown(tmp_path: Path):
    events = [
        {"ts": "2026-05-17T10:00:00Z", "event": "tool_start", "detail": "nmap"},
        {"ts": "2026-05-17T10:02:00Z", "event": "tool_end",
         "detail": "nmap", "duration_s": 120, "exit_code": 0},
        {"ts": "2026-05-17T10:02:00Z", "event": "tool_start", "detail": "hashcat"},
        {"ts": "2026-05-17T10:07:00Z", "event": "tool_end",
         "detail": "hashcat", "duration_s": 300, "exit_code": 0},
    ]
    session = make_session(tmp_path, jsonl_lines=events)
    _, out, _ = run(session, no_jsonl=True)
    # At least one tool name should appear in the dashboard
    assert "nmap" in out or "hashcat" in out


def test_empty_session_shows_dashboard(tmp_path: Path):
    """Session with no events still emits a dashboard (no crash)."""
    session = make_session(tmp_path)
    code, out, _ = run(session, no_jsonl=True)
    assert code == 0
    assert "═" in out


# ─── Budget alerting ──────────────────────────────────────────────────────────

def _make_budget_session(tmp_path: Path, slug: str,
                          minutes_elapsed: int, budget: int) -> tuple[Path, Path]:
    session_dir = tmp_path / f"htb-2026-05-17-{slug}"
    session_dir.mkdir()
    state = make_state_file(
        tmp_path, slug,
        difficulty="Easy",
        started_minutes_ago=minutes_elapsed,
        session_budget_min=budget,
    )
    return session_dir, state


def test_budget_ok_below_80pct(tmp_path: Path):
    session, state = _make_budget_session(tmp_path, "target", 70, 90)
    code, _, _ = run(session, state_file=state, no_jsonl=True)
    assert code == 0, "Expected OK (0) at 77% budget"


def test_budget_warn_at_80pct(tmp_path: Path):
    session, state = _make_budget_session(tmp_path, "target", 75, 90)
    code, _, _ = run(session, state_file=state, no_jsonl=True)
    assert code == 1, f"Expected WARN (1) at 83% budget, got {code}"


def test_budget_critical_at_100pct(tmp_path: Path):
    session, state = _make_budget_session(tmp_path, "target", 95, 90)
    code, _, _ = run(session, state_file=state, no_jsonl=True)
    assert code == 2, f"Expected CRITICAL (2) at 105% budget, got {code}"


def test_budget_abandon_at_150pct(tmp_path: Path):
    session, state = _make_budget_session(tmp_path, "target", 140, 90)
    code, _, _ = run(session, state_file=state, no_jsonl=True)
    assert code == 3, f"Expected ABANDON (3) at 155% budget, got {code}"


def test_no_state_file_exits_zero(tmp_path: Path):
    """Without a state file, budget is unknown → exit 0."""
    session = make_session(tmp_path)
    code, _, _ = run(session, no_jsonl=True)
    assert code == 0
