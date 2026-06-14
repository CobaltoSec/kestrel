"""
Tests for stuck_detector.py — L3 stuck signal parsing.
"""
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "scripts" / "stuck_detector.py"


def make_session(tmp_path: Path, *, estado: str = "", findings: str = "",
                 jsonl_lines: list[dict] | None = None) -> Path:
    session = tmp_path / "session"
    session.mkdir()
    (session / "estado.md").write_text(estado)
    (session / "findings.md").write_text(findings)
    if jsonl_lines:
        (session / "sessions.jsonl").write_text(
            "\n".join(json.dumps(line) for line in jsonl_lines) + "\n"
        )
    return session


def run(session_dir: Path, *, stall_minutes: int = 0) -> tuple[int, dict]:
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--session-dir", str(session_dir),
         "--stall-minutes", str(stall_minutes)],
        capture_output=True, text=True, timeout=10,
    )
    return r.returncode, json.loads(r.stdout)


def test_clean_session_no_signals(tmp_path: Path):
    session = make_session(tmp_path, estado="todo bien", findings="| 80 | http | OK |")
    code, out = run(session)
    assert code == 0
    assert out["stuck"] is False
    assert out["signals"] == []
    assert out["recommendation"] == "continue"


def test_shell_lost_detection(tmp_path: Path):
    session = make_session(
        tmp_path,
        estado="la shell se cae con connection reset cada 30 seg",
        findings="",
    )
    code, out = run(session)
    assert code == 1
    assert "shell_lost" in out["signals"]
    assert out["recommendation"] == "reset_listener"


def test_hash_stuck_via_estado(tmp_path: Path):
    session = make_session(
        tmp_path,
        estado="hash policy triggered — bcrypt no rompe en 5 min",
        findings="",
    )
    code, out = run(session)
    assert code == 1
    assert "hash_stuck" in out["signals"]
    assert out["recommendation"] == "escalate_gpu"


def test_hash_stuck_via_jsonl_unresolved(tmp_path: Path):
    session = make_session(
        tmp_path,
        estado="",
        jsonl_lines=[
            {"ts": "2026-05-11T19:30:00Z", "phase": "p3", "event": "hash_policy_triggered", "detail": "bcrypt timeout"},
            {"ts": "2026-05-11T19:35:00Z", "phase": "p3", "event": "next_action_pending"},
        ],
    )
    code, out = run(session)
    assert code == 1
    assert "hash_stuck" in out["signals"]


def test_hash_resolved_no_signal(tmp_path: Path):
    """If after hash_policy_triggered there's a crack_complete event, signal is cleared."""
    session = make_session(
        tmp_path,
        jsonl_lines=[
            {"ts": "2026-05-11T19:30:00Z", "phase": "p3", "event": "hash_policy_triggered", "detail": "bcrypt"},
            {"ts": "2026-05-11T19:45:00Z", "phase": "p3", "event": "crack_complete", "detail": "password found"},
        ],
    )
    code, out = run(session)
    assert "hash_stuck" not in out["signals"]


def test_cred_exhausted_from_jsonl(tmp_path: Path):
    session = make_session(
        tmp_path,
        jsonl_lines=[
            {"ts": "2026-05-11T19:00:00Z", "event": "winrm_attempt", "detail": "admin:wonderful1 auth_failed"},
            {"ts": "2026-05-11T19:01:00Z", "event": "winrm_attempt", "detail": "marcus:wonderful1 auth_failed"},
            {"ts": "2026-05-11T19:02:00Z", "event": "winrm_attempt", "detail": "cactidbuser:7pyrf6ly8qx4 auth_failed"},
        ],
    )
    code, out = run(session)
    assert code == 1
    assert "cred_exhausted" in out["signals"]
    assert out["recommendation"] == "switch_vector"


def test_alternatives_extracted_from_findings(tmp_path: Path):
    session = make_session(
        tmp_path,
        estado="all winrm creds auth_failed auth_failed auth_failed",
        findings="| 5985 | wsman | WinRM | High | exposed | netexec |\n| 445 | smb | SMB | Medium | | |",
        jsonl_lines=[
            {"ts": "2026-05-11T19:00:00Z", "event": "auth_failed"},
            {"ts": "2026-05-11T19:01:00Z", "event": "auth_failed"},
            {"ts": "2026-05-11T19:02:00Z", "event": "auth_failed"},
        ],
    )
    code, out = run(session)
    assert "cred_exhausted" in out["signals"]
    assert "winrm-lateral" in out["alternatives"]
    assert "smb-exploit" in out["alternatives"]


def test_missing_session_dir(tmp_path: Path):
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--session-dir", str(tmp_path / "nope"),
         "--stall-minutes", "0"],
        capture_output=True, text=True, timeout=5,
    )
    assert r.returncode == 2


def test_monitorsfour_real_world_case(tmp_path: Path):
    """Synthesizes MonitorsFour S3 state: bcrypt stuck + WinRM cred spray exhausted."""
    session = make_session(
        tmp_path,
        estado="""
# Estado — MonitorsFour
WinRM spray todos fallaron — admin/marcus/cactidbuser auth_failed.
Bcrypt Cacti admin hash policy triggered — no rompe en 5 min CPU.
""",
        findings="""
| 1 | 80/HTTP   | type juggling                          | High     | Confirmed |
| 2 | 80/HTTP   | CVE-2025-24367 Cacti RCE               | Critical | Exploited |
| 3 | 5985/WinRM | service exposed, no working creds      | Medium   | Stuck     |
""",
        jsonl_lines=[
            {"ts": "2026-05-11T19:30:00Z", "event": "hash_policy_triggered", "detail": "bcrypt 5min no match"},
            {"ts": "2026-05-11T19:32:00Z", "event": "winrm_attempt", "detail": "admin auth_failed"},
            {"ts": "2026-05-11T19:34:00Z", "event": "winrm_attempt", "detail": "marcus auth_failed"},
            {"ts": "2026-05-11T19:36:00Z", "event": "winrm_attempt", "detail": "cactidbuser auth_failed"},
            {"ts": "2026-05-11T19:40:00Z", "event": "winrm_attempt", "detail": "monitorsdbuser auth_failed"},
        ],
    )
    code, out = run(session)
    assert code == 1
    # Both signals should fire — multi-stuck case
    assert "hash_stuck" in out["signals"]
    assert "cred_exhausted" in out["signals"]
    # Recommendation should prioritize hash → GPU escalation
    assert out["recommendation"] == "escalate_gpu"
    # Alternatives should still suggest pivoting
    assert "winrm-lateral" in out["alternatives"]


# ─── P2.3 — attack_plan alternative_chains propagation ───────────────────────

def test_alternatives_from_attack_plan(tmp_path: Path):
    """P2.3: when findings.md is empty but fingerprint.json has alternatives → propagate."""
    import json as _json

    session = tmp_path / "session"
    session.mkdir()
    fp = {
        "attack_plan": {
            "primary_chain": {"categories": ["web-exploit"], "confidence": 0.80, "rationale": "x"},
            "alternative_chains": [
                {"categories": ["smb-exploit"], "confidence": 0.55, "rationale": "y"},
                {"categories": ["docker-escape"], "confidence": 0.40, "rationale": "z"},
            ],
        }
    }
    (session / "fingerprint.json").write_text(_json.dumps(fp))
    (session / "findings.md").write_text("")
    jsonl = [
        {"ts": "2026-05-17T10:00:00Z", "event": "auth_failed"},
        {"ts": "2026-05-17T10:01:00Z", "event": "auth_failed"},
        {"ts": "2026-05-17T10:02:00Z", "event": "auth_failed"},
    ]
    (session / "sessions.jsonl").write_text("\n".join(_json.dumps(e) for e in jsonl) + "\n")
    (session / "estado.md").write_text("")

    code, out = run(session)
    assert code == 1
    assert "cred_exhausted" in out["signals"]
    assert "smb-exploit" in out["alternatives"] or "docker-escape" in out["alternatives"], (
        f"Expected plan alternatives, got {out['alternatives']}"
    )


# ─── P3.1 — lab_unstable signal ──────────────────────────────────────────────

def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_lab_unstable_signal(tmp_path: Path):
    """P3.1: >= 3 network error patterns in recent events → lab_unstable signal."""
    ts = _now_ts()
    session = make_session(
        tmp_path,
        estado="",
        jsonl_lines=[
            {"ts": ts, "event": "exploit_attempt", "detail": "connection reset by peer"},
            {"ts": ts, "event": "ssh_connect",     "detail": "ssh timeout connecting to target"},
            {"ts": ts, "event": "ping_check",       "detail": "no route to host 10.10.11.42"},
        ],
    )
    code, out = run(session)
    assert "lab_unstable" in out["signals"], f"Expected lab_unstable, got {out['signals']}"
    assert out["recommendation"] == "switch_vpn_server"


def test_lab_unstable_below_threshold(tmp_path: Path):
    """P3.1: only 2 network errors → no lab_unstable."""
    ts = _now_ts()
    session = make_session(
        tmp_path,
        jsonl_lines=[
            {"ts": ts, "event": "e1", "detail": "connection reset by peer"},
            {"ts": ts, "event": "e2", "detail": "ssh timeout"},
        ],
    )
    code, out = run(session)
    assert "lab_unstable" not in out["signals"]


def test_lab_unstable_old_events_ignored(tmp_path: Path):
    """P3.1: 3 errors but all older than the window → no lab_unstable."""
    session = make_session(
        tmp_path,
        jsonl_lines=[
            {"ts": "2026-01-01T00:00:00Z", "event": "e1", "detail": "connection reset by peer"},
            {"ts": "2026-01-01T00:01:00Z", "event": "e2", "detail": "no route to host"},
            {"ts": "2026-01-01T00:02:00Z", "event": "e3", "detail": "network is unreachable"},
        ],
    )
    code, out = run(session)
    assert "lab_unstable" not in out["signals"]


# ─── IMP-06 — rabbit_hole detection ──────────────────────────────────────────


def test_rabbit_hole_same_narrate_text_detected(tmp_path: Path):
    """IMP-06: same 🔍 narrate text ≥3 times in window → rabbit_hole signal."""
    ts = _now_ts()
    text = "curl http://10.10.10.1/test returns 404"
    session = make_session(
        tmp_path,
        jsonl_lines=[
            {"ts": ts, "event": "narrate", "stream": "🔍", "detail": text},
            {"ts": ts, "event": "narrate", "stream": "🔍", "detail": text},
            {"ts": ts, "event": "narrate", "stream": "🔍", "detail": text},
        ],
    )
    code, out = run(session)
    assert code == 1
    assert "rabbit_hole" in out["signals"]
    assert out["recommendation"] == "switch_vector"


def test_rabbit_hole_consecutive_events_detected(tmp_path: Path):
    """IMP-06: same event detail ≥4 consecutive times → rabbit_hole signal."""
    ts = _now_ts()
    detail = "gobuster /admin always 403"
    session = make_session(
        tmp_path,
        jsonl_lines=[
            {"ts": ts, "event": "recon_attempt", "detail": detail},
            {"ts": ts, "event": "recon_attempt", "detail": detail},
            {"ts": ts, "event": "recon_attempt", "detail": detail},
            {"ts": ts, "event": "recon_attempt", "detail": detail},
        ],
    )
    code, out = run(session)
    assert code == 1
    assert "rabbit_hole" in out["signals"]


def test_rabbit_hole_not_detected_when_varied(tmp_path: Path):
    """IMP-06: varied narrate texts below threshold → no rabbit_hole."""
    ts = _now_ts()
    session = make_session(
        tmp_path,
        jsonl_lines=[
            {"ts": ts, "event": "narrate", "stream": "🔍", "detail": "curl /admin → 200"},
            {"ts": ts, "event": "narrate", "stream": "🔍", "detail": "gobuster found /config"},
            {"ts": ts, "event": "narrate", "stream": "🔍", "detail": "nmap port 8080 open"},
        ],
    )
    code, out = run(session)
    assert "rabbit_hole" not in out["signals"]


def test_rabbit_hole_old_events_ignored(tmp_path: Path):
    """IMP-06: 3 same-text events but older than 20min window → no rabbit_hole."""
    text = "curl http://10.10.10.1/ returns 403"
    session = make_session(
        tmp_path,
        jsonl_lines=[
            {"ts": "2026-01-01T00:00:00Z", "event": "narrate", "stream": "🔍", "detail": text},
            {"ts": "2026-01-01T00:01:00Z", "event": "narrate", "stream": "🔍", "detail": text},
            {"ts": "2026-01-01T00:02:00Z", "event": "narrate", "stream": "🔍", "detail": text},
        ],
    )
    code, out = run(session)
    assert "rabbit_hole" not in out["signals"]
