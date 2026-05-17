#!/usr/bin/env python3
"""
Kestrel heartbeat.py — session observability dashboard + budget alerting.

Reads sessions.jsonl + last-cycle.json + estado.md mtime to emit a
human-readable dashboard and append a `heartbeat` event to sessions.jsonl.

Exit codes:
    0 = OK (elapsed < 80% of budget, or no budget info available)
    1 = WARN (80-100% of budget consumed)
    2 = CRITICAL (100-150% of budget) — skill triggers the budget-exceeded HITL
    3 = ABANDON_RECOMMENDED (> 150%) — skill recommends aborting the session
    4 = error (session-dir missing or unreadable)

Usage:
    python3 scripts/heartbeat.py \\
        --session-dir sectors/red-team/htb-sessions/htb-2026-05-13-monitorsfour \\
        [--state-file fleet/agents/htb/state/last-cycle.json] \\
        [--no-jsonl]
"""
import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


BUDGET_BY_DIFFICULTY = {
    "easy":   90,
    "medium": 180,
    "hard":   360,
    "insane": 480,
}

PHASE_HINTS = {
    "vuln_scan": (
        "Vuln scan activo >30 min — considerá: cambiar vector, hint mode, o pause."
    ),
    "exploit": (
        "Exploit en curso >45 min — stuck gate recomendado."
    ),
}


def parse_iso(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def top_time_sinks(events: list[dict], top_n: int = 3) -> list[tuple[str, int]]:
    """Sum duration_s per tool from tool_end events."""
    totals: dict[str, int] = defaultdict(int)
    for e in events:
        if e.get("event") == "tool_end":
            tool = e.get("detail", "unknown")
            dur = e.get("duration_s", 0) or 0
            totals[tool] += int(dur)
    return sorted(totals.items(), key=lambda x: x[1], reverse=True)[:top_n]


def last_activity_minutes(session_dir: Path, events: list[dict],
                           now: datetime) -> float:
    """Minutes since last file was modified or event was logged."""
    candidates: list[datetime] = []
    for fname in ("estado.md", "findings.md", "sessions.jsonl"):
        p = session_dir / fname
        if p.exists():
            candidates.append(
                datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
            )
    if events:
        last_ts = parse_iso(events[-1].get("ts", ""))
        if last_ts:
            candidates.append(last_ts)
    if not candidates:
        return 0.0
    latest = max(candidates)
    return max(0.0, (now - latest).total_seconds() / 60)


def load_machine_state(state_file: Path | None, session_dir: Path) -> dict:
    """Extract session_started_at, session_budget_min, current_phase from last-cycle.json."""
    if not state_file or not state_file.exists():
        return {}
    try:
        state = json.loads(state_file.read_text())
    except (json.JSONDecodeError, OSError):
        return {}

    machines = state.get("data", {}).get("machines", {})
    dir_name = session_dir.name  # e.g. htb-2026-05-17-monitorsfour

    machine = None
    # Try matching machine slug at end of dir name
    for key in machines:
        if dir_name.endswith(f"-{key}") or dir_name == key:
            machine = machines[key]
            break

    # Fallback: match via session_slug field
    if machine is None:
        for val in machines.values():
            if val.get("session_slug") == dir_name:
                machine = val
                break

    # Last resort: single-machine state
    if machine is None and len(machines) == 1:
        machine = next(iter(machines.values()))

    if not machine:
        return {}

    return {
        "session_started_at": (
            machine.get("session_started_at") or machine.get("started_at")
        ),
        "session_budget_min": machine.get("session_budget_min"),
        "machine_difficulty": machine.get("machine_difficulty", "Easy"),
        "current_phase": state.get("data", {}).get("current_phase", "unknown"),
        "last_phase_completed": machine.get("last_phase_completed"),
    }


def compute_budget(machine_state: dict,
                   now: datetime) -> tuple[float | None, int | None, str]:
    """Returns (elapsed_min, budget_min, difficulty_key)."""
    started_str = machine_state.get("session_started_at")
    if not started_str:
        return None, None, "unknown"
    started = parse_iso(started_str)
    if not started:
        return None, None, "unknown"
    elapsed_min = (now - started).total_seconds() / 60

    difficulty = (machine_state.get("machine_difficulty") or "Easy").lower()
    budget_min = machine_state.get("session_budget_min") or BUDGET_BY_DIFFICULTY.get(
        difficulty, 90
    )
    return elapsed_min, int(budget_min), difficulty


def exit_code_for_budget(elapsed: float | None, budget: int | None) -> int:
    if elapsed is None or budget is None:
        return 0
    ratio = elapsed / budget
    if ratio >= 1.5:
        return 3
    if ratio >= 1.0:
        return 2
    if ratio >= 0.8:
        return 1
    return 0


def suggest_heuristic(machine_state: dict, elapsed_min: float | None,
                       idle_min: float) -> str | None:
    phase = machine_state.get("current_phase") or ""
    for key, hint in PHASE_HINTS.items():
        if key in phase:
            threshold = 30 if key == "vuln_scan" else 45
            if elapsed_min and elapsed_min > threshold:
                return hint
    if idle_min > 20:
        return f"Sin actividad detectada hace {idle_min:.0f} min — ¿todo bien?"
    return None


def emit_dashboard(
    machine_state: dict,
    elapsed_min: float | None,
    budget_min: int | None,
    budget_exit: int,
    idle_min: float,
    sinks: list[tuple[str, int]],
    event_count: int,
) -> None:
    W = 60
    lines = ["", "═" * W, "💓 KESTREL HEARTBEAT", "═" * W]

    phase = (
        machine_state.get("current_phase")
        or machine_state.get("last_phase_completed")
        or "desconocida"
    )
    lines.append(f"  Fase actual:    {phase}")
    lines.append(f"  Última act.:    hace {idle_min:.0f} min")
    lines.append(f"  Eventos log:    {event_count}")

    if elapsed_min is not None and budget_min is not None:
        pct = int(elapsed_min / budget_min * 100)
        filled = min(10, pct // 10)
        bar = "█" * filled + "░" * (10 - filled)
        sym = {0: "✅", 1: "⚠️ ", 2: "🔴", 3: "💀"}.get(budget_exit, "?")
        lines.append(
            f"  Tiempo:         {elapsed_min:.0f} min / {budget_min} min "
            f"[{bar}] {pct}% {sym}"
        )
    else:
        lines.append("  Tiempo:         n/a (session_started_at no disponible)")

    if sinks:
        lines.append("  Top time-sinks:")
        for tool, secs in sinks:
            lines.append(f"    {tool:<20} {secs // 60}m {secs % 60}s")

    suggestion = suggest_heuristic(machine_state, elapsed_min, idle_min)
    if suggestion:
        lines.append(f"  💡 {suggestion}")

    if budget_exit >= 2:
        lines.append("")
        if budget_exit == 3:
            lines.append("  💀 BUDGET ×1.5 — abandono recomendado (skill lanza prompt).")
        else:
            lines.append("  🔴 BUDGET EXCEDIDO — (skill lanza prompt de revisión).")

    lines.append("═" * W)
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--session-dir",  required=True, type=Path)
    ap.add_argument("--state-file",   default=None,  type=Path,
                    help="last-cycle.json (optional, enables budget alerting)")
    ap.add_argument("--no-jsonl",     action="store_true",
                    help="Skip appending heartbeat event to sessions.jsonl")
    args = ap.parse_args()

    if not args.session_dir.exists():
        print(f"ERROR: session-dir not found: {args.session_dir}", file=sys.stderr)
        sys.exit(4)

    now = datetime.now(timezone.utc)
    jsonl_path = args.session_dir / "sessions.jsonl"

    events = read_jsonl(jsonl_path)
    machine_state = load_machine_state(args.state_file, args.session_dir)
    elapsed_min, budget_min, _ = compute_budget(machine_state, now)
    idle_min = last_activity_minutes(args.session_dir, events, now)
    sinks = top_time_sinks(events)
    budget_exit = exit_code_for_budget(elapsed_min, budget_min)

    emit_dashboard(
        machine_state, elapsed_min, budget_min,
        budget_exit, idle_min, sinks, len(events),
    )

    if not args.no_jsonl:
        ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        detail_parts = [f"idle={idle_min:.0f}min", f"events={len(events)}"]
        if elapsed_min is not None:
            detail_parts.insert(0, f"elapsed={elapsed_min:.0f}min")
        if budget_min is not None:
            detail_parts.insert(1, f"budget={budget_min}min")
        entry = {
            "ts": ts,
            "phase": "heartbeat",
            "event": "heartbeat",
            "detail": " ".join(detail_parts),
        }
        with jsonl_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")

    sys.exit(budget_exit)


if __name__ == "__main__":
    main()
