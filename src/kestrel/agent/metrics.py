"""Run metrics — KPIs per agent run, persisted to state_dir/runs/."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class RunMetrics:
    machine: str
    mode: str
    provider: str
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Counters
    iterations: int = 0
    tools_called: int = 0
    stuck_events: int = 0
    hitl_gates: int = 0
    tokens_input: int = 0
    tokens_output: int = 0

    # Timing
    user_flag_at: str | None = None
    root_flag_at: str | None = None
    time_to_user_flag_min: float | None = None
    time_to_root_flag_min: float | None = None

    # Strategy
    vector_chosen: str | None = None
    # filled post-run by operator: "correct" | "partial" | "wrong"
    vector_accuracy: str | None = None

    # Outcome
    finished_at: str | None = None
    outcome: str | None = None  # "owned" | "abandoned" | "budget_exceeded" | "max_iterations"

    def record_flag(self, flag_type: str) -> None:
        """Mark when a flag (user/root) was obtained."""
        now = datetime.now(timezone.utc)
        ts = now.isoformat()
        started = datetime.fromisoformat(self.started_at)
        elapsed_min = round((now - started).total_seconds() / 60, 1)
        if flag_type == "user":
            self.user_flag_at = ts
            self.time_to_user_flag_min = elapsed_min
        elif flag_type == "root":
            self.root_flag_at = ts
            self.time_to_root_flag_min = elapsed_min

    def finish(self, outcome: str) -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat()
        self.outcome = outcome

    def save(self, runs_dir: Path, session_slug: str) -> Path:
        runs_dir.mkdir(parents=True, exist_ok=True)
        ts = self.started_at[:19].replace(":", "").replace("-", "").replace("T", "-")
        path = runs_dir / f"{session_slug}-{ts}.json"
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False))
        return path

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
