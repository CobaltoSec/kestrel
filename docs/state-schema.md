# State Schema — Kestrel Framework v0.3

Defines the shape of state files written and consumed by Kestrel scripts.
All scripts follow the same read/write contracts documented here.

---

## sessions.jsonl

Append-only audit log per session. One JSON object per line.

### Base event shape

```json
{"ts": "<ISO8601>", "phase": "<phase-id>", "event": "<event-type>", "detail": "<free-text>"}
```

### v0.3 extension — `duration_s` (optional)

Tool-wrapped commands add `duration_s` (wall-clock seconds) to `tool_end` events.
Field is absent on events that predate v0.3. Consumers must use `.get("duration_s", 0)`.

```json
{"ts": "2026-05-17T10:02:00Z", "phase": "tool-timer", "event": "tool_end",
 "detail": "nmap", "duration_s": 120, "exit_code": 0}
```

### Event type catalog

| Event | Source | Fields |
|---|---|---|
| `tool_start` | `tool-timer.sh` | `detail=<tool-name>` |
| `tool_end` | `tool-timer.sh` | `detail=<tool-name>`, `duration_s`, `exit_code` |
| `heartbeat` | `heartbeat.py` | `detail="elapsed=Xmin budget=Ymin idle=Zmin events=N"` |
| `session_start` | Skill p2 | `detail="budget=Nmin difficulty=<X>"` |
| `session_budget_alert` | Skill p3 | `detail="elapsed=N budget=M choice=<c|p|h|a>"` |
| `fingerprint_complete` | Skill p3 | `detail="top=<cat> conf=<X> kb=<true|false>"` |
| `phase_transition` | Skill p3 | `detail="<from>→<to>"` |
| `auto_pivot` | Skill p3 | `detail="from=<vec> to=<vec> via=parallel_explorer"` |
| `hash_policy_triggered` | Skill p3 / Hash Policy | `detail="<type>:<elapsed>s no match → <option>"` |
| `hash_policy_decision` | Skill p3 / Hash Policy | `detail="recommendation=<X> elapsed_min=<N> round=<N>"` |
| `crack_async_dispatched` | Skill p3 / Hash Policy | `detail="job_id=<ID> mode=<M> wordlist=<W>"` |
| `hint_used` | Skill p3 | `detail="phase=<X> recommendation=<X>"` |
| `flag_submitted` | Skill p4 | `detail="user: OK|FAIL, root: OK|FAIL"` |
| `feedback_complete` | Skill p6 | `detail="<file_size> bytes"` |
| `pentest_complete` | Skill p3 | `detail="user+root via <vectors> (mode=<X>, time=<N>min)"` |

### Backward compat

Consumers reading `sessions.jsonl` must tolerate:
- Missing `duration_s` → default to `0` or `None`
- Unknown event types → skip silently
- Malformed lines → skip (use `try/except json.JSONDecodeError`)

---

## last-cycle.json — `data.machines.<slug>` fields

Fields added in v0.2 and v0.3. All optional — older code ignores them.

### v0.2 cross-session tracking

| Field | Type | Description |
|---|---|---|
| `tried_credentials` | array | Creds already attempted; prevents repeat sprays |
| `tried_endpoints` | array | HTTP endpoints already enumerated |
| `tried_hashes` | array | Hash+wordlist combos already cracked |
| `attack_plan` | object | Fingerprint attack plan (primary + alternatives) |
| `current_vector` | object | Active exploit vector with budget timer |
| `hash_jobs` | array | Async GPU crack jobs dispatched via crack-helper.sh |

### v0.3 session budget

| Field | Type | Description |
|---|---|---|
| `session_started_at` | ISO8601\|null | Set by skill p2 on engagement start |
| `session_budget_min` | int\|null | Total budget: 90/Easy, 180/Medium, 360/Hard |
| `session_budget_alerts_triggered` | array | ISO8601 timestamps when budget gate fired |

#### `session_started_at` usage

Used by `heartbeat.py` to compute elapsed time and emit budget alerts.
Set at p2-engagement-setup (PASO 7) alongside the existing `started_at` field.
`started_at` remains the canonical session start; `session_started_at` is the
budget clock start — they are set to the same timestamp.

#### Budget thresholds (heartbeat.py)

| Threshold | Exit code | Action |
|---|---|---|
| < 80% | 0 | OK |
| 80-100% | 1 | WARN displayed in dashboard |
| 100-150% | 2 | CRITICAL — skill triggers budget-exceeded HITL |
| > 150% | 3 | ABANDON_RECOMMENDED — skill prompts session abort |

---

## wordlist-plan.json (wordlist_strategy.py output)

```json
{
  "generated_at": "<ISO8601>",
  "machine": "<name>",
  "hash_type": "<bcrypt|md5|...>",
  "recommendation": "<cpu|gpu_async|hint_first>",
  "plan": [
    {
      "priority": 1,
      "wordlist_id": "context_runtime",
      "wordlist_path": "/tmp/context-<slug>.txt",
      "rules": "none",
      "size": 240,
      "estimated_time_minutes": 1,
      "needs_generation": true
    }
  ]
}
```

### `recommendation` values (v0.3)

| Value | Condition | Action |
|---|---|---|
| `cpu` | Fast hash OR short estimated time (<5 min) | Run CPU crack normally |
| `gpu_async` | Slow hash AND (estimated >30 min OR wordlist >1M) | Skip CPU, go straight to GPU async |
| `hint_first` | Otherwise | Offer intel/writeup hint before spending GPU |

---

## fingerprint.json (blind_fingerprint.py output)

```json
{
  "target_ip": "10.10.11.X",
  "os_likely": "linux|windows|unknown",
  "attack_categories": [
    {"category": "web-exploit", "confidence": 0.70, "tactics": [3, 4]}
  ],
  "attack_plan": {
    "primary_chain": {"categories": ["web-exploit"], "confidence": 0.70, "rationale": "..."},
    "alternative_chains": [{"categories": ["smb-exploit"], "confidence": 0.55, "rationale": "..."}],
    "parallel_tracks": [],
    "execution_hint": "single-path|multi-path|wide-scan"
  }
}
```

`alternative_chains` is guaranteed non-empty when any `attack_categories` entry
has confidence ≥ 0.5, thanks to the static fallback in v0.3 (`STATIC_ALTERNATIVES`).

---

## stuck.json (stuck_detector.py output)

```json
{
  "stuck": true,
  "signals": ["hash_stuck", "lab_unstable"],
  "recommendation": "switch_vpn_server|release_respawn|escalate_gpu|switch_vector|reset_listener|continue",
  "alternatives": ["smb-exploit", "docker-escape"],
  "rationale": "...",
  "session_dir": "...",
  "scanned_at": "<ISO8601>"
}
```

`lab_unstable` signal (v0.3): fires when ≥3 network error patterns appear in
sessions.jsonl in the last 10 minutes.
