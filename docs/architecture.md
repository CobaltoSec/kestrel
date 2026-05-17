# Kestrel — Architecture

> Architecture overview. v0.3 (2026-05-17).

---

## What is Kestrel?

An engagement orchestrator for HackTheBox VMs. Its differentiator is an intelligence layer applied before touching the network: on retired machines it reads public writeups to go directly to the CVE; on active machines it classifies the target by ports/services to prioritize the attack vector.

**Not:** a scanner, an exploit framework, or a bot that solves HTB automatically.
**Is:** a decision system that reduces an unknown VM to an executable sequence of steps, with human-in-the-loop (HITL) only at the ~6 moments that actually matter.

---

## 4-Layer Model

```
┌─────────────────────────────────────────────────────────┐
│  4. MEMORY                                              │
│     estado.md · state.json · writeup.md                 │
│     KB synthesis · publish-hint                         │
│     → persists between sessions, learns from each run   │
├─────────────────────────────────────────────────────────┤
│  3. EXECUTION                                           │
│     delegated to /pentest --mode lab                    │
│     p2-discovery → p3-vuln → p4-exploit                 │
│     → Kestrel orchestrates, doesn't execute directly    │
├─────────────────────────────────────────────────────────┤
│  2. ORCHESTRATION                                       │
│     phases p0 → p1 → p1.5 → p2 → p3 → p4 → p5 → p6   │
│     mode switching · HITL gates · continuous narration  │
│     → workflow engine, core of Kestrel                  │
├─────────────────────────────────────────────────────────┤
│  1. INTEL                                               │
│     WebSearch retired + blind_fingerprint.py active     │
│     intel.md · fingerprint.json · KB auto-query         │
│     → the hover before the dive                         │
└─────────────────────────────────────────────────────────┘
```

---

## Layer 1 — Intel

**Responsibility**: know the target before touching the network.

**Guided mode (retired machines):**
- WebSearch 4 parallel queries (writeup sources)
- Fetch top-3 URLs → anti-spoiler synthesis
- Output: `intel.md` with confidence (high/medium/low) + probable chain

**Blind mode (active machines):**
- HTB TOS: no writeups for active machines → no WebSearch
- `blind_fingerprint.py` post-discovery:
  - Classifies ports/services/banners → attack_categories with confidence scores
  - KB auto-query for categories with confidence ≥ 0.80
- Output: `fingerprint.json` with attack_categories + kb_results

---

## Layer 2 — Orchestration

**Responsibility**: complete workflow, decisions, HITL.

| Phase | Function |
|---|---|
| p0 | Dashboard + active session detection + proactive resume |
| p1 | Machine list via HTB API, extract MACHINE_RETIRED flag |
| p1.5 | Intel: guided (WebSearch) or blind (fingerprint handoff) |
| p2 | SESSION_DIR + roe.md + VPN + spawn + ping |
| p3 | **Core**: guided/blind branch, continuous narration, critical HITL |
| p4 | Submit user+root via HTB API, update profile |
| p5 | Writeup + KB synthesis + gap analysis + publish-hint |
| p6 | Release + VPN down + debrief |

**Key design decisions:**
- HITL ~6 (vs ~19 pre-redesign) — only at vector exploit (H3) and destructive privesc (H5 conditional)
- Continuous narration without Enter mid-flight
- Stuck gate Easy threshold=1 guided skip, 1 attempt blind
- Hash Policy: 5 min max CPU → GPU/hint automatic

---

## Layer 3 — Execution

**Responsibility**: run the actual commands against the target.

Kestrel **does not execute directly**. It delegates to `/pentest --mode lab`:
- Discovery → nmap + recon.md
- Vuln → prioritized vuln checks
- Exploit → exploit + post-exploitation

**L2 → L3 handoff contract:**
```
MODE=lab
TARGET=<TARGET_IP>
ENGAGEMENT_DIR=<SESSION_DIR>
PRIORITY_SERVICE=<from fingerprint.json in blind mode>  # optional
SKIP_GENERIC_NUCLEI=true                                # blind with conf ≥ 0.70
```

**Current bottleneck**: handoff is one-way. If /pentest finds something unexpected (complex AD chain, RBCD), Kestrel doesn't replan — it only executes the stuck gate. Future improvement: L3→L2 feedback loop via estado.md parsing.

---

## Layer 4 — Memory

**Responsibility**: persist state between sessions + learn from each engagement.

**During engagement:**
- `estado.md` — narrative progress notes
- `state.json` — state machine (current_phase, kali_listeners, next_step_hint, etc.)

**Post-engagement:**
- `writeup.md` — complete writeup (8 sections)
- KB synthesis → staging for ingestion into pgvector
- `publish-hint.json` → queue for eventual blog publication

**Cross-session resume:**
- `resume_validator.sh` runs on Kali — validates VPN + machine IP + listeners
- p0 invokes it proactively when a paused session is detected
- Auto-recovery: re-up VPN + respawn machine + restart listeners

**L4 → L1 loop**: KB syntheses generated post-engagement feed into future blind fingerprints via KB auto-query.

---

## Handoff Contracts

### L1 → L2
`intel.md` (guided) or `fingerprint.json` (blind) in `SESSION_DIR/`:
```json
{
  "intel_confidence": "high|medium|low|none",
  "htb_mode": "guided|blind",
  "blind_fingerprint_top": "ad-abuse",
  "blind_fingerprint_conf": 0.85
}
```

### L2 → L3
Variables in `roe.md` frontmatter:
```yaml
mode: lab
htb_mode: guided|blind
target: 10.10.10.x
priority_service: smb        # blind only
skip_generic_nuclei: true    # blind with conf ≥ 0.70
```

### L3 → L4
Artifacts in `SESSION_DIR/`:
- `recon.md`, `findings.md`, `loot/user.txt`, `loot/root.txt`
- Updates to `estado.md` and `state.json` (techniques[], gaps_found[])

---

## Bottlenecks

| Layer | Bottleneck | Impact | Future mitigation |
|---|---|---|---|
| **L1** | Blind mode without writeups = port classification only. Works for Easy/Medium but loses nuance in Hard AD chains. | ~30% less context on complex chains | v1.1: multi-path hypothesis (top-3 probable chains with probability) |
| **L2** | L2→L3 handoff is one-way. If /pentest finds something unexpected, Kestrel doesn't replan. | Garfield: RBCD chain not in flow → paused | v1.2: feedback loop L3→L2 via estado.md parsing |
| **L3** | Handoff contract doesn't force /pentest to return "stuck" signals. | Stuck in L3 = stuck in Kestrel | v1.1: event/webhook from p4-exploit back to Kestrel |
| **L4** | KB synthesis is opt-in. | Some sessions don't synthesize | v1.1: auto synthesis default=true for Medium+ |

---

## Decision Log

| Decision | Why |
|---|---|
| **Retired-only WebSearch** | HTB TOS prohibits writeups for active machines. Skip for compliance, not capability. |
| **HITL ~6 vs ~19** | Redesign reduced prompts by eliminating trivial confirmations. Only H3 (exploit vector) and H5 (destructive privesc) are mandatory. |
| **Continuous narration without Enter** | Better learning experience — read output while it runs, not at the end. Enter mid-flight interrupts flow and increases friction. |
| **Hash Policy 5 min → GPU/hint** | bcrypt case: 45 min CPU that was avoidable. Proactive policy = don't block flow on a hash. |
| **Stuck gate Easy threshold=1** | Easy guided: skip (intel already guides). Easy blind: 1 failed attempt = hint. Aggressive but justified — Easy shouldn't need more. |
| **L3 delegated to /pentest** | Kestrel doesn't re-implement recon/vuln/exploit. Inherits 90% of the logic. Cost: rigidity in handoff (see bottlenecks). |

---

## Iteration Log

### v0.1 — 2026-05-08
- L1: Blind fingerprinting layer (`blind_fingerprint.py` + p1.5 + p3 PASO 1.5)
- L2: Snapshot hooks in p3 (next_step_hint + last_phase_completed)
- L4: Resume hardening: `resume_validator.sh` + p0 proactive validation + extended state schema
- Docs: this architecture doc + README

### v0.2 — 2026-05-11
- L1: `blind_fingerprint.py` multi-path `attack_plan` output (primary + alternatives + parallel tracks)
- L2: `wordlist_strategy.py`, `stuck_detector.py`, `parallel_explorer.py`, `crack_status.py`, `state_inspector.py`
- L4: Cross-session dedup arrays (`tried_credentials`, `tried_endpoints`, `tried_hashes`)
- Tests: 58 → 66 tests across 6 modules

### v0.3 — 2026-05-17 — Speed & Observability

**Problem statement:** 10-session audit identified 5 time-sinks causing 6-30h sessions on 30min-2h targets.

| Time-sink | Measured loss | Fix |
|---|---|---|
| Bcrypt CPU without GPU policy | 25-30 min | `wordlist_strategy.py` `recommendation=gpu_async` auto-escalation |
| `stuck_detector` fires with `alternatives: []` | 4h30 (Helix) | STATIC_ALTERNATIVES fallback + `fingerprint.json` propagation |
| VPN/VM instability without detection | 6h+ (Garfield) | `lab_unstable` signal, 9 patterns, 10-min window |
| Cross-OS Docker blindspot | 10h (MonitorsFour) | `web_in_container` heuristic: Windows host + Linux web stack |
| sessions.jsonl almost empty (telemetría rota) | All sessions blind | `tool-timer.sh` + `heartbeat.py` + session budget enforcement |

**New components:**
- `scripts/tool-timer.sh` — command wrapper with `duration_s` telemetry
- `scripts/heartbeat.py` — session observability dashboard + budget alerting (exit codes 0-3)
- `scripts/wordlist_strategy.py` `recommendation` field — cpu / gpu_async / hint_first
- `blind_fingerprint.py` `web_in_container` category + `STATIC_ALTERNATIVES` guarantee
- `stuck_detector.py` `lab_unstable` signal + `alternatives_from_attack_plan()` propagation
- Session budget enforcement: `session_budget_min` in `last-cycle.json` + HITL prompt at 100%
- Closure HARD GATE: p6 blocks until `feedback.md` has all 5 required sections
