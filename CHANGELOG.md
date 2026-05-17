# Changelog

All notable changes to Kestrel are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.3.0] — 2026-05-17

### Added

- **P0.2 · `scripts/tool-timer.sh`** — Bash wrapper that stamps `tool_start` /
  `tool_end` events (with `duration_s`) around any command. Feeds telemetry into
  `sessions.jsonl` so per-tool time-sinks are measurable. Forwards stdout/stderr
  transparently and mirrors the wrapped command's exit code.
- **P0.3 + P5.3 · `scripts/heartbeat.py`** — Session observability dashboard. Reads
  `sessions.jsonl` + `last-cycle.json` and prints elapsed time, top time-sinks, phase,
  idle window, and a heuristic suggestion. Budget alerting: exit 1 at 80%, exit 2 at
  100%, exit 3 at 150% of `session_budget_min`.
- **P1.1 · `wordlist_strategy.py` `recommendation` field** — Auto-decides CPU vs GPU
  based on hash type and estimated time. `bcrypt` + large wordlists → `gpu_async`;
  fast hashes → `cpu`; slow hashes with small lists → `hint_first`.
- **P2.1 · `blind_fingerprint.py` `STATIC_ALTERNATIVES` fallback** — Guarantees
  `attack_plan.alternative_chains` is never empty when a category scores ≥ 0.5.
  Chains are marked `source="static_fallback"` so the skill can narrate appropriately.
- **P2.3 · `stuck_detector.py` `alternatives_from_attack_plan()`** — Reads
  `fingerprint.json` and propagates enriched `alternative_chains` into the stuck signal
  output so `alternatives` is never `[]` when a fingerprint exists.
- **P3.1 · `stuck_detector.py` `lab_unstable` signal** — Detects ≥ 3 network error
  patterns (`connection reset`, `no route to host`, `ssh timeout`, etc.) in the last
  10 minutes and recommends `switch_vpn_server`.
- **P4.1 · `blind_fingerprint.py` `web_in_container` category** — Heuristic that fires
  when a Windows host exposes only web ports but banners/framework suggest a Linux
  stack (Cacti, nginx, PHP, etc.). Confidence 0.70. Prevents the MonitorsFour
  cross-OS pivot blindspot.
- **`docs/state-schema.md`** — Full public schema for `sessions.jsonl` event catalog,
  `last-cycle.json` v0.3 budget fields, `wordlist-plan.json` `recommendation`, and
  `fingerprint.json` `alternative_chains` guarantee.

### Test coverage
- 7 new test modules: `test_tool_timer.py`, `test_heartbeat.py` (new scripts).
- New test functions in `test_wordlist_strategy.py` (P1.1: recommendation field × 4),
  `test_fingerprint.py` (P2.1: STATIC_ALTERNATIVES KB-miss, P4.1: web_in_container ×2),
  `test_stuck_detector.py` (P2.3: fingerprint alternatives propagation, P3.1: lab_unstable ×3).

### Added (v0.2 — sub-bloques A–G, KESTREL-V02-IMPL)
- **A · Golden test dataset** — `tests/test_fingerprint_golden.py` with fixtures for
  Kobold, CCTV, Silentium, WingData, MonitorsFour and Garfield. Regression suite
  guards `blind_fingerprint.py` against confidence/categorization drift.
- **B · `scripts/wordlist_strategy.py`** — context-aware wordlist plan generator.
  Tokenizes machine name + vhosts, builds a tiny runtime wordlist, then emits a
  priority-ordered plan branching by hash speed (fast vs bcrypt/argon2). Includes
  CeWL recipe (string only — caller executes).
- **C · Cross-session state extension** — three optional arrays in
  `last-cycle.json.data.machines.<slug>`: `tried_credentials`, `tried_endpoints`,
  `tried_hashes`. Helper `scripts/state_inspector.py` exposes list/check/summary
  commands so future sessions avoid retrying what already failed. Fully backward
  compatible — fields are optional.
- **D · Async GPU crack** — `crack-helper.sh --async` writes a job state JSON and
  emits a notebook addendum to paste at the end of Colab cell 7.
  `scripts/crack_status.py` polls the result. While the GPU crunches, Kestrel can
  keep exploring other vectors.
- **E · Multi-path `attack_plan` output** — `blind_fingerprint.py` now emits an
  additive `attack_plan` field with `primary_chain`, `alternative_chains`,
  `parallel_tracks` and an `execution_hint` (single-path / multi-path / wide-scan).
  Existing `attack_categories` field unchanged — v0.1 consumers unaffected.
- **F · `scripts/parallel_explorer.py`** — concurrent task runner (thread pool,
  default 4 workers). Each task = an SSH command to Kali with its own timeout.
  Stdout/stderr tails (4 KB) consolidated into one JSON output. `--dry-run` mode
  for CI testing.
- **G · `scripts/stuck_detector.py`** — parses `estado.md`, `findings.md` and
  `sessions.jsonl` of a session and emits one of four signals (`shell_lost`,
  `hash_stuck`, `cred_exhausted`, `progress_stalled`) plus a recommendation and
  alternative vectors. Validated against the real MonitorsFour S3 session.

### Test infrastructure
- 6 new test modules; full suite goes from 3 → 58 tests (Windows) / 66 (Linux CI).
- Fixed pre-existing `test_fingerprint.py` calls missing the required `--output`
  flag.
- Cleaned unused imports in `scripts/resume_validator.py` and test modules
  (ruff clean across `scripts/` and `tests/`).

### Notes
- v0.2 modules are NOT yet wired into the Kestrel skill phases — that
  integration is the follow-up block `KESTREL-V02-VALIDATE` (gated by a real test
  run against MonitorsFour S4). v0.2.0 GitHub release happens in
  `KESTREL-V02-PUBLISH` after validation.

---

## [0.1.0] — 2026-05-08

### Added
- `scripts/blind_fingerprint.py` — L1 intel layer. Classifies nmap/httpx output into
  8 attack categories with confidence scores. Optional pgvector KB integration.
- `scripts/resume_validator.py` / `resume_validator.sh` — L4 cross-session health check.
  Validates VPN up, machine reachable, listeners alive. Returns JSON recovery actions.
- `docs/architecture.md` — 4-layer architecture doc (Intel / Orchestration / Execution / Memory).
- ATT&CK coverage table (Recon, Initial Access, Execution, Privilege Escalation,
  Credential Access, Discovery).

### Case studies
- **Kobold** (Easy Linux, retired) — CVE-2026-23520 command injection → Docker socket
  escape → root. Guided mode, ~90 min, intel match=full.
- **Garfield** (Hard Windows, retired) — Blind mode. Chain: SYSVOL → RBCD → KeyList attack.
  HTB flag regeneration bug documented (not a Kestrel issue).
