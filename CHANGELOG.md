# Changelog

All notable changes to Kestrel are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### v0.5.0 (RT-KESTREL-V05 — Blind Effectiveness Sprint)

**10 mejoras de confiabilidad e inteligencia blind (2026-06-14):**

#### P0 — Bugs críticos
- **IMP-01** `transport/ssh.py`: `exec()` ahora usa `channel.settimeout()` en lugar de pasar timeout a `exec_command` — elimina el bloqueo indefinido de `stdout.read()`. Auto-reconexión: captura `socket.timeout`/`SSHException`/`EOFError`, retry 1 vez. `_run_kali()` prefixea comandos pesados con `timeout {N}s` en Kali-side.
- **IMP-02** `mcp/tools/intel.py`: `intel_classify_blind` — `query_kb()` síncrono → `await asyncio.wait_for(asyncio.to_thread(...))`. Elimina bloqueo del event loop MCP.
- **IMP-03** `mcp/tools/vuln.py`: `vuln_nuclei_targeted` — templates via `-id CVE1,CVE2` (comma-separated) en lugar de múltiples `-id` repetidos. Nuclei v3 ignoraba todos excepto el último.
- **IMP-04** `mcp/tools/state.py`: `state_write_machine` valida nombre de máquina con `[a-z0-9][a-z0-9-]{0,48}` — rechaza XSS/SSTI/null-bytes antes de persistir.

#### P1 — Efectividad blind
- **IMP-07** `core/fingerprint.py` + `mcp/tools/intel.py`: `KB_CONFIDENCE_THRESHOLD` 0.80 → 0.60. Targets web-only ahora acceden a KB. Agregar `kb_active: bool` + `kb_note` al output de `intel_classify_blind` e `intel_next_step`.
- **IMP-08** `mcp/tools/recon.py`: nmap `full` + `--host-timeout 600s --max-rtt-timeout 300ms --initial-rtt-timeout 50ms`. UDP top-ports=100 + timing. Nuevo perfil `os_detect`.
- **IMP-09** `mcp/prompts/kickoff.py`: machine_lines enriquecido — `target_ip`, `machine_os`, línea `↳` con `next_hint`/`intel_conf`/`fingerprint`/`session` al retomar.
- **IMP-10** `mcp/tools/intel.py`: `intel_next_step` — nuevas fases `p3a_pre_foothold` (exploit-focused) y `p3b_post_foothold` (post-shell). `p3_foothold` conservado por compatibilidad.
- **IMP-12** `transport/kali_proxy.py` + `transport/base.py`: `ExecResult` + `infrastructure_error: bool`. `via_kali()` retorna ExecResult estructurado en lugar de propagar excepción paramiko cruda.
- **IMP-13** `core/fingerprint.py`: `score_rules()` normaliza por `max_possible` de la categoría — `0.95` solo con todos los signals activos.
- **IMP-17** `mcp/tools/intel.py`: `intel_next_step` auto-carga `tried_credentials` + `tried_endpoints` desde state_store para dedup cross-session. Expone `auto_tried_merged: int`.

**Tests:** 382 passed, 16 skipped — +~40 tests nuevos en transport, recon, vuln, intel, fingerprint, state, prompts.

---

### v0.5.0-dev (RT-KESTREL-V05-W4-O2 — Intel Tools)

**+2 MCP tools en categoría `intel`:**
- `intel_next_step(phase, findings, tried, os_hint, session_dir)` — consulta KB pgvector dado estado del engagement, filtra caminos ya intentados (Jaccard ≥0.6), detecta señales stuck (shell_lost/hash_stuck/cred_exhausted), fallback a templates builtin por fase. Retorna pasos priorizados con comandos exactos.
- `lolbin_suggest(binaries, context, os)` — dado inventario de binarios, consulta GTFOBins/LOLBAS en KB concurrentemente (asyncio.gather). Retorna técnicas explotables por binario con comandos.

**Improvements sobre intel_next_step:**
- Stuck signals auto-detect: wiring a `kestrel.core.stuck`, prepend recovery step (priority 1, source="stuck")
- Jaccard fuzzy dedup: threshold 0.6, strip annotations em-dash/en-dash antes de comparar
- Templates builtin por fase: p2_enum / p3_foothold / p4_privesc como fallback sin KB

**Tests:** 38 test_tools_intel + 347 suite total (+ 16 skip).

---

### v0.4.0-dev (RT-KESTREL-V04 — MCP Pivot)

Branch `feat/v04-mcp-pivot`. **15/16 fases del plan completas** (pendiente: E2E Lame final).

**Hecho (Fase 0-13):**
- **Fase 0 — Preflight + snapshot**: branch creada, phases v0.3 archivadas a `docs/v03-phases-archive/`, `requirements.lock.txt`, baseline 80 pass + 16 skip.
- **Fase 1 — Pyproject + skeleton**: `pyproject.toml` PEP 621 (`kestrel-htb 0.4.0-dev`), console scripts `kestrel` + `kestrel-mcp`, `src/kestrel/{mcp,core,transport,integrations,state,agent}/`. Deps clave: `mcp>=1.0`, `paramiko`, `pypsrp`, `pymetasploit3`, `filelock`, `typer`, `Jinja2`, `httpx`, `pydantic>=2.5`. Agent runner diferido a v0.5 (stub `NotImplementedError`).
- **Fase 2 — Core refactor**: 8 scripts movidos a `src/kestrel/core/*.py` (fingerprint, stuck, wordlist, crack, heartbeat, state_inspector, parallel, resume_validator). Shim files en `scripts/` con `DeprecationWarning` para retrocompat 1 ciclo. Nuevo `core/timer.py` reemplaza `tool-timer.sh` con contextmanager Python + `run_with_timer` CLI-compat. Heartbeat refactor: data layer (`emit_dashboard_data`) separado de presentation. Tests 90 pass + 10 nuevos = 100. 0 regresiones.
- **Fase 3 — State store + schema**: `kestrel.state.schema` con pydantic models completos v0.3 (LastCycle, MachineState con todos los campos v0.2/v0.2.1/v0.3, AttackPlan, CurrentVector, HashJob, TriedCredential/Endpoint/Hash, KaliListener, SessionEvent, Profile). `kestrel.state.store.StateStore` con filelock + atomic temp+rename, `_write_unlocked` para re-entrant safety. 16 tests incluyen concurrent updates con threading, roundtrip de prod `fleet/agents/htb/state/last-cycle.json` real.
- **Fase 4 — Transport + MSF RPC setup**: `transport/base.py` Session ABC + SessionRegistry thread-safe; `transport/ssh.py` paramiko persistente con upload/download; `transport/winrm.py` pypsrp NTLM/Kerberos; `transport/msf.py` pymetasploit3 RPC con `execute_exploit`, `sessions`, `wait_for_session`, `ping`; `transport/kali_proxy.py` global session + `via_kali()`. `scripts/kali-setup-msfrpc.sh` idempotente con systemd unit. 24 tests mocked.
- **Fase 5 — MCP server boilerplate**: `mcp/registry.py` decoradores `@tool/@prompt/@resource` + JSON schema inference desde type hints; `mcp/context.py` singleton ServerContext con StateStore + SessionRegistry; `mcp/server.py` con SDK oficial Anthropic (Server, list_tools/call_tool/list_prompts/get_prompt/list_resources/read_resource handlers, stdio transport, file logging a `%LOCALAPPDATA%/kestrel/mcp.log`, URI template matching para `kestrel://session/{machine}/...`). Dummy handlers: tool `kestrel_ping`, tool `kestrel_version`, resource `kestrel://config`, prompt `kestrel_kickoff`. Examples `claude-{code,desktop}-mcp.json`. 18 tests. **Handshake post CC restart validado 2026-05-20.**
- **Fase 6 — Tools MCP por categoría**: **70 tools registrados en 19 categorías** (supera target ≥50):
  - `state` (4): read, write_machine, append_event, session_dir
  - `phase` (2): current, enter (returns guidance + suggested tools + HITL gates)
  - `narrate` (1): emit (📡 🔍 💡 ➡)
  - `htb` (6): list_machines, machine_info, spawn, release, submit_flag, profile_update
  - `vpn` (3): up, down, status (htb-vpn.sh wrapper via Kali SSH)
  - `kali` (2): status, ping_target
  - `recon` (6): nmap_scan (4 profiles), service_probe, web_fingerprint, smb_enum, dns_enum, ldap_enum
  - `intel` (4): classify_blind, kb_query (graceful), cve_lookup (4-stage KB→NVD→ExploitDB→MSF), save_synthesis
  - `vuln` (4): nuclei_targeted, nuclei_broad, check_exploit_db, msf_search (RPC graceful)
  - `creds` (6): default_check, password_spray, hash_recommend, hash_crack, hash_status, save_tried
  - `exploit` (6): run_msf (RPC + session_id wait), run_poc, web_lfi, web_rce, smb_psexec (pth auto), winrm (evil-winrm)
  - `post` (8): linpeas_run, winpeas_run, enum_user, enum_system, privesc_kernel, privesc_sudo (gtfobins), check_token, privesc_potato
  - `ad` (4): bloodhound_collect, kerberoast, asreproast, dcsync (impacket)
  - `session` (4): open (ssh/winrm/msf), exec, close, list
  - `flag` (2): extract (linux/windows), validate (HTB 32-hex)
  - `writeup` (3): generate (Jinja2 template), kb_synthesize (anti-spoiler), publish_hint (emit.py subprocess)
  - `heartbeat` (2): stuck_check (5 signals + recommend), heartbeat_status (dashboard wrap)
  - `hitl` (1): request_user_confirmation con `_hitl: true` marker contract
  - `meta` (2): kestrel_ping, kestrel_version
  - +132 tests nuevos en este fase.
- **Fase 7 — Prompts MCP**: 10 prompts Jinja2 registrados (`kestrel_kickoff`, `p0_setup`..`p5_close`, `intel_synthesis_template`, `hint_generation`, `debrief_template`). El kickoff y phase prompts interpolan estado en vivo; intel/hint/debrief son templates. +11 tests.
- **Fase 8 — Resources MCP**: 10 URIs registrados (`kestrel://state/{last-cycle,sessions-jsonl,profile}`, `kestrel://session/{machine}/{intel,recon,findings,fingerprint,writeup}`, `kestrel://kb/categories`, `kestrel://config`). Template matching para session URIs. +10 tests.
- **Fase 9 — CLI completo**: `kestrel {version,mcp,agent,status,fingerprint,config init/show,state show,debug tools-list/ssh-exec/msfrpc-ping}`. +12 tests via Typer's CliRunner.
- **Fase 10 — Skill `/kestrel` thin rewrite**: `.claude/skills/kestrel/SKILL.md` reescrito a 105 líneas (down 134). Powered by MCP server. Sub-comandos `/kestrel hint/status/resume` mapean a tool/prompt calls explícitos. NO toca `phases/` aún (cutover en Fase 13).
- **Fase 11 — Tests + CI**: 313 tests pasan + 16 skipped (POSIX-only bash tests). `.github/workflows/test.yml` actualizado: matrix Ubuntu+Windows × Python 3.11+3.12, lint con ruff, e2e job gated por tag `v0.4*`.
- **Fase 12 — Docs**: `docs/architecture.md` v0.4 con 5-layer model (MCP protocol added), `docs/tools-reference.md` autogenerado por `scripts/gen_tools_reference.py` (70 tools + 10 prompts + 10 resources), `docs/prompts-reference.md` nuevo, `docs/public-usage.md` nuevo (setup CC + Desktop + env vars + troubleshooting). `examples/claude-{code,desktop}-mcp.json` ya existen desde Fase 5.
- **Fase 13 — Cutover**: pendiente (eliminar `phases/` skill después de confirmar archive en `docs/v03-phases-archive/`, commit branch + tag `v0.4.0-rc1` local).

**Pendiente final:**
- Check final completo (manual desde CC nueva sesión).
- E2E Lame ≤10min con HITL 3-4 via MSF usermap_script.
- Tag `v0.4.0` + push origin + GitHub Release post-E2E ok.

**Tests al cierre**: **313 pass, 16 skip, 0 fail**. Coverage no medido formalmente pero conservador (mocks cubren ~80% del happy path por categoría).

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
