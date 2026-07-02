# Siguiente — Kestrel

> Diagnóstico completo 2026-06-30 (4 agentes paralelos). Base técnica sólida (77 tools, 432 tests)
> pero roto por 3 causas raíz. Camino a "pro" tiene 5 bloques + case study.

---

## PRÓXIMO — E2E Reactor post-mejoras V10b-S3

**Estado**: Listo para correr. 30 mejoras adicionales implementadas (474 tests ✅, commit `ce89967`).

**Target**: Reactor — 10.129.41.238 (Easy, Linux). Spawnar si no está activa.

**Modo**: Claude Code + MCP tools (yo actúo como agente). Sin agente headless, sin ANTHROPIC_API_KEY separada.

**Estado sesión 2026-07-02**: Gate completo ✅
- Kali up ✅ (locks stale limpiados para arrancar)
- VPN conectada ✅
- Reactor spawneada → IP `10.129.43.0` ✅ (persista en state)
- **Pendiente**: reinicio Claude Code para tomar fix `commit 77ec47a` (creds tools aceptan string CSV, no solo list)

**Retomar desde aquí** (post-reinicio):
1. `creds_themed_wordlist_gen(machine="reactor", keywords="nuclear,site7,monitoring,reactorwatch,coolant", staff="james,elena,marcus,jthompson,erodriguez,mkim")`
2. `creds_ssh_bruteforce(target="10.129.43.0", users="jthompson,james,erodriguez,elena,mkim,marcus,reactor,admin", wordlist="/tmp/kestrel-themed-reactor.txt")`
   - `-e nsr` incluido → prueba `reactor/reactor`, `rotcaer`, `""` automáticamente
3. Si 0 hits → `creds_ssh_bruteforce` con `/usr/share/wordlists/rockyou.txt`
4. `session_open` → `post_check_suid` + `post_linpeas_run` → `flag_extract` → `htb_submit_flag`

**Contexto**: Reactor tiene SSH 22 + port 3000 (Next.js 15 estático "ReactorWatch"). Web agotada. Vector es SSH.
Bloqueante histórico: `CRED_FAIL_THRESHOLD` ya en 20 (100 durante bruteforce activo). `-e nsr` ya incluido.

**Blind siempre**: no writeups, no hints externos.

---

## CAUSAS RAÍZ

1. ~~**Env vars ausentes**~~ — ✅ RESUELTO 2026-07-01.
2. ~~**Fase 13 nunca completada**~~ — ✅ RESUELTO 2026-07-01. `skill/phases/` → `docs/v04-phases-archive/`.
3. ~~**Lifecycle tools nunca llamados**~~ — ✅ PARCIALMENTE RESUELTO 2026-07-01. SKILL.md actualizado. E2E confirmó que las tools funcionan cuando se las llama. Gaps de automatización → V08.

---

## RT-KESTREL-FIX-V01 ← CERRADO 2026-07-01

**Objetivo:** Kestrel funcional E2E contra una máquina Easy.

1. ~~**Env vars en MCP config**~~ — ✅ DONE 2026-07-01. `KESTREL_KALI_HOST=192.168.179.137`, `KALI_USER=kali`, `KALI_KEY=~/.ssh/kali-pentest`, `HTB_API_TOKEN`, `HTB_USER_ID=3460182`, `KESTREL_KB_PATH`. Reiniciar Claude Code para que tome efecto.

2. ~~**Completar Fase 13 (cutover)**~~ — ✅ DONE 2026-07-01. `skill/phases/` movido a `docs/v04-phases-archive/`. Commit `e06bcdf`.

3. ~~**Lifecycle protocol en SKILL.md**~~ — ✅ DONE 2026-07-01. `session_open` → `phase_enter` → `session_close` documentados como obligatorios. Commit `e06bcdf`.

4. ~~**Gate Kali up en SKILL.md**~~ — ✅ DONE 2026-07-01. `kali_vm_status` + `kali_vm_up` como primer step, HARD STOP si `reachable: false`. Commit `e06bcdf`.

5. ~~**Fix path MCP server**~~ — ✅ DONE 2026-07-01. `~/.claude.json` actualizado: `C:\opsec\runner\` → `C:\Proyectos\Kestrel\`. Requiere restart Claude Code para tomar efecto.

6. ~~**E2E**~~ — ✅ DONE 2026-07-01. Reactor 10.129.41.238: Kali gate ✅, VPN ✅, spawn ✅, ping ✅, `sessions.jsonl` con lifecycle events ✅. 3 gaps → V08: (1) session_slug no persiste automático, (2) current_session no se actualiza al cambiar máquina, (3) phase_enter no emite state_append_event.

**Deliverable:** ✅ CERRADO 2026-07-01. Flow E2E funciona. Automatización del lifecycle → V08.

---

## RT-KESTREL-V08 — State & Session Continuity ← CERRADO 2026-07-01 (partial)

**Objetivo:** Resume real entre sesiones. Estado persistente entre turnos de Claude.

1. ~~**Fix session_slug**~~ — ✅ DONE. `_resolve_session_dir` persiste slug via `update_machine`. Commit `5896279`.
2. ~~**current_session auto-update**~~ — ✅ DONE. `set_current_session()` en StateStore; `htb_spawn` lo llama. Commit `5896279`.
3. ~~**Attack plan persistence**~~ — ✅ DONE. `intel_classify_blind(machine=...)` persiste `attack_plan` + `current_vector`. Commit `5896279`.
4. ~~**Progress tracking**~~ — ✅ DONE. `phase_enter(machine=...)` escribe `progress[phase]` + `last_phase_completed` + lifecycle event. Commit `5896279`.
5. **htb_cli.py** — ⏸ DEFERRED → cut; los MCP tools cubren todas las funciones del CLI planificado.
6. **E2E own** — ⏸ DEFERRED. Lifecycle protocol confirmado ✅; Reactor (10.129.41.238) no owned — vector SSH no encontrado con 232 combinaciones, web estática sin API. Diferido a próxima sesión con máquina distinta.

**Estado:** D1-D4 done (441 tests ✅), D5 cut, D6 deferred.

---

## RT-KESTREL-V09 — Intelligence Loop ← CERRADO 2026-07-01

1. ~~**intel_next_step loop**~~ — ✅ ya estaba en SKILL.md — verificado.
2. ~~**Stuck detection automático**~~ — ✅ DONE. `rabbit_hole` bug fix en `heartbeat.py`; `stuck_check` wired en p1/p2/p4; SKILL.md: "3 tools consecutivos sin findings".
3. ~~**KB integration real**~~ — ✅ DONE. Path auto-detection fix en `intel.py` + `fingerprint.py`; deps instaladas; KB import funciona (Ollama bge-m3 + pgvector Tailscale).
4. ~~**lolbin_suggest en post-explotación**~~ — ✅ DONE. Wired en `p4_privesc` + SKILL.md.
5. ~~**Rabbit hole detection**~~ — ✅ ya estaba en SKILL.md — verificado.

**Commit:** `502cd04`. Tests: 446 passed.

---

## RT-KESTREL-V10 — Metrics & KPIs (2-3h)

**Objetivo:** Framework medible. Equivalente a los "72 TPs, 3 CRITICAL, FP rate 36%" de Corvus.

1. **Success tracking** — `LastCycle` acumula: `machines_owned`, `machines_attempted`, `machines_abandoned`, desglosado por `difficulty` y `os`. CLI: `kestrel stats`.
2. **Time-to-own** — `session_analytics` ya tiene `started_at/finished_at`. Agregar `time_to_user_min`, `time_to_root_min` calculado al hacer `htb_submit_flag`.
3. **ATT&CK coverage map** — mapear cada tool a tácticas MITRE. `kestrel stats --attck` muestra qué tactics/techniques se usaron en el lifetime de sesiones.
4. **Per-machine writeup quality score** — completeness del `sessions.jsonl` (lifecycle events, narrate density, findings) como proxy de calidad.
5. **Ranking progression** — `htb_profile_update` ya actualiza `profile.json`. Agregar tracking de rank histórico: `["Noob", "User", "Hacker", "Pro Hacker", ...]` con fechas.

**Deliverable:** `kestrel stats` muestra: N máquinas owned, success rate por dificultad, ATT&CK coverage, rank actual vs target.

---

## RT-KESTREL-V10b — ReAct Agent Headless ← CERRADO 2026-07-01

**Objetivo:** Kestrel corre solo, sin Claude Code. Agente que pwna HTB machines autónomamente.

### S1 — Skeleton (2026-07-01) ← DONE
1. ~~**`src/kestrel/agent/`**~~ — ✅ `ReActAgent` + bridge + metrics + CLI wired.
2. ~~**Loop ReAct**~~ — ✅ `observe → think → act` con Anthropic SDK, tool_use nativo.
3. ~~**Bridge MCP → Anthropic tools**~~ — ✅ registry → `[{type, name, description, input_schema}]`.
4. ~~**CLI**~~ — ✅ `kestrel agent --machine <slug> --mode blind --provider anthropic --budget-tokens 200000`.
5. ~~**HITL terminal**~~ — ✅ 4 gates: machine_pick, vector_confirm, submit_flag, debrief. `input()` en CLI.
6. ~~**Métricas**~~ — ✅ `state_dir/runs/<slug>-<ts>.json`: tools_called, stuck_events, time-to-flag.

### S2 — Framework fixes post-análisis (2026-07-01) ← DONE (12 mejoras, commits b16dd4d + 879c600)
- **M1** `creds_ssh_bruteforce` — hydra wrapper (1 user × N passwords). Bloqueante crítico.
- **M2** `creds_themed_wordlist_gen` — wordlist CTF-temático automático (machine+staff+keywords).
- **M3** `_result_has_new_findings` — 0 hits ya no cuenta como progreso; stuck_check dispara.
- **M4** `recon_web_dirfuzz` auto-escalate a raft-medium cuando common.txt=0.
- **M5** `_probe_nextjs` hint: indica creds_themed_wordlist_gen + creds_ssh_bruteforce explícitamente.
- **M6** `vuln.py` nuclei con `timeout {safe_secs}s` igual que recon.py.
- **M7** `_SYSTEM_BLIND` — guía completa SSH flow, session_open, flag extraction, privesc.
- **M8** `htb_submit_flag` metrics fix — busca "correct" en `result.result` además del top level.
- **M9** `_result_has_new_findings` — nmap con 0 puertos abiertos = no progress.
- **M10** `phase.py` p3_exploit — guidance con nuevas tools (bruteforce, session_exec).
- **M11** `post.py` SUDO_GTFOBINS 9→35 binarios (bash, env, cp, git, docker, nmap, etc.).
- **M12** `post.py` `post_linpeas_run` — copia local en Kali primero, fallback GitHub.

### S3 — Deep audit + 30 mejoras pre-E2E (2026-07-01) ← DONE (474 tests ✅, commit `ce89967`)

5 agentes investigación + 5 agentes implementación paralelos. Root causes del E2E fallido identificados y resueltos.

**Bloqueantes críticos resueltos**:
- `CRED_FAIL_THRESHOLD` 3→20 (100 durante bruteforce activo) — abandonaba bruteforce en 3 fallos
- `-e nsr` en hydra — prueba `user=password` automáticamente (`reactor/reactor` sin estar en wordlist)
- `detect_rabbit_hole` falsos positivos — filtra heartbeats, window 40→80 chars, consecutive 4→6
- Port 3000 ausente en `score_rules` — `intel_classify_blind` retornaba attack_plan vacío para Reactor
- `post_linpeas_run` ANSI codes — `finding_count` siempre 0; `tail -c 8000` → grep filter 16000 bytes
- SSH sin keepalive → linpeas rompía sesión a los 3-5 min
- `_execute_tool` sin timeout → agente podía bloquearse indefinidamente

**Otros fixes**:
- `intel_next_step` lee `attack_plan` del state (antes ciega al contexto ya calculado)
- `post_check_suid` nueva tool — SUID privesc sin correr linpeas entero
- `connect_timeout` 10→30s, `flag_extract` sudo fallback
- `recon_web_fingerprint` 4000→16000 bytes + `__NEXT_DATA__` extraction
- `_probe_nextjs` lee buildManifest real; Next.js/Node en `FRAMEWORK_CATEGORIES`
- `phase_enter` filtra tools AD/OS según machine state
- `p3a_pre_foothold` fallback incluye SSH cred reuse steps
- Budget warnings 75%/90%, dedup tool+args, HITL regex robusta, bridge 800→2000 chars

**14 archivos modificados**: `creds.py`, `fingerprint.py`, `recon.py`, `stuck.py`, `intel.py`, `phase.py`, `post.py`, `ssh.py`, `session.py`, `flag.py`, `loop.py`, `bridge.py`, `test_stuck_detector.py`, `test_tools_recon.py`

**E2E pendiente**: correr contra Reactor desde Claude Code con MCP tools (ver sección PRÓXIMO arriba).

**Por qué es el diferenciador**: ninguna herramienta HTB pública hace esto. Pasa de "Claude con tools" a "agente de seguridad con benchmarks". Es lo que convierte el proyecto en investigación publicable.

---

## RT-KESTREL-CS01 — Case Study: 10 Máquinas (4-6h total, sessions)

**Objetivo:** Dataset real publicable. "Kestrel owned X HTB machines autónomamente".

1. **10 Easy Machines retiradas** — `htb_list_machines` filtrado por `difficulty=Easy, retired=True`. Target: 10 owned con Kestrel como orquestador principal.
2. **Métricas por máquina** — time-to-own, gates HITL usados, vectors probados, stuck events, KB hits.
3. **Writeups anti-spoiler** — writeup publicable por máquina (técnicas, no flags). `writeup_kb_synthesize` para cada una.
4. **Report combinado** — `case-studies/cs01-htb-autonomous/report.md`: success rate, avg time-to-own, ATT&CK coverage, comparison guided vs blind mode.
5. **Blog post / LinkedIn** — "Construí un framework de IA que hackea HackTheBox autónomamente. Aquí están los datos."

**Deliverable:** Dataset + report públicos. Ángulo de diferenciación: único framework MCP con métricas reales de éxito en HTB.

---

## RT-KESTREL-V11 — Hardening & Publish (2-3h)

**Objetivo:** Framework instalable, reproducible, con CI verde.

1. **PyPI** — `pip install kestrel-htb` ya funciona en teoría. Verificar build limpio, `twine upload` con `.pypirc`.
2. **kestrel.toml** — config file equivalente a `corvus.toml`. Prioridad: file > env > default.
3. **GitHub CI verde** — `.github/workflows/test.yml` ya existe. Verificar que pasa en el remote post-push v0.7.1.
4. **Coverage formal** — `pytest --cov=kestrel --cov-report=xml`. Target: ≥70% líneas.
5. ~~**Push v0.7.1**~~ — ✅ DONE 2026-07-01. Remote HEAD=`23fa139`.
6. **CI Windows fix** — `test_attack_plan.py` + `test_fingerprint.py` fallan en `windows-latest` (pre-existente). Ubuntu pasa. Fix path separators o mock comportamiento Windows.

**Deliverable:** `pip install kestrel-htb`, CI verde en todos los runners, repo público al día.

---

## Deadline: Ekoparty 2026 — CFP 2026-08-14 (44 días)

Con V08 + V10b + CS01 completos, Kestrel sería track B en Ekoparty: "construimos un agente que pwna HTB solo — acá están los benchmarks".

**Prioridad**: `FIX-V01 → V08 → V10b → CS01` antes del 14 agosto.

---

## Cerrados

- **RT-KESTREL-PREP-V01** — ✅ 2026-07-01. `kali_vm_up/down/status` + 7 tests → 432 total. 16 commits pusheados.
- **RT-KESTREL-V07** — ✅ 2026-06-15. Web-only pivot sprint. 6 IMPs. 425 tests.
- **RT-KESTREL-V06** — ✅ 2026-06-14. Operational hardening. 9 IMPs. 412 tests.
- **RT-KESTREL-V05** — ✅ 2026-06-14. Blind effectiveness sprint. 10 IMPs. 382 tests.
- **RT-KESTREL-V04** — ✅ MCP pivot. 70+ tools, 10 prompts, 10 resources.
