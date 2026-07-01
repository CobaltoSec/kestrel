# Siguiente — Kestrel

> Diagnóstico completo 2026-06-30 (4 agentes paralelos). Base técnica sólida (77 tools, 432 tests)
> pero roto por 3 causas raíz. Camino a "pro" tiene 5 bloques + case study.

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

## RT-KESTREL-V09 — Intelligence Loop (2-3h)

**Objetivo:** El framework detecta cuando está trabado y cambia de vector sin intervención.

1. **intel_next_step loop** — SKILL.md debe instruir llamar `intel_next_step` cada N steps fallidos, no solo al inicio. Actualmente se llama una vez y el modelo improvisa.
2. **Stuck detection automático** — `stuck_check` debe llamarse después de 3 tools consecutivos sin progreso. El tool ya existe y funciona — el modelo simplemente no lo llama.
3. **KB integration real** — conectar pgvector E16 desde Kestrel: `KESTREL_KB_PATH` debe apuntar al socket de `kb-pgvector :5433`. Actualmente usa fallback templates builtin (funcionan, pero pierde todos los ATT&CK/HackTricks del KB).
4. **lolbin_suggest en post-explotación** — después de `post_enum_system`, llamar `lolbin_suggest` con los binarios encontrados. Tool implementado pero nunca invocado.
5. **Rabbit hole detection** — `stuck_check` ya detecta rabbit holes (mismo output 3+ veces en 20min). Agregar instrucción en SKILL.md para actuar sobre `rabbit_hole: true`.

**Deliverable:** Kestrel completa máquinas Medium sin trabarse más de 30min en un vector muerto.

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

## RT-KESTREL-V10b — ReAct Agent Headless (2-3 sesiones) ← DIFERENCIADOR

**Objetivo:** Kestrel corre solo, sin Claude Code. Agente que pwna HTB machines autónomamente.

El `agent/` ya existe como stub (`NotImplementedError`). Implementarlo convierte Kestrel de "MCP server que Claude usa" a "agente autónomo de red-team".

1. **Loop ReAct** — Anthropic SDK directo: `observe → think → act → observe`. Estado entre iteraciones vía MCP state tools. Budget de tokens configurable.
2. **Comando**: `kestrel agent --machine kobold --mode blind --provider anthropic`
3. **HITL gates via `request_user_confirmation`** — el agente pausa solo en los 4 gates críticos (pick máquina, confirmar vector, submit flag, debrief). El resto corre solo.
4. **Métricas por run**: tiempo-a-user-flag, tiempo-a-root-flag, `tools_called`, `stuck_events`, `vector_accuracy`. Guardadas en `state_dir/runs/`.
5. **Criterio de done**: agente headless obtiene root en Kobold (Easy) sin intervención humana excepto los 4 gates.

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
