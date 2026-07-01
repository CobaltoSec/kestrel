---
name: kestrel
description: >
  Skill Kestrel framework v0.4 — thin wrapper sobre MCP server `kestrel-mcp`
  (powered by sectors/red-team/htb-framework-public, github.com/CobaltoSec/kestrel).
  Sesiones HTB E2E con AI orquestando tools nativos: HTB API, recon, intel + KB + CVE,
  MSF RPC, AD attacks, write-up + KB synthesis. Phases p0_setup→p5_close.
  HITL solo en gates críticos (machine pick, vector confirm, submit, debrief).
  Narración continua 📡→🔍→💡→➡ por cada acción significativa.
  State en fleet/agents/htb/state/, sesiones en sectors/red-team/htb-sessions/YYYY-MM-DD-<slug>/.

  Usar cuando Nico diga: /kestrel | /kestrel hint | /kestrel status | /kestrel resume |
  /htb (alias) | /htb hint | /htb status | /htb resume |
  "empezamos HTB" | "corramos una máquina" | "practiquemos HTB" | "hackthebox"
---

# /kestrel — HTB E2E via MCP server

Skill thin wrapper sobre el servidor MCP `kestrel-mcp`. Toda la lógica vive en el repo público.
La skill no duplica nada: solo bootstrappea el prompt inicial y mapea sub-comandos a tool calls.

## Setup (una sola vez)

El MCP server debe estar registrado en `~/.claude.json` o `~/.claude/mcp_servers.json`:

```json
{
  "mcpServers": {
    "kestrel": {
      "command": "C:/Proyectos/Kestrel/.venv/Scripts/kestrel-mcp.exe"
    }
  }
}
```

Si no carga: verificá con `kestrel debug tools-list` que el venv responde, y `kestrel debug msfrpc-ping` para el RPC de MSF.

## Bootstrap por sesión

Cuando Nico dispara `/kestrel`:

1. **Gate Kali up** — PRIMER PASO SIEMPRE, sin excepción:
   - `kali_vm_status` → si `powered: true` y `reachable: true`: continuar.
   - Si `powered: false`: `kali_vm_up` → espera hasta `reachable: true` (polling incluido, hasta 120s).
   - Si `reachable: false` después de boot: HARD STOP — reportar a Nico, no continuar.
2. Invocá el prompt MCP `kestrel_kickoff` → la respuesta incluye rol, phases, narración, HITL rules + estado actual.
3. Seguí las instrucciones del prompt:
   - **Fresh start** → `session_open({machine: <slug>})` → **registra `session_slug` en state** → luego `phase_enter('p0_setup')` + `htb_list_machines(status='retired', difficulty='Easy')` → HITL pick.
   - **Resume** → `state_read` + `phase_current` para retomar la sesión activa.

## Lifecycle protocol (OBLIGATORIO)

El modelo DEBE llamar estas tools en orden. Sin lifecycle no hay resume posible.

| Momento | Tool | Qué hace |
|---------|------|----------|
| Al iniciar sesión | `session_open({machine, session_dir})` | Genera y persiste `session_slug` en `MachineState` |
| Al cambiar de fase | `phase_enter({phase})` | Escribe `progress[phase]` + `last_phase_completed`; activa HITL gate si corresponde |
| Al terminar | `session_close({machine})` | Escribe `finished_at`, actualiza `current_session` en `LastCycle` |

**Reglas:**
- `session_open` va ANTES de cualquier otro tool en sesión nueva.
- `phase_enter` va ANTES de los tools de esa fase (no después).
- `session_close` va al final del p5_close, después de `htb_release`.
- Si una sesión se retoma (`/kestrel resume`): NO llamar `session_open` de nuevo — usar el `session_slug` existente en state.

## Sub-comandos

| Comando | Tool / prompt MCP |
|---------|-------------------|
| `/kestrel hint` | `get_prompt('hint_generation')` → emití el hint que devuelve, 1 sola línea, anti-spoiler. |
| `/kestrel status` | `call_tool('heartbeat_status', {machine: <slug>})` → renderá el dashboard al usuario. |
| `/kestrel resume` | `call_tool('state_read')` + `call_tool('phase_current')` → narrar dónde quedó y proponer próximo paso. |

## Reglas operativas (recordá al LLM en cada turn)

- **Español, conciso, sin preámbulos.**
- **Kali gate primero** — NUNCA llamar tools de recon/exploit/session sin confirmar que Kali está up y reachable (ver Bootstrap).
- **Lifecycle obligatorio** — `session_open` al inicio, `phase_enter` en cada cambio de fase, `session_close` al terminar (ver Lifecycle protocol).
- **Narración 4-streams obligatoria** durante p1-p4: por cada acción significativa, `call_tool('narrate_emit', {stream: '📡|🔍|💡|➡', text: '...', machine: ...})`.
- **HITL solo gates críticos** (~3-4 por máquina): machine pick, vector confirm, submit_flag, debrief. Para eso `call_tool('request_user_confirmation', {...})` y esperá la respuesta de Nico.
- **Anti-spoiler en intel.md**: dirección no comandos. Mencionar CVE/técnica OK, copy-paste payload NO.
- **Persistir progreso**: después de cada hito (target_ip, vector elegido, session abierta, flag extraída), `call_tool('state_write_machine', {...})`.
- **Stuck handling**: si una acción no avanza en 30 min o falla repetido → `call_tool('stuck_check', {machine: ...})` y aplicar la recomendación. Si `rabbit_hole: true` → pivotar de vector inmediatamente.
- **intel_next_step loop**: llamar `intel_next_step` después de cada 3 tools consecutivos sin progreso, no solo al inicio.

## Phases (referencia rápida)

| Phase | Goal | HITL gate |
|-------|------|-----------|
| p0_setup | Pick + intel + spawn + ping | machine_pick |
| p1_recon | nmap + service enum + classify | — |
| p2_vector | Propose ranked vectors (KB+CVE+MSF) | vector_confirm |
| p3_exploit | Run confirmed vector, open session | destructive_action_confirm |
| p4_privesc | Enum + escalate (skip si foothold = root) | destructive_action_confirm |
| p5_close | Flags + submit + writeup + cleanup + debrief | submit_confirm, debrief |

Cada `phase_enter(<phase>)` devuelve la lista de tools sugeridas + HITL gates para esa fase.

## Estado y artefactos

- **State JSON**: `fleet/agents/htb/state/last-cycle.json` (LastCycle schema).
- **Profile**: `fleet/agents/htb/state/profile.json` (HTB user stats).
- **Session dir**: `sectors/red-team/htb-sessions/<session_slug>/`
  - `estado.md` (narración timeline)
  - `intel.md` (síntesis pre-engagement, anti-spoiler)
  - `recon/` (nmap XMLs, web fps, smb dumps)
  - `findings.md` (notebook vivo)
  - `writeup.md` (generado en p5)
  - `feedback.md` (debrief 5-secciones — HARD GATE p5)
  - `sessions.jsonl` (audit log)

## Cleanup (p5_close)

Antes de cerrar:
1. `feedback.md` con las 5 secciones (prompt `debrief_template`).
2. HITL `submit_confirm` antes de cada `htb_submit_flag`.
3. HITL `debrief` antes del cleanup.
4. Cleanup: `vpn_down` + `htb_release` + `session_close` para todos los handles abiertos.
5. `writeup_kb_synthesize` opcional (KB ingest).
6. `writeup_publish_hint` opcional (downstream JobSearch automation).

## Resume checklist (sesión existente)

Cuando retomás una sesión en progreso (`/kestrel resume`), verificá antes de actuar:

1. **VPN activa** — `vpn_status` → si `connected: false`, `vpn_up` primero.
2. **Target respondiendo** — `kali_ping_target({ip})` → si falla, respawnear máquina HTB.
3. **Sessions abiertas** — `session_list` → si vacío, re-abrir con `session_open`.
4. **Receivers en background** (si usás HTTP exfil) — via `session_exec`: `pgrep -f recv_multi || echo DEAD`. Si DEAD: re-desplegar.
5. **Dependencias en /dev/shm** (si instalaste wheels sin pip) — via `session_exec`: verificar que aún existen. `df -h /` para chequear disco antes de re-instalar.
6. **Backup files** — siempre explorar `/opt/<service>/support-bundles/`, `/var/backups/`, `/home/*/.ssh/` post-foothold: pueden contener ED25519 keys u otros credenciales de usuarios del sistema.

## Troubleshooting

- **MCP server no responde** → `claude mcp` para listar servers, `kestrel-mcp --log-level DEBUG` para correr standalone y ver logs.
- **Tool error específico** → leer `%LOCALAPPDATA%\kestrel\mcp.log` para el traceback.
- **MSF RPC down** → `kestrel debug msfrpc-ping`; si fail, `bash scripts/kali-setup-msfrpc.sh` en Kali.
- **KB unavailable** → tools retornan `available: false` con `reason`; flow degrada graceful (no rompe).
