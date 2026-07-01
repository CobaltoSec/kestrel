# Phase p2 — Engagement Setup

## Objetivo
Preparar todo antes de atacar: directorio de sesión, RoE, VPN activa, machine spawneada, conectividad verificada.

Referencia: `phases/shared/api-helpers.md` — secciones VPN, spawn, ping.

---

## PASO 1 — Crear directorio de sesión

```
SESSION_DATE  = hoy en YYYY-MM-DD
SESSION_SLUG  = htb-<SESSION_DATE>-<MACHINE_NAME>  (ej: htb-2026-05-03-lame)
SESSION_DIR   = sectors/red-team/htb-sessions/<SESSION_SLUG>/
```

Crear estructura desde template:
```
mkdir sectors/red-team/htb-sessions/<SESSION_SLUG>/
mkdir sectors/red-team/htb-sessions/<SESSION_SLUG>/raw/
mkdir sectors/red-team/htb-sessions/<SESSION_SLUG>/loot/
```

Copiar templates:
- `_template/roe.md` → `<SESSION_DIR>/roe.md`
- `_template/estado.md` → `<SESSION_DIR>/estado.md`
- `_template/findings.md` → `<SESSION_DIR>/findings.md`

---

## PASO 2 — Generar RoE + mover intel.md

Rellenar `roe.md` con datos reales (reemplazar placeholders):

```yaml
---
slug: <SESSION_SLUG>
target: TBD (se completa post-spawn)
mode: lab
discipline: LAN
opsec_tier: 0
authorized_by: HackTheBox
engagement_type: htb-machine
machine_id: <MACHINE_ID>
machine_name: <MACHINE_NAME>
machine_os: <MACHINE_OS>
machine_difficulty: <MACHINE_DIFFICULTY>
machine_retired: <true|false>
htb_mode: <guided|blind>           # de p1.5-intel-recon
intel_path: ./intel.md              # null si MODE=blind sin intel
intel_confidence: <high|medium|low|none>
hints_used: false
hints_allowed: auto    # auto (stuck gate ≥1 fallido en Easy, ≥2 Medium+) | true | false
attempts_threshold: <1|2>           # 1 para Easy, 2 para Medium+ (override manual posible)
started_at: <TIMESTAMP_ISO8601>
finished_at: null
---
```

**Mover intel.md de staging:**
```bash
STAGING_INTEL=sectors/red-team/htb/staging/htb-intel-<MACHINE_NAME>.md
DEST_INTEL=<SESSION_DIR>/intel.md
if [ -f "$STAGING_INTEL" ]; then
    mv "$STAGING_INTEL" "$DEST_INTEL"
fi
```

Si `STAGING_INTEL` no existe (raro — p1.5 debería siempre escribir algo) → crear `intel.md` minimal con MODE=blind nota.

También actualizar `estado.md`: primera fila del timeline con `started_at` y acción "engagement iniciado (mode=<guided|blind>)".

---

## PASO 3 — Levantar VPN

```bash
bash scripts/htb-vpn.sh up
```

Esperar hasta 35s. Si sale exitoso: mostrar IP tun0. Si falla:
1. Mostrar error exacto.
2. `bash scripts/htb-vpn.sh status` para diagnosticar.
3. Ofrecer: `[r] reintentar | [c] cleanup y reintentar | [q] abortar`.

Post-VPN: verificar status:
```bash
bash scripts/htb-vpn.sh status
```

---

## PASO 4 — Spawn machine

Primero verificar si ya hay una máquina activa:
```bash
python3 sectors/red-team/htb/htb_cli.py active
```

Si el resultado NO es `{}`:
```
⚠ Hay otra máquina activa: <nombre> (<ip>)
  [r] release esa y spawn <MACHINE_NAME>
  [k] continuar con la activa (si es la misma máquina)
  [q] abortar
```
Si `r` → `python3 sectors/red-team/htb/htb_cli.py release <ACTIVE_ID>` primero.

Spawn:
```bash
python3 sectors/red-team/htb/htb_cli.py spawn <MACHINE_ID>
```

La respuesta de spawn es `{"message": "Playing machine."}` — NO incluye IP.
Esperar ~5 segundos y obtener IP via `active`:
```bash
sleep 5
python3 sectors/red-team/htb/htb_cli.py active
```

Del JSON resultante, extraer IP del campo `ip` (según respuesta real de la API en el momento de spawn).
Si `active` devuelve `{}` después de 5s → reintentar hasta 3 veces con 5s de espera entre intentos.

Una vez obtenida la IP: actualizar `roe.md` con `target: <IP>` y `estado.md` timeline.

---

## PASO 5 — Verificar conectividad

Ping desde Kali (VPN está en Kali):
```bash
KALI_IP=$(bash scripts/kali-vm.sh ip)
ssh -i ~/.ssh/kali-pentest kali@$KALI_IP "ping -c 3 -W 2 <TARGET_IP>"
```

Si `ping` falla:
1. Verificar VPN: `bash scripts/htb-vpn.sh status`.
2. Esperar 15s y reintentar (las máquinas HTB pueden tardar en bootear).
3. Si falla 3 veces: mostrar output completo y preguntar si continuar igual.

Si OK → mostrar: `✓ <TARGET_IP> responde (RTT: Xms)`

---

## PASO 6 — Resumen de setup + confirmación

```
=== SETUP COMPLETO ===
Sesión:   <SESSION_SLUG>
Target:   <MACHINE_NAME> (<MACHINE_OS>, <MACHINE_DIFFICULTY>)
IP:       <TARGET_IP>
VPN:      tun0 UP (<VPN_IP>)
Dir:      sectors/red-team/htb-sessions/<SESSION_SLUG>/

¿Arrancamos el pentest? [s/n]
```

Si `n` → "Sesión guardada. Retomá con `/htb resume`." + actualizar last-cycle.json.

---

## PASO 7 — Actualizar state

Determinar el budget por dificultad (usado por heartbeat.py para alertas):
- Easy = 90 min | Medium = 180 min | Hard = 360 min | Insane = 480 min

Actualizar `fleet/agents/htb/state/last-cycle.json`:
```json
{
  "last_run": "<TIMESTAMP>",
  "cycle_id": "HTB-<TIMESTAMP_COMPACT>",
  "run_count": "<run_count + 1>",
  "data": {
    "current_phase": "p2-engagement-setup",
    "current_session": "<SESSION_SLUG>",
    "machines": {
      "<MACHINE_NAME>": {
        "machine_id": "<MACHINE_ID>",
        "machine_os": "<MACHINE_OS>",
        "machine_difficulty": "<MACHINE_DIFFICULTY>",
        "started_at": "<TIMESTAMP>",
        "finished_at": null,
        "hints_used": false,
        "session_slug": "<SESSION_SLUG>",
        "session_started_at": "<TIMESTAMP>",
        "session_budget_min": "<90|180|360|480>",
        "session_budget_alerts_triggered": []
      }
    }
  }
}
```

Append a `<SESSION_DIR>/sessions.jsonl`:
```json
{"ts": "<TIMESTAMP>", "phase": "p2-engagement-setup", "event": "setup_complete", "detail": "VPN up, machine spawned, ping OK"}
{"ts": "<TIMESTAMP>", "phase": "p2-engagement-setup", "event": "session_start", "detail": "budget=<N>min difficulty=<MACHINE_DIFFICULTY>"}
```

Continuar a `p3-delegate-pentest.md`.
