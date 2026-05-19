# State Schema — /htb

## fleet/agents/htb/state/profile.json

Snapshot del perfil HTB. Se actualiza al final de p4 (post-submit) y p6 (cierre de sesión).

```json
{
  "handle": "Cobalt0",
  "htb_id": 123456,
  "updated_at": "2026-05-03T14:00:00Z",
  "rank_text": "Hacker",
  "ranking": 9999,
  "points": 20,
  "user_owns": 1,
  "system_owns": 1,
  "machines_owned": [
    {
      "machine_id": 1,
      "machine_name": "lame",
      "machine_os": "Linux",
      "machine_difficulty": "Easy",
      "owned_user_at": "2026-05-03T14:10:00Z",
      "owned_root_at": "2026-05-03T14:15:00Z",
      "session_slug": "htb-2026-05-03-lame"
    }
  ]
}
```

**Actualizar** (lectura + merge):
1. Leer `profile.json`.
2. Ejecutar `python3 sectors/red-team/htb/htb_cli.py profile` → obtener valores actuales desde API.
3. Merge: `htb_id`, `rank_text`, `ranking`, `points`, `user_owns`, `system_owns` desde API.
4. Append a `machines_owned[]` si la máquina no está ya (por `machine_id`).
5. Set `updated_at` = now ISO8601.
6. Escribir `profile.json` atómico.

---

## fleet/agents/htb/state/last-cycle.json

Schema agente-ready. Un "cycle" = una sesión HTB completa (p0→p6).

```json
{
  "agent": "htb",
  "last_run": "2026-05-08T00:00:00Z",
  "cycle_id": "HTB-20260508T000000Z",
  "run_count": 9,
  "data": {
    "current_phase": "p2-engagement-setup",
    "current_session": "htb-2026-05-08-monitorsfour",
    "paused": false,
    "paused_reason": null,
    "resumed_session_count": 0,
    "machines": {
      "monitorsfour": {
        "machine_id": 814,
        "machine_os": "Windows",
        "machine_difficulty": "Easy",
        "machine_retired": false,
        "machine_rating": 3.5,
        "machine_tags": [],
        "started_at": "2026-05-08T00:00:00Z",
        "finished_at": null,
        "hints_used": false,
        "user_owned": false,
        "root_owned": false,
        "session_slug": "htb-2026-05-08-monitorsfour",
        "htb_mode": "blind",
        "intel_confidence": "none",
        "intel_path": "sectors/red-team/htb-sessions/htb-2026-05-08-monitorsfour/intel.md",
        "intel_sources": [],
        "target_ip": "10.129.53.74",
        "blind_fingerprint_pending": true,
        "blind_fingerprint_path": null,
        "blind_fingerprint_top": null,
        "blind_fingerprint_conf": null,
        "vpn_iface_state": "up",
        "last_machine_ip": "10.129.53.74",
        "kali_listeners": [],
        "next_step_hint": null,
        "last_phase_completed": "p2-engagement-setup",
        "paused": false,
        "progress": {},
        "next_steps": [],
        "abandoned": false,
        "abandoned_reason": null
      }
    }
  }
}
```

**Campos de `data.*` (top-level):**

| Campo | Tipo | Descripción |
|---|---|---|
| `current_phase` | str | Phase activa: `p0-welcome`, `p1-target-pick`, ..., `p6-cleanup` |
| `current_session` | str\|null | Slug de la sesión activa (null si no hay) |
| `paused` | bool | true si la sesión fue pausada (menú E5) |
| `paused_reason` | str\|null | Motivo del pause (para contexto al retomar) |
| `resumed_session_count` | int | Cantidad de veces que se retomó la sesión activa |

**Campos de `data.machines.<slug>.*`:**

| Campo | Tipo | Descripción |
|---|---|---|
| `machine_id` | int | ID HTB de la máquina |
| `machine_os` | str | `"Linux"` / `"Windows"` |
| `machine_difficulty` | str | `"Easy"` / `"Medium"` / `"Hard"` / `"Insane"` |
| `machine_retired` | bool | true si la máquina está retired al momento de la sesión |
| `machine_rating` | float\|null | Rating promedio HTB (0.0-5.0) |
| `machine_tags` | array | Tags HTB (ej: `["Active Directory", "CVE"]`) |
| `started_at` | ISO8601\|null | Inicio de sesión |
| `finished_at` | ISO8601\|null | Fin de sesión (null si activa) |
| `hints_used` | bool | true si se usaron hints durante la sesión |
| `user_owned` | bool | true si se submiteó user flag exitosamente |
| `root_owned` | bool | true si se submiteó root/system flag exitosamente |
| `session_slug` | str\|null | Slug de la sesión (ej: `"htb-2026-05-08-monitorsfour"`) |
| `htb_mode` | str | `"guided"` (intel pre-loaded) / `"blind"` (sin intel) |
| `intel_confidence` | str | `"high"` / `"medium"` / `"low"` / `"none"` |
| `intel_path` | str\|null | Path al archivo `intel.md` generado en p1.5 |
| `intel_sources` | array | URLs de fuentes de intel (writeups, CVE advisories) |
| `target_ip` | str\|null | IP actual de la máquina (puede cambiar en respawns) |
| `last_machine_ip` | str\|null | Alias de `target_ip` (mantener por compatibilidad) |
| `blind_fingerprint_pending` | bool | true si MODE=blind y fingerprint aún no corrió |
| `blind_fingerprint_path` | str\|null | Path a `fingerprint.json` generado en p3 PASO 1.5 |
| `blind_fingerprint_top` | str\|null | Top attack category detectado |
| `blind_fingerprint_conf` | float\|null | Confidence del top category (0.0-1.0) |
| `vpn_iface_state` | str\|null | `"up"` / `"down"` / `"expired"` |
| `kali_listeners` | array | Listeners activos: `[{pid, port, type, cmd}]` |
| `next_step_hint` | str\|null | Descripción legible del próximo paso al retomar |
| `last_phase_completed` | str\|null | Ej: `"p3-delegate-pentest:foothold"` |
| `paused` | bool | true si esta máquina fue pausada explícitamente |
| `progress` | object | Estado libre de avance en la máquina (creds, flags, pivots) |
| `next_steps` | array | Lista de pasos pendientes en texto libre |
| `abandoned` | bool | true si la máquina fue abandonada sin completar |
| `abandoned_reason` | str\|null | Motivo del abandono |

**Reglas de idempotencia:**
- `cycle_id` = `HTB-` + timestamp ISO8601 sin separadores (ej: `HTB-20260503T140000Z`).
- `run_count` es monotónico, nunca se resetea.
- `data.machines` es un dict por slug — upsert, no lista.
- `current_phase` se actualiza al inicio de cada phase (sirve para resume).
- `current_session` se clearrea al final de p6.
- `target_ip` y `last_machine_ip` son alias — escribir ambos al actualizar la IP.

---

## v0.2 — Optional cross-session tracking fields (sub-bloque C)

A partir de Kestrel v0.2 los tres campos siguientes pueden aparecer dentro de `data.machines.<slug>`. Son **opcionales** — código viejo los ignora vía `.get([], default=[])`. Sirven para evitar reintentar lo mismo entre sesiones (caso MonitorsFour S1→S3).

| Campo | Tipo | Descripción |
|---|---|---|
| `tried_credentials` | array | Pares user/password ya probados contra servicios |
| `tried_endpoints` | array | Endpoints HTTP/HTTPS ya enumerados |
| `tried_hashes` | array | Hashes ya pasados por hashcat con wordlist+rules específicas |

### Schema por entry

```json
{
  "tried_credentials": [
    {
      "user": "marcus",
      "password": "wonderful1",
      "service": "cacti-web",
      "result": "success",
      "ts": "2026-05-11T11:30:00Z"
    },
    {
      "user": "admin",
      "password": "wonderful1",
      "service": "winrm",
      "result": "auth_failed",
      "ts": "2026-05-11T19:45:00Z"
    }
  ],
  "tried_endpoints": [
    {
      "path": "/api/v1/users",
      "method": "GET",
      "vhost": "monitorsfour.htb",
      "status": 200,
      "interesting": true,
      "ts": "2026-05-11T11:00:00Z"
    }
  ],
  "tried_hashes": [
    {
      "hash_preview": "$2y$10$wqlo06...",
      "type": "bcrypt",
      "wordlist": "rockyou",
      "rules": "none",
      "elapsed_s": 300,
      "result": "no_match",
      "ts": "2026-05-11T19:30:00Z"
    }
  ]
}
```

### Valores de `result`

- credentials: `success` | `auth_failed` | `error` | `account_locked`
- hashes: `match` | `no_match` | `timeout` | `error`
- endpoints: response status code en `status` (int), `interesting` (bool) marca el caller

### Helper de consulta

`sectors/red-team/htb-framework-public/scripts/state_inspector.py` expone los queries idiomáticos (list / check). Ver `--help`. Exit codes:
- `0` = found / tried
- `1` = not found / not tried
- `2` = error de lectura/schema

### Backward compat

Para que código v0.1.1 siga funcionando, los consumers deben usar `machine.get("tried_credentials", [])` (nunca `machine["tried_credentials"]`). Lo mismo para los otros dos arrays.

---

## v0.2.1 — Attack plan + vector tracking + async crack jobs

A partir de Kestrel v0.2.1 los siguientes campos aparecen en `data.machines.<slug>`. Son **opcionales** — código previo los ignora vía `.get(...)`.

| Campo | Tipo | Descripción |
|---|---|---|
| `attack_plan` | object\|null | Copia del `attack_plan` emitido por `blind_fingerprint.py` (primary_chain, alternative_chains[], parallel_tracks[], execution_hint) |
| `current_vector` | object\|null | Vector activo con timer de budget |
| `hash_jobs` | array | Trabajos async de cracking GPU lanzados por `crack-helper.sh --async` |

### `attack_plan` shape

Copia literal del campo `attack_plan` del JSON de `blind_fingerprint.py --output`. Se persiste en PASO 1.5 (p3) cuando `fingerprint.json` se escribe, y lo consumen `stuck_detector.py` + auto-pivot para conocer el plan vigente.

```json
{
  "attack_plan": {
    "primary_chain": ["cve-cacti-sqli", "md5-crack", "winrm"],
    "alternative_chains": [
      ["php-type-juggling", "winrm"],
      ["lfi-nginx-bypass", "cred-reuse"]
    ],
    "parallel_tracks": ["docker-escape-enum"],
    "execution_hint": "multi-path"
  }
}
```

### `current_vector` shape

Budget defaults por difficulty: Easy = 25 min foothold / 15 min privesc, Medium = 45/25, Hard = 90/45.

```json
{
  "current_vector": {
    "id": "cve-2025-24367-rce",
    "started_at": "2026-05-16T14:00:00Z",
    "budget_min": 25,
    "exhausted": false
  }
}
```

### `hash_jobs[]` shape

Escrito por `crack-helper.sh --async`. Polleable con `scripts/crack_status.py --job-id <id>`.

```json
{
  "hash_jobs": [
    {
      "job_id": "htb-20260516-abc123",
      "hash_preview": "$2y$10$wqlo06...",
      "type": "bcrypt",
      "wordlist": "rockyou75",
      "started_at": "2026-05-16T14:35:00Z",
      "status": "pending_upload"
    }
  ]
}
```

Valores de `status`: `pending_upload` | `running` | `complete` | `no_match` | `timeout` | `error`

### Nota sobre `attempts_failed_in_phase`

Este campo fue declarado en versiones previas pero nunca se implementó. Ha sido reemplazado por `stuck_detector.py`, que lee señales reales de `estado.md`/`findings.md`/`sessions.jsonl`. No documentar ni usar este campo.

---

## v0.3 — Session budget fields (P5)

A partir de v0.3 los siguientes campos aparecen en `data.machines.<slug>`. Opcionales — código v0.2 los ignora vía `.get(...)`.

| Campo | Tipo | Descripción |
|---|---|---|
| `session_started_at` | ISO8601\|null | Inicio del reloj de budget (seteado en p2 PASO 7, mismo valor que `started_at`) |
| `session_budget_min` | int\|null | Budget total: 90/Easy, 180/Medium, 360/Hard, 480/Insane |
| `session_budget_alerts_triggered` | array | ISO8601 timestamps cuando heartbeat disparó el gate de budget |

**Regla de escritura:** `session_budget_alerts_triggered` es append-only. Nunca truncar.

**heartbeat.py exit codes (thresholds):**

| Exit code | Condition | Acción en skill |
|---|---|---|
| 0 | elapsed < 80% budget | Continuar normalmente |
| 1 | 80-100% | WARN en dashboard (solo informativo) |
| 2 | 100-150% | CRITICAL → skill lanza prompt `session_budget_alert` |
| 3 | > 150% | ABANDON_RECOMMENDED → skill sugiere abandonar |

---

## sessions.jsonl (en session dir)

Audit log append-only de operaciones ejecutadas. Formato base por línea:

```json
{"ts": "2026-05-03T14:00:00Z", "phase": "p2-engagement-setup", "event": "vpn_up", "detail": "tun0 IP 10.10.10.1"}
{"ts": "2026-05-03T14:05:00Z", "phase": "p3-delegate-pentest", "event": "checkpoint_recon", "detail": "5 puertos, smbd 3.0.20 vector principal"}
{"ts": "2026-05-03T14:30:00Z", "phase": "p4-flag-submit", "event": "flag_submitted", "detail": "user: OK, root: OK"}
```

### v0.3 — Campo `duration_s` (opcional)

Comandos wrappeados por `tool-timer.sh` agregan `duration_s` (segundos wall-clock) al evento `tool_end`. Campo ausente en eventos anteriores a v0.3. Consumers deben usar `.get("duration_s", 0)`.

```json
{"ts": "2026-05-17T10:00:00Z", "phase": "tool-timer", "event": "tool_start", "detail": "nmap"}
{"ts": "2026-05-17T10:02:00Z", "phase": "tool-timer", "event": "tool_end",
 "detail": "nmap", "duration_s": 120, "exit_code": 0}
```

### Catálogo de event types (v0.3 completo)

| Event | Fuente | Campos extra |
|---|---|---|
| `tool_start` | `tool-timer.sh` | `detail=<tool-name>` |
| `tool_end` | `tool-timer.sh` | `detail=<tool-name>`, `duration_s`, `exit_code` |
| `heartbeat` | `heartbeat.py` | `detail="elapsed=Xmin budget=Ymin idle=Zmin events=N"` |
| `session_start` | Skill p2 (PASO 7) | `detail="budget=Nmin difficulty=<X>"` |
| `session_budget_alert` | Skill p3 (post-heartbeat) | `detail="elapsed=N budget=M choice=<c|p|h|a>"` |
| `fingerprint_complete` | Skill p3 PASO 1.5 | `detail="top=<cat> conf=<X> kb=<true|false>"` |
| `phase_transition` | Skill p3 PASO 5 | `detail="<from>→<to>"` |
| `auto_pivot` | Skill p3 PASO 4.5 | `detail="from=<vec> to=<vec> via=parallel_explorer"` |
| `hash_policy_triggered` | Skill p3 / Hash Policy | `detail="<type>:<elapsed>s no match → <opción>"` |
| `hash_policy_decision` | Skill p3 / Hash Policy | `detail="recommendation=<X> elapsed_min=<N> round=<N>"` |
| `crack_async_dispatched` | Skill p3 / Hash Policy | `detail="job_id=<ID> mode=<M> wordlist=<W>"` |
| `hint_used` | Skill p3 hint mode | `detail="phase=<X> recommendation=<X>"` |
| `flag_submitted` | Skill p4 | `detail="user: OK|FAIL, root: OK|FAIL"` |
| `feedback_complete` | Skill p6 (closure gate) | `detail="<file_size> bytes"` |
| `pentest_complete` | Skill p3 PASO 8 | `detail="user+root via <vectors> (mode=<X>, time=<N>min)"` |
