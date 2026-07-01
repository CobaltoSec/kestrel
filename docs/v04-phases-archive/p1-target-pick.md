# Phase p1 — Target Pick

## Objetivo
Listar máquinas HTB disponibles y dejar que Nico elija el target.

Referencia: `phases/shared/api-helpers.md` — sección "Listar machines".

---

## PASO 1 — Obtener lista de machines

```bash
python3 sectors/red-team/htb/htb_cli.py list --difficulty Easy
```

Si falla (error de auth o red):
1. Mostrar el error exacto.
2. Verificar token: ¿existe `C:\Users\nicol\.htb\token`?
3. Ofrecer: `[r] reintentar | [m] ingresar machine manualmente por ID/nombre | [q] abortar`.

---

## PASO 2 — Filtrar y mostrar tabla

Del JSON resultante, filtrar máquinas no ownadas (`authUserInUserOwns == false`).
Ordenar por rating descendente. Mostrar las primeras 15:

```
=== MACHINES DISPONIBLES (Easy Retired, no ownadas) ===

  #   ID     Nombre       OS        Pts   Rating
  1   [id]   [nombre]     Linux     20    4.8
  2   [id]   [nombre]     Windows   20    4.6
  ...

Filtros activos: Retired=Yes | Difficulty=Easy | No ownadas
Cambiar: [m]=Medium | [w]=Windows only | [l]=Linux only | [t]=todas las dificultades
```

Si no hay resultados con filtro Easy → expandir a Medium automáticamente y avisar.

Recomendaciones clásicas para primer run (si aparecen en la lista):
- **Lame** (Linux) — Samba 3.0.20 RCE, la más básica del catálogo, no requiere privesc
- **Legacy** (Windows) — MS08-067 / MS17-010, entrada clásica Windows
- **Devel** (Windows) — IIS FTP + token impersonation, buen intro a privesc Windows

---

## PASO 3 — User elige

```
¿Cuál elegís? [número de la tabla | nombre de la máquina | auto | cambiar filtro]

  auto → elige la primera Easy retired no ownada (mayor rating)
```

Procesar respuesta:
- Número → elegir la máquina en esa posición de la tabla.
- Nombre → buscar en la lista (case-insensitive). Si no está, buscar con `python3 sectors/red-team/htb/htb_cli.py list` sin filtro.
- `auto` → elegir `machines[0]` de la lista filtrada.
- Cambiar filtro (`m`, `w`, `l`, `t`) → volver al PASO 1 con nuevo filtro y re-mostrar.

---

## PASO 4 — Confirmar selección

```
=== TARGET SELECCIONADO ===
Nombre:       <MACHINE_NAME>
ID:           <MACHINE_ID>
OS:           <MACHINE_OS>
Dificultad:   <MACHINE_DIFFICULTY>
Rating:       <RATING>
IP:           (se asigna al spawnear en p2)

¿Confirmamos y pasamos al setup? [s / n / ver-otra]
```

- `n` o `ver-otra` → volver al PASO 2.
- `s` → guardar variables de sesión y continuar.

---

## PASO 5 — Guardar estado y continuar

Del JSON de la máquina elegida, extraer también:
- `MACHINE_RETIRED` — boolean. Si la fetcheaste con filtro retired (default), es `true`. Si usaste `--active`, es `false`. También se puede leer del field `retired` o `release` (release date pasada = retired).
- `MACHINE_TAGS` — array de tags si la API los expone (puede estar vacío).
- `MACHINE_RATING` — float (rating de la máquina).

Esta info alimenta a **p1.5-intel-recon** que decide entre `MODE=guided` (retired, WebSearch agresivo) o `MODE=blind` (active, sin writeups por TOS HTB).

Actualizar `fleet/agents/htb/state/last-cycle.json`:
```json
{
  "data": {
    "current_phase": "p1-target-pick",
    "current_session": null,
    "machines": {
      "<MACHINE_NAME>": {
        "machine_id": "<MACHINE_ID>",
        "machine_os": "<MACHINE_OS>",
        "machine_difficulty": "<MACHINE_DIFFICULTY>",
        "machine_retired": <true|false>,
        "machine_tags": [<...>],
        "machine_rating": <RATING>
      }
    }
  }
}
```

Variables de sesión para las fases siguientes:
- `MACHINE_ID` — ID numérico
- `MACHINE_NAME` — nombre (slug, ej: `lame`)
- `MACHINE_OS` — `Linux` | `Windows`
- `MACHINE_DIFFICULTY` — `Easy` | `Medium`
- `MACHINE_RETIRED` — `true` | `false` (decide intel policy en p1.5)
- `MACHINE_TAGS` — array de tags
- `MACHINE_RATING` — float

Continuar a `p1.5-intel-recon.md`.
