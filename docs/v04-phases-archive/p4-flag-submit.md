# Phase p4 — Flag Submit

## Objetivo
Verificar los flags obtenidos, submitirlos a HTB via API, y actualizar el perfil local.

Referencia: `phases/shared/api-helpers.md` — sección "Submit flag".

---

## PASO 1 — Leer flags de loot/

Leer `<SESSION_DIR>/loot/user.txt` y `<SESSION_DIR>/loot/root.txt`.

Mostrar preview (primeros 6 chars + "..." para no exponer el flag completo en pantalla):

```
=== FLAGS ENCONTRADAS ===
  user.txt:  abc123... (<n> chars)
  root.txt:  def456... (<n> chars)

¿Submiteamos ambas a HTB? [s / n]
```

Si alguno de los archivos está vacío o no existe → avisar y preguntar si quiere volver a p3 para extraerlo.

---

## PASO 2 — Submit user flag

```bash
python3 sectors/red-team/htb/htb_cli.py submit <MACHINE_ID> "$(cat <SESSION_DIR>/loot/user.txt)" --difficulty 50
```

Mostrar respuesta de la API.

Si la API responde con error de flag inválida:
1. Mostrar error exacto.
2. Verificar que `loot/user.txt` no tiene newline extra: `cat -A <SESSION_DIR>/loot/user.txt`.
3. Ofrecer: `[r] ingresar flag manualmente | [v] volver a p3 para re-extraer`.

Si exitoso: `✓ User flag submitada.`

---

## PASO 3 — Submit root flag

```bash
python3 sectors/red-team/htb/htb_cli.py submit <MACHINE_ID> "$(cat <SESSION_DIR>/loot/root.txt)" --difficulty 50
```

Misma lógica de error que PASO 2.

Si exitoso: `✓ Root flag submitada.`

---

## PASO 4 — Actualizar profile.json

Ejecutar:
```bash
python3 sectors/red-team/htb/htb_cli.py profile
```

Del JSON resultante, actualizar `fleet/agents/htb/state/profile.json`:
1. Leer `profile.json` actual.
2. Mergear campos desde API: `htb_id`, `rank_text`, `ranking`, `points`, `user_owns`, `system_owns`.
3. Append a `machines_owned[]` si no está ya (verificar por `machine_id`):
```json
{
  "machine_id": <MACHINE_ID>,
  "machine_name": "<MACHINE_NAME>",
  "machine_os": "<MACHINE_OS>",
  "machine_difficulty": "<MACHINE_DIFFICULTY>",
  "owned_user_at": "<TIMESTAMP>",
  "owned_root_at": "<TIMESTAMP>",
  "session_slug": "<SESSION_SLUG>"
}
```
4. Set `updated_at` = now.
5. Escribir `profile.json`.

---

## PASO 5 — Mostrar delta de perfil

```
=== PERFIL ACTUALIZADO ===
  Antes: <user_owns_prev> user / <root_owns_prev> root — <points_prev> pts — Rank: <rank_prev>
  Ahora: <user_owns_new>  user / <root_owns_new>  root — <points_new> pts — Rank: <rank_new>

  <MACHINE_NAME> agregada a machines_owned ✓
```

Si el rank subió: agregar celebración: `🎯 ¡Subiste de rank: <rank_prev> → <rank_new>!`

---

## PASO 6 — Actualizar state y continuar

Actualizar `fleet/agents/htb/state/last-cycle.json`:
```json
{
  "data": {
    "current_phase": "p5-writeup",
    "machines": {
      "<MACHINE_NAME>": {
        "user_owned": true,
        "root_owned": true,
        "owned_user_at": "<TIMESTAMP>",
        "owned_root_at": "<TIMESTAMP>"
      }
    }
  }
}
```

Append a `sessions.jsonl`:
```json
{"ts": "<TS>", "phase": "p4-flag-submit", "event": "flags_submitted", "detail": "user: OK, root: OK, profile updated"}
```

Preguntar: `¿Generamos el writeup ahora? [s / n (saltar a cleanup)]`

- `s` → continuar a `p5-writeup.md`.
- `n` → saltar directamente a `p6-cleanup.md`.
