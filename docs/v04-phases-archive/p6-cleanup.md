# Phase p6 — Cleanup + Debrief

## Objetivo
Cerrar la sesión limpiamente (release machine + VPN down) y capturar aprendizajes con un debrief estructurado.
El debrief captura mejoras a `/pentest` automáticamente — no como paso manual post-sprint.

Referencia: `phases/shared/debrief-template.md` — template completo de `feedback.md`.
Referencia: `phases/shared/api-helpers.md` — secciones VPN y release.

---

## PASO 1 — Cleanup técnico

### 1.1 — Release machine

```bash
python3 sectors/red-team/htb/htb_cli.py release <MACHINE_ID>
```

Si falla (ej: ya fue terminada automáticamente por HTB): ignorar error y continuar.

### 1.2 — VPN down

```bash
bash scripts/htb-vpn.sh down
```

Verificar que no quedan rutas `10.10.*`:
```bash
bash scripts/htb-vpn.sh status
```

Si quedan rutas residuales: `bash scripts/htb-vpn.sh cleanup`.

### 1.3 — Marcar sesión como finalizada

Actualizar `<SESSION_DIR>/roe.md`: set `finished_at: <TIMESTAMP_ISO8601>`.

Actualizar `estado.md`: append fila "engagement finalizado" al timeline.

---

## PASO 2 — Debrief comprimido (2 preguntas core)

Post-rediseño RT-HTB-INTEL-DRIVEN: el debrief se acorta a 2 preguntas core (vs 5 anteriores). El resto se infiere automáticamente del state (`time_spent_minutes`, `hash_policy_triggered`, `htb_mode_used`, `intel_match`).

```
=== DEBRIEF EXPRESS — <MACHINE_NAME> ===

📊 Auto-stats:
  Tiempo:        <TTOWN_MINS> min vs target Easy ≤90min
  Mode:          <guided|blind>  (intel match: <full|partial|divergent|na>)
  Hints usados:  <Sí|No>
  Hash policy:   <triggered|no>
  HITL count:    <N>  (target: ≤6)

2 preguntas (responde corto, bullets ok):
```

**Q1 — Friction:** "¿Qué te frenó más durante el run?"
- Opciones sugeridas en el prompt (Nico puede combinar):
  - intel divergente / outdated
  - vuln scan blind
  - hash crack lento
  - exploit no funcionó primer intento
  - privesc no obvio
  - VPN HTB inestable
  - ninguno — fluyó

**Q2 — Take-away:** "¿Qué técnica de hoy te llevás a otra máquina/engagement?"
- 1-2 líneas: la técnica + por qué te interesa replicarla.

**Bonus opcional (solo si Nico tiene ganas):**
- "¿Algo concreto que mejorarías en `/htb` o `/pentest`?" → si responde, alimenta PASO 5.

---

## PASO 3 — Generar feedback.md

Usando el template de `phases/shared/debrief-template.md`, crear `<SESSION_DIR>/feedback.md` rellenando con las respuestas de Nico.

Tiempo aproximado (calcular desde `started_at` de `roe.md` hasta ahora):
```
TTOWN_SECS = now - started_at
TTOWN_MINS = TTOWN_SECS / 60
```

Incluir en el header del feedback.md: session slug, fecha, tiempo total, hints usados.

---

## PASO 4 — Append al log cross-machine

Leer o crear `sectors/red-team/htb/htb-feedback-log.md`.

Append al final:
```markdown

## <MACHINE_NAME> — <DATE>
- **Tiempo:** <TTOWN_MINS> min | **Hints:** <Sí/No>
- **Técnicas:** <lista de techniques de last-cycle.json>
- **Gaps tools:** <resumen Q1 — "ninguno" si no hubo>
- **Gaps KB:** <resumen Q2>
- **Mejoras /pentest:** <resumen Q3 + Q4>
```

---

## PASO 5 — Proponer bloque en SIGUIENTE.md (si hay mejoras)

Si las respuestas de Q3, Q4, o Q7 identificaron mejoras concretas a `/pentest` o `/htb`:

Construir propuesta de bloque y **mostrarla a Nico** antes de escribir:

```
=== PROPUESTA SIGUIENTE.md ===
Basado en el debrief de <MACHINE_NAME>, propongo agregar:

### RT-PENTEST-IMPROVEMENTS-FROM-HTB — Mejoras post-<MACHINE_NAME>
- <mejora 1> — <contexto: surgió porque ...>
- <mejora 2> — <contexto>
- <mejora 3> — <contexto>

¿Agregamos esto a SIGUIENTE.md? [s / n / editar]
```

Si `s` → leer `SIGUIENTE.md`, append el bloque bajo "## Otras opciones", guardar.
Si `editar` → Nico dicta los cambios, mostrar resultado, confirmar nuevamente.
Si `n` → no modificar SIGUIENTE.md.

---

## PASO 6 — Guardar en engram

```
mem_save:
  title: "HTB <MACHINE_NAME> (<MACHINE_OS> <MACHINE_DIFFICULTY>) — técnicas + lecciones"
  type: discovery
  scope: project
  topic_key: htb/lessons/<MACHINE_NAME_LOWER>
  content:
    What: Máquina <MACHINE_NAME> ownada. <user_owned + root_owned, tiempo TTOWN_MINS min>.
    Why: Sprint RT-HTB-1 — aprendizaje red-team con plataforma pública.
    Where: sectors/red-team/htb-sessions/<SESSION_SLUG>/
    Chain: <TÉCNICA_RECON> → <TÉCNICA_FOOTHOLD> → <TÉCNICA_PRIVESC o "root directo">
    Técnicas: <lista techniques>
    Mode: <guided|blind> (intel match: <full|partial|divergent|na>)
    Hints usados: <Sí/No>
    Hash policy triggered: <Sí/No>
    Friction: <de Q1 — qué frenó>
    Take-away: <de Q2 — técnica que se lleva>
    HITL count: <N> (target ≤6)
```

---

## PASO 6.5 — HARD GATE: validar feedback.md ⛔

**Antes de cerrar la sesión** — verificar que `<SESSION_DIR>/feedback.md` existe y está completo.

Secciones requeridas (las 5 del template en `phases/shared/debrief-template.md`):
1. `## 1. Tools faltantes`
2. `## 2. KB gaps`
3. `## 3. Pentest skill`
4. `## 4. Lab mode skips`
5. `## 5. Hint mode`

**Validación:**
```
FEEDBACK_PATH = <SESSION_DIR>/feedback.md
REQUIRED_SECTIONS = ["## 1.", "## 2.", "## 3.", "## 4.", "## 5."]
```

Si el archivo NO existe o le faltan secciones:
```
⛔ CLOSURE BLOCKED — feedback.md incompleto o ausente.
   Secciones faltantes: <lista>

No puedo cerrar la sesión sin el debrief estructurado.
Necesito que respondas las preguntas del template:
```
→ Lanzar el debrief express del PASO 2 para las secciones faltantes.
→ Completar el archivo feedback.md.
→ Repetir validación hasta que pase.

Si el archivo SÍ existe con todas las secciones:
```
✅ feedback.md validado (<N> bytes, 5 secciones)
```
Append a `<SESSION_DIR>/sessions.jsonl`:
```json
{"ts": "<TS>", "phase": "p6-cleanup", "event": "feedback_complete",
 "detail": "<file_size_bytes> bytes"}
```

---

## PASO 7 — Actualizar last-cycle.json y cerrar sesión

Actualizar `fleet/agents/htb/state/last-cycle.json`:
```json
{
  "last_run": "<TIMESTAMP>",
  "data": {
    "current_phase": null,
    "current_session": null,
    "machines": {
      "<MACHINE_NAME>": {
        "finished_at": "<TIMESTAMP>",
        "ttown_secs": <TTOWN_SECS>,
        "gaps_found": ["<gap1>", "<gap2>"]
      }
    }
  }
}
```

Append final a `sessions.jsonl`:
```json
{"ts": "<TS>", "phase": "p6-cleanup", "event": "session_closed", "detail": "release OK, VPN down, debrief completo, feedback.md generado"}
```

---

## PASO 8 — Cierre

```
=== SESIÓN CERRADA ===
Máquina:  <MACHINE_NAME> ownada ✓
Tiempo:   <TTOWN_MINS> min
Flags:    user.txt ✓ | root.txt ✓
VPN:      DOWN ✓
Machine:  released ✓

Sesión guardada en: sectors/red-team/htb-sessions/<SESSION_SLUG>/

¿Siguiente máquina? → /htb para una nueva sesión
```
