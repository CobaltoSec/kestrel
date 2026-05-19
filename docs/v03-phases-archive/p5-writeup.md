# Phase p5 — Writeup

## Objetivo
Generar un writeup local de la máquina en formato HTB. Solo para uso propio — no se publica automáticamente.

---

## PASO 1 — Leer contexto de sesión

Leer:
- `<SESSION_DIR>/roe.md` → `MACHINE_NAME`, `MACHINE_OS`, `MACHINE_DIFFICULTY`, `started_at`
- `<SESSION_DIR>/estado.md` → timeline de acciones
- `<SESSION_DIR>/findings.md` → tabla de findings
- `<SESSION_DIR>/recon.md` → puertos y servicios (si existe)
- `last-cycle.json` → `techniques`, `hints_used`, `started_at`, `finished_at`

---

## PASO 2 — Generar writeup.md

Crear `<SESSION_DIR>/writeup.md` con el siguiente esquema:

```markdown
# HTB — <MACHINE_NAME> (<MACHINE_DIFFICULTY>, <MACHINE_OS>)

**Fecha:** <DATE>
**Tiempo total:** <TTOWN_MINS> min
**Dificultad real percibida:** <1-10 subjetivo>
**Hints usados:** <Sí/No>

---

## Resumen ejecutivo

<2-3 líneas: qué era la máquina, qué la hizo interesante, técnica principal>

---

## Recon

### Nmap
```
<output nmap relevante de raw/tcp-<ip>.txt — no pegarlo entero, solo los puertos abiertos>
```

### Análisis de superficie
- **Puerto X / <servicio>:** <por qué fue interesante>
- **Puerto Y / <servicio>:** <por qué fue descartado o secundario>

---

## Foothold

### Vector: <nombre del exploit / CVE>

**¿Cómo funciona?**
<Explicación del mecanismo en prosa — 4-8 líneas. El concepto, no solo el comando.>

**Ejecución:**
```
<comandos / pasos relevantes — redactados, no copy-paste de terminal>
```

**Resultado:** shell como `<usuario>` en `<hostname>`

---

## Privilege Escalation

### Vector: <técnica de privesc>

**¿Cómo funciona?**
<Explicación del mecanismo.>

**Ejecución:**
```
<comandos / pasos>
```

**Resultado:** shell como `root` / `SYSTEM`

[Si la máquina dio root directo, poner: "Root directo — no se requirió privesc separada."]

---

## Chain completo

```
Recon → <servicio>:<puerto> (v<X>)
         ↓
Foothold → <exploit> → <user>@<host>
         ↓
Privesc → <técnica> → root/SYSTEM
```

---

## Técnicas aprendidas / reforzadas

| Técnica | Herramienta | Cuándo usar |
|---------|-------------|-------------|
| <técnica 1> | <tool> | <contexto> |
| <técnica 2> | <tool> | <contexto> |

---

## Paths alternativos

<Si había otros vectores posibles que no se usaron, mencionarlos brevemente.
 Ej: "También había un FTP anónimo — podría haber servido para enumerar archivos,
 pero Samba era más directo.">

---

## Recursos útiles

- <link o referencia que usaste o que habrías usado>
- <KB query que funcionó bien>
```

---

## PASO 3 — Mostrar resumen y confirmar

Mostrar las primeras secciones del writeup generado y preguntar:

```
Writeup generado en: <SESSION_DIR>/writeup.md

¿Querés ajustar alguna sección antes de continuar? [s / n]
```

- `s` → preguntar qué sección ajustar, hacer edición, volver a mostrar.
- `n` → continuar.

---

## PASO 3.5 — Extraer técnica(s) al KB de red-team (opt-in)

### Heurística default

Analizar antes de preguntar:
- ¿El writeup tiene ≥3 secciones técnicas distintas (`## Foothold`, `## Privilege Escalation`, otras `##` técnicas)? → default `s`
- ¿Hay regex `CVE-\d{4}-\d+` en el writeup? → default `s`
- ¿`MACHINE_DIFFICULTY` es `Medium`, `Hard` o `Insane`? → default `s`
- Si ninguna condición → default `n`

Preguntar:
```
¿Extraer técnica(s) al KB de red-team? [s/n] (default: <s|n>)
```

### Si `s`

**1. Determinar técnicas principales** del writeup (1-3 técnicas, cada una genera un archivo):
- 1 archivo por técnica principal (foothold y privesc son archivos separados si las técnicas son distintas).
- Naming: `<DATE>-htb-<machine-slug>-<technique-slug>.md`
  - Ej: `2026-05-03-htb-facts-camaleon-mass-assignment.md`

**2. Generar cada archivo** en `sectors/red-team/kb/staging/query-syntheses/`:

```yaml
---
date: <YYYY-MM-DD>
lab: HTB <MACHINE_NAME> (<machine_id>, <DIFFICULTY> <OS>)
tools: <comma-list de herramientas usadas, extraído del writeup>
target_os: <Linux|Windows>
cve: <CVE-XXXX-XXXXX si aplica, omitir si no>
framework: <stack tecnológico si aplica, ej: camaleon-cms, apache2, sudo>
tags: [htb, <difficulty-lowercase>, <os-lowercase>, <technique-tag>]
---

# <Título técnico> — <vector resumido>

<Intro 1-2 líneas: qué era la vuln/técnica y en qué contexto.>

## Prerequisitos

- <condición que debe cumplirse para que esta técnica aplique>
- <versión vulnerable / misconfiguration / credencial necesaria>

## <Técnica/Vector Principal> ✅

<Explicación del mecanismo — 3-5 líneas.>

```bash
# comandos principales
```

**Gotchas:**
- <algo que no es obvio / que puede fallar>

## Referencias KB

- `python -m kb.query.smart "<query útil para encontrar esto>"`
```

Extraer contenido del writeup — reformatear como playbook reusable, no copy-paste literal.

**Template de oro:** `sectors/red-team/kb/staging/query-syntheses/2026-05-03-camaleon-cms-mass-assignment.md`

**3. Mostrar diff + confirmar** `s/n` antes de escribir cada archivo.

**4. Ingestar al KB:**
```bash
cd C:/Proyectos/CobaltoSec
python -m kb.ingest.loader_external --corpus syntheses
```
(idempotente — skip automático si hash ya existe)

Imprimir:
```
N syntheses ingestadas en KB pgvector
Disponibles vía: python -m kb.query.smart "<técnica>"
```

### Si `n` → continuar a PASO 4 sin hacer nada.

---

## PASO 3.6 — Gap analysis automático

Leer `last-cycle.json.data.machines.<MACHINE_NAME>` y generar tabla de métricas para la sesión:

| Métrica | Valor |
|---------|-------|
| Tiempo total | `<ttown_secs / 60> min` (o calcular desde `started_at` → `finished_at`) |
| Hints usados | `<hints_used: true/false>` |
| Stuck signals | `<stuck_signals_count>` (contar eventos `stuck_*` en `sessions.jsonl`) |
| CVE via web triage | `Sí` si `findings.md` tiene tag `cve-fresh-web`, si no `No` |
| Técnicas exitosas | `<techniques list>` |

**Propuestas de mejora** (1-3, generadas automáticamente según las métricas):
- Si `ttown_secs > 7200` (>2h) Y `hints_used == false` Y `stuck_signals_count >= 2` → "stuck_detector disparó ≥2 veces sin resolver — revisar alternative_chains en fingerprint.json"
- Si `CVE via web triage == No` Y `ttown_secs > 5400` → "Verificar que CVE web triage (p2-discovery PASO 3.5) corrió para todos los servicios con versión"
- Si `stuck_signals_count >= 3` → "Cadena de vectores agotada — revisar tried_credentials + tried_hashes para no repetir entre sesiones"
- Agregar propuestas ad-hoc basadas en las técnicas usadas y la cadena del writeup

Mostrar tabla + propuestas. Luego:

```
¿Appendeamos el gap analysis a SIGUIENTE.md? [s/n] (default: s)
```

Si `s` → append a `C:/Proyectos/CobaltoSec/SIGUIENTE.md`:
```markdown
## RT-HTB-FROM-<MACHINE_SLUG> (gap <DATE>)
- Tiempo: <X> min | Hints: <sí/no> | Intentos fallidos: <N>
- <propuesta 1>
- <propuesta 2>
```

Actualizar `last-cycle.json.data.machines.<MACHINE_NAME>.gap_analysis` con las propuestas (array de strings).

---

## PASO 3.7 — Emitir publish-hint a JobSearch cockpit (opt-in)

Captura metadata del writeup mientras está fresca para que `/job` cockpit
(JobSearch) lo vea como acción `[vis]` y se procese después con `/publish`.

### Heurística default

Default `s` si CUALQUIERA:
- `MACHINE_DIFFICULTY ∈ {Medium, Hard, Insane}`
- Hay regex `CVE-\d{4}-\d+` en el writeup
- ≥3 secciones técnicas distintas (`## Foothold`, `## Privilege Escalation`, otras `##`)

Default `n` si:
- `MACHINE_DIFFICULTY == Easy` AND sin CVE AND ≤2 secciones técnicas (writeup base, no novedoso).

### Preguntar

```
¿Emitir publish-hint para review desde /job cockpit (JobSearch)? [s/n] (default: <s|n>)
```

Si `n` → continuar a PASO 4.

### Si `s` — recolectar metadata

Calcular:
- `MACHINE_SLUG`: lowercase del nombre máquina (ej. `silentium`, `wingdata`).
- `NOVELTY`:
  - `high` si CVE fresh (<6 meses) OR chain multi-vuln OR Hard/Insane.
  - `med` si Medium con técnica notable OR Easy con CVE.
  - `low` si Easy sin CVE pero técnica clara.
- `HOOKS` (csv): top 3-5 ganchos — CVEs encontrados, técnicas (ej. `mass-assignment`, `symlink-traversal`, `ssrf`), frameworks vulnerables.
- `TAGS` (csv): `htb,<difficulty-lowercase>,<os-lowercase>,<technique-tag-1>,<technique-tag-2>`.

HTB writeups NO requieren sanitización de IPs (10.10.X.X son rangos HTB públicos) ni clientes (HTB es lab público). `--redact-credentials` solo si hay hashes/secrets que aparecieron en flag intermedia (poco común).

### Invocar emit.py

```bash
python ".claude/skills/_shared/publish-prep/emit.py" \
  --type htb \
  --source "htb-<MACHINE_SLUG>" \
  --source-artifact "<SESSION_DIR>/writeup.md" \
  --novelty <high|med|low> \
  --hooks "<HOOKS>" \
  --tags "<TAGS>" \
  --suggested-format blog \
  --suggested-project "" \
  --emitter "htb/p5-writeup"
```

**No bloqueante.** Si emit.py exit≠0 → anotar y seguir.

Imprimir:
```
Hint emitido: <path>. Verlo en próximo /job (sección VISIBILITY).
```

---

## PASO 4 — Actualizar state y continuar

Actualizar `fleet/agents/htb/state/last-cycle.json`:
```json
{
  "data": {
    "current_phase": "p6-cleanup"
  }
}
```

Append a `sessions.jsonl`:
```json
{"ts": "<TS>", "phase": "p5-writeup", "event": "writeup_generated", "detail": "<SESSION_DIR>/writeup.md"}
```

Continuar a `p6-cleanup.md`.
