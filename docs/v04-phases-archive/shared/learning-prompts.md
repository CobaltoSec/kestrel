# Learning Prompts — Checkpoints + Narración Continua HTB

Patrones reusables para `p3-delegate-pentest`. Combina **narración automática** (sin Enter) durante acciones + **HITL críticos** solo en decisiones de impacto.

## Principio

Después del rediseño RT-HTB-INTEL-DRIVEN, p3 se mueve **rápido** narrando en el camino. Solo se detiene en 2-3 puntos críticos donde una mala decisión cuesta tiempo (vector exploit) o es irreversible (acción destructiva, submit).

---

## Continuous Narration Pattern (CORE)

Patrón estándar para cada acción importante en p3. **Sin esperar Enter — solo informa y avanza.**

```
📡 ACCIÓN: <qué se va a hacer en 1 línea>
🔍 HALLAZGO: <qué encontró en 1-2 líneas>
💡 POR QUÉ IMPORTA: <riesgo/oportunidad en 1 línea — qué significa para el chain>
➡ PRÓXIMO: <qué viene>
```

**Ejemplo concreto (recon):**
```
📡 nmap -sV -p- 10.10.11.42 (scan completo TCP + service detection)
🔍 :22 OpenSSH 8.4 / :80 ZoneMinder 1.37.63 / :8080 motionEye 0.43
💡 ZoneMinder 1.37.63 = CVE-2024-51482 (SQLi tid=) según intel. Match exacto.
➡ Salto vuln scan genérico, voy directo a explotar tid= con sqlmap.
```

**Ejemplo concreto (post-foothold):**
```
📡 Shell connectada como www-data via reverse-shell sobre :4444.
🔍 uid=33 sin sudo. Encontré /home/mark/.htpasswd con hash bcrypt.
💡 Bcrypt $2y$10 → wordlist rockyou top 1000 = ~3 min en CPU.
➡ Lanzo hashcat. Si en 5 min no rompe → política hash dispara hint.
```

### Reglas del patrón

1. **Cada bloque máximo 5 líneas.** Si no entra, partilo en dos bloques.
2. **Si la acción es trivial** (ej: `cd /tmp`, `ls -la`, scan <2s), solo emitir `✓ <descripción corta>`. No usar el patrón completo.
3. **No esperar Enter.** Esto es informativo, no HITL.
4. **Idioma español, datos técnicos en formato original** (CVE, IPs, comandos cuando los menciones).
5. **Si hay error inesperado o hallazgo crítico**, agregar línea `⚠ ATENCIÓN:` antes del `➡`.

---

## H1 — CHECKPOINT_SETUP (pre-recon) — AUTO-NARRATED

**Antes:** prompt + Enter para continuar.
**Ahora:** narración automática, sin Enter.

```
📡 EMPEZANDO RECON — <MACHINE_NAME> (<MACHINE_OS>, <DIFFICULTY>) en <IP>
🔍 MODE=<guided|blind>. Intel: <"chain conocido — vector probable: X" | "blind, sin info pública">
💡 En guided saltamos vuln scan genérico. En blind, stuck gate threshold=<1|2>.
➡ Lanzo nmap -sV -p- (TCP completo + service detection).
```

---

## H2 — CHECKPOINT_RECON (post-discovery) — AUTO-NARRATED

**Antes:** prompt con 4 opciones [s/m/e/h] + Enter.
**Ahora:** narración automática + decisión interna sobre próxima acción. Sin prompt.

```
📡 RECON COMPLETO — <MACHINE_NAME>
🔍 Servicios:
   <puerto> | <servicio> | <versión>
   <puerto> | <servicio> | <versión>
💡 Vector elegido: <servicio> en :<puerto> — <razón en 1 línea>.
   Alternativas: <servicio2> (backup si vector primario falla).
   <Si guided + match con intel>: "Match con intel ✓ — sigo el chain conocido"
   <Si guided + mismatch>: "⚠ intel divergente (esperaba X, hay Y) — switching a blind para esta fase"
   <Si blind>: "Versión <X> de <Y> — buscaré CVEs específicos"
➡ <"Salto a confirmar endpoint exacto" | "Lanzo vuln scan dirigido a <framework>">
```

> Si Nico quiere intervenir: puede escribir `pause` o `explain` en cualquier momento. Detección manual del orquestador.

---

## H2.5 — FRAMEWORK DETECTION — AUTO-NARRATED (en guided mode) / OPCIONAL (en blind)

**Guided:** automático. El intel ya tiene framework + CVE confirmado. Solo narrar.
```
📡 Framework confirmado por intel: <framework> <versión>
🔍 CVE clave: <CVE-XXXX-YYYYY> — <descripción 1 línea>
💡 Endpoint específico: <path/param>. Skip nuclei genérico (ahorra ~10 min).
➡ Voy directo al exploit dirigido.
```

**Blind:** opcional. Si Nico ya identificó vector (poco probable sin intel) puede saltar el scan. Default = correr nuclei + searchsploit.

---

## H3 — CHECKPOINT_VULN (pre-exploit) — **HITL CRÍTICO** ⚠

**Único checkpoint que SÍ espera input.** Confirma vector antes de lanzar exploit.

```
=== ⚠ CONFIRMAR VECTOR EXPLOIT ===

Vector: <CVE/técnica>
Mecanismo: <2 líneas — el concepto, no el comando>
Impacto: <qué obtenemos: shell user / shell root / data leak / DoS>
Riesgo: <idempotente | destructivo | crashable>
Reversible: <sí | no — explica>

¿Lanzamos?
[s] sí ejecutar
[e] explicame el mecanismo en más detalle (te lo amplío y vuelvo a preguntar)
[c] cambiar vector (ofrezco alternativas del recon)
[h] hint mode (registra hints_used=true)
```

**Stuck gate H3 (stuck_detector-based):**
- Antes del prompt HITL, invocar:
  ```bash
  python3 sectors/red-team/htb-framework-public/scripts/stuck_detector.py \
      --session-dir <SESSION_DIR> --output <SESSION_DIR>/stuck.json
  ```
- Si `stuck=true` Y `hints_allowed != "false"` Y `recommendation != "continue"` → mostrar antes del prompt:
  ```
  ⚠ Stuck detectado: <signals[]>
    Recomendación: <recommendation> — <rationale>
    Alternativas del attack_plan: <alternatives[]>
  ¿Pivotamos o buscamos hint? [p] pivot  [h] hint  [n] ignorar
  ```
  → `p`: auto-pivot a `alternative_chains[0]` del attack_plan (ver bloque Auto-pivot paralelo en p3 PASO 4.5).
  → `h`: hint mode.
  → `n`: continuar con prompt HITL normal.
- Easy con MODE=guided + match alto: skip stuck gate.
- Si `stuck=false`: mostrar prompt HITL normal sin gate previo.

---

## H4 — CHECKPOINT_FOOTHOLD (shell obtenida) — AUTO-NARRATED

**Antes:** prompt con opciones para encarar privesc.
**Ahora:** narración automática + auto-trigger LinPEAS. Sin prompt.

```
📡 FOOTHOLD ✓ — shell como <user>@<host> via <vector>
🔍 Privilegios: uid=<X> gid=<Y>. <Si guided>: "Intel apunta a privesc por <técnica>"
💡 Chain hasta acá: recon → <servicio> → <exploit> → shell.
   Próximo: privesc <→ root | → SYSTEM>.
➡ Lanzo LinPEAS/WinPEAS automático en background. Mientras, exploro <hint del intel>.
```

> Sin prompt — el orquestador decide entre LinPEAS + exploración manual paralela. Si el vector es no-trivial (ver H5), pausa.

---

## H5 — CHECKPOINT_PRIVESC — **HITL CONDICIONAL** ⚠

Solo si el vector de privesc es **destructivo o crashable** (kernel exploit, race condition, modificar config crítico). Si es trivial (sudo -l con NOPASSWD, SUID gtfobins) → auto-narrated.

```
=== ⚠ VECTOR PRIVESC DESTRUCTIVO ===

Vector: <técnica>
Riesgo: <ej: "kernel exploit puede congelar la VM" | "modifica /etc/passwd, requiere revert">

¿Ejecutamos?
[s] sí | [c] buscar vector menos invasivo | [h] hint
```

**Stuck gate H5:** mismo patrón que H3. Threshold dinámico por dificultad.

---

## H6 — CHECKPOINT_ROOT — AUTO-NARRATED

**Antes:** prompt para repasar antes de submit.
**Ahora:** narración automática del chain completo + handoff a flag-submit. Sin prompt (excepto si Nico escribe `repasar`).

```
🎯 ROOT/SYSTEM ✓ — <MACHINE_NAME> ownada

Chain completo:
  1. Recon    → <servicio> :<puerto> (<versión>)
  2. Foothold → <CVE/técnica> → shell <user>
  3. Privesc  → <técnica> → root/SYSTEM

📂 Flags guardadas:
  user.txt → loot/user.txt ✓
  root.txt → loot/root.txt ✓

📚 Técnicas usadas:
  - <T1>: <1 línea>
  - <T2>: <1 línea>

➡ Continuando a flag submit. (Para repasar, escribí "repasar" antes de continuar.)
```

---

## Hash Policy (NEW — RT-HTB-INTEL-DRIVEN)

Política explícita para cracking de hashes durante p3. Evita el "se cuelga 30 min esperando GPU" del feedback CCTV.

### Triggers

Cuando p3 encuentra un hash crackeable (bcrypt, MD5, SHA1, SHA256, NTLM, NetNTLMv2, etc.) durante recon/exploit:

```
📡 Hash detectado: <tipo> en <archivo/contexto>
🔍 Ejemplo: $2y$10$abc... (bcrypt cost 10)
💡 Política: generar plan context-aware, luego 5 min CPU. Si no rompe → GPU async + continuar.
➡ Paso 1: invocar wordlist_strategy.py. Paso 2: lanzar hashcat con top entry. Paso 3: si falla → async.
```

### Flujo hash completo

**Paso 1 — generar plan (wordlist_strategy):**
```bash
python3 sectors/red-team/htb-framework-public/scripts/wordlist_strategy.py \
    --machine-name <MACHINE_NAME> \
    --vhosts <vhost1,vhost2> \
    --framework <framework|""> \
    --hash-type <bcrypt|md5|sha1|ntlm|...> \
    --output <SESSION_DIR>/wordlist-plan.json
```
Narrar el plan recibido: prioridad 1 = context wordlist, luego common10k, luego rockyou-branch según hash speed.

**Paso 1.5 — leer `recommendation` del plan (auto-decision P1.1):**

```
recommendation = wordlist-plan.json["recommendation"]
```

| Valor | Acción |
|---|---|
| `gpu_async` | **Saltar paso 2 CPU completamente.** Ir directo a GPU async (paso 3 `[g]`) sin prompt. Narrar: `💡 Hash lento + wordlist grande → GPU async directo (política auto). Skip CPU.` |
| `hint_first` | Ofrecer hint antes de CPU: `💡 ¿Querés ver la pista de intel antes de crackear? [h] hint / [c] CPU de todos modos` |
| `cpu` | Flujo normal (paso 2 CPU). |

Append a `sessions.jsonl`:
```json
{"ts":"<TS>","phase":"p3","event":"hash_policy_decision","detail":"recommendation=<X> round=1"}
```

**Paso 2 — primer pase CPU (5 min, solo si `recommendation != gpu_async`):**
```
📡 Hash <tipo> — corriendo plan priorizado: [1] context-<MACHINE_NAME>.txt → [2] common10k → [3] rockyou-variant
🔍 Lanzando hashcat -m <modo> con prioridad 1 (context wordlist, ~<N> entradas).
💡 Si context no rompe en 5 min → dispatch async GPU y sigo con otros vectores.
➡ Timer activo.
```

**Paso 3 — si 5 min pasan sin match (ronda 1-2):**
```
⚠ Hash no rompió en 5 min — disparando GPU async.

Opciones:
[g] GPU async (crack-helper.sh --async → job_id; sigo trabajando en paralelo) ← default recomendado
[h] hint mode (WebSearch "<MACHINE_NAME> password" + writeups → password)
[w] wordlist alternativa (manual — decime cuál)
[s] seguir CPU igual (10 min más)  ← solo disponible en ronda 1
[p] poll job anterior (crack_status.py --job-id <ID> si había job previo)
```

**Paso 3 — ronda 3+ (track via events hash_policy_decision en jsonl):**
```
⚠ Hash sin romper — ronda 3+.

Opciones reducidas:
[g] GPU async
[h] hint mode
[a] abandonar hash — seguir con otros vectores sin resolver esto ahora
```
La opción `[s] seguir CPU` se elimina en ronda 3+ para evitar loops de CPU sin fin.

**Si `[g]` elegido (GPU async):**
```bash
# Desde Kali via SSH
bash scripts/crack-helper.sh --async \
    --hash <HASH_PREVIEW> \
    --hash-mode <HASHCAT_MODE> \
    --wordlist <next_entry_del_plan> \
    --slug <MACHINE_NAME_LOWERCASE>
```
Capturar `job_id` del output. Append a `hash_jobs[]` en `last-cycle.json`:
```json
{"job_id": "<ID>", "hash_preview": "<primeros 20 chars>", "type": "<tipo>",
 "wordlist": "<wordlist>", "started_at": "<ISO8601>", "status": "pending_upload"}
```
Continuar a otros vectores. Para consultar estado más tarde:
```bash
python3 sectors/red-team/htb-framework-public/scripts/crack_status.py \
    --job-id <ID> --jobs-dir sectors/red-team/engagements/.crack-jobs
```

### Excepciones

- **Si MODE=guided + intel menciona el password textualmente**: probar ese password primero. Si falla, correr wordlist_strategy con ese password como extra token.
- **Si MODE=guided + intel menciona wordlist específica**: pasarla como prioridad 1 al plan en lugar del context wordlist.
- **Si ya existe un job en `hash_jobs[]` para este hash**: no relanzar — usar `[p]` para pollear el job existente.

### Registro

Cada vez que la política dispara, append a `sessions.jsonl`:
```json
{"ts": "<TS>", "phase": "p3", "event": "hash_policy_triggered", "detail": "<tipo>:<elapsed>s no match → <opción elegida>"}
```
Si se lanza async job:
```json
{"ts": "<TS>", "phase": "p3", "event": "crack_async_dispatched", "detail": "job_id=<ID> mode=<M> wordlist=<W>"}
```

---

## Hint mode (`/htb hint`)

Si Nico escribe `/htb hint` en cualquier momento durante p3 — o si stuck gate dispara automático:

1. Determinar contexto: ¿qué fase? ¿qué se intentó? ¿qué falló?
2. **Si MODE=guided:** mostrar la sección relevante del `intel.md` (foothold/privesc/gotchas) según fase actual.
3. **Si MODE=blind:**
   - WebSearch `"<MACHINE_NAME> hackthebox <fase>"` (ej: "writeup foothold").
   - Extraer 1-2 pistas del top result — dirección, no solución.
4. Setear `hints_used: true` en `roe.md` + `last-cycle.json`.
5. Append a `sessions.jsonl`: `{"event": "hint_used", "detail": "phase=<fase> recommendation=<prev_recommendation>"}`.

**Ejemplo de hint apropiado (post-recon Lame):**
> "El servicio en :139/:445 es Samba 3.0.20 (2007). Buscá CVE específicos para esa versión — hay uno que permite RCE sin credenciales vía un parámetro de configuración de username."

**Ejemplo de hint inapropiado (spoiler completo):**
> ~~"Usá exploit/multi/samba/usermap_script en MSF con RHOST=<IP>"~~ → NO, eso es la solución completa.

---

---

## Heartbeat Pattern (NEW — RT-KESTREL-V03)

Invocación periódica de `heartbeat.py` para observabilidad + budget alerting.
Nunca bloquea el flow — solo muestra dashboard y retorna exit code.

### Cuándo disparar

Al final de cada PASO mayor de p3 **SI** `(now - last_heartbeat_ts) >= 30 min`:

| PASO | Momento de invocación |
|---|---|
| PASO 1 (discovery) | Después de narrar los servicios detectados |
| PASO 2 (vuln scan) | Después de narrar los findings |
| PASO 4 (exploit) | Después de confirmar shell obtenida |
| PASO 5 (foothold) | Después del enum inicial + antes de privesc |

### Comando

```bash
python3 sectors/red-team/htb-framework-public/scripts/heartbeat.py \
    --session-dir <SESSION_DIR> \
    --state-file fleet/agents/htb/state/last-cycle.json
EXIT=$?
```

### Respuesta por exit code

| Exit code | Acción |
|---|---|
| 0 (OK) | Continuar silenciosamente |
| 1 (WARN, 80-100% budget) | Narrar `⚠️ <X> min vs <Y> min target` y continuar |
| 2 (CRITICAL, 100-150%) | Mostrar prompt `Budget Exceeded` (ver p3 sección final) |
| 3 (ABANDON ×1.5) | Mostrar prompt con `💀` prefix + opción abandonar destacada |

### Tracking last_heartbeat

Mantener timestamp del último heartbeat en memoria durante p3 (no persiste en jsonl — el heartbeat event sí se appendea). Comparar con `now` en cada transición de PASO.

---

## Resumen de HITL en p3 después del rediseño

| Checkpoint | Antes | Ahora | Justificación |
|-----------|-------|-------|---------------|
| H1 setup | Enter | auto | Informativo, no decisión |
| H2 recon | 4 opciones | auto | Narración + decisión interna |
| H2.5 framework | 3 opciones | auto (guided) / opcional (blind) | Intel ya guía |
| **H3 vector** | 4 opciones | **HITL** ⚠ | Decisión crítica pre-exploit |
| H4 foothold | 4 opciones | auto | Auto-trigger LinPEAS |
| H5 privesc | 3 opciones | **HITL condicional** ⚠ | Solo si destructivo |
| H6 root | 2 opciones | auto | Handoff a submit |
| Stuck gates | 2/fase | 1/fase Easy, 2 Medium+ | Más agresivo |
| Hash policy | inexistente | auto-trigger 5 min | Bug feedback CCTV |

**Total HITL p3:** 1-2 críticos (vs 8 actuales).
