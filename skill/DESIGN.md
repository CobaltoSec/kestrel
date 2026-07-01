# Kestrel — Design Document

> **Versión**: v0.1 (2026-05-08) — actualizado v0.1.1 (2026-05-12)
> **Status**: internal — NOT for publication. Iterate 2-3x before sanitizing.
> **Nombre**: Kestrel — cernícalo que hovea observando el target antes de clavar. Intel phase = hover, execution = dive.
>
> **2026-05-12 (bloque KESTREL-RENAME-PUBLIC-OSS):** Skill renombrada de `/htb` → `/kestrel` (`/htb` queda como alias). Scripts core movidos a source of truth único: `htb-framework-public/scripts/`. Auto-push a GitHub integrado en `/cierre` Paso 5b.

---

## ¿Qué es Kestrel?

Un orquestador de engagements contra VMs de HackTheBox. Su diferenciador es que aplica una capa de inteligencia antes de ejecutar: en máquinas retired lee writeups públicos para ir directo al CVE; en máquinas active clasifica el target por ports/servicios para priorizar el vector de ataque.

**No es:** un scanner, un exploit framework, ni un bot que resuelve HTB solo.
**Es:** un sistema de toma de decisiones que reduce una VM desconocida a una secuencia de pasos ejecutables, con HITL solo en los ~6 momentos que realmente importan.

---

## Arquitectura — 4 Layers

```
┌─────────────────────────────────────────────────────────┐
│  4. MEMORY                                              │
│     estado.md · state.json · writeup.md                 │
│     KB synthesis · publish-hint                         │
│     → persiste entre sesiones, aprende de cada run      │
├─────────────────────────────────────────────────────────┤
│  3. EXECUTION                                           │
│     delegado a /pentest --mode lab                      │
│     p2-discovery → p3-vuln → p4-exploit                 │
│     → Kestrel no ejecuta comandos, orquesta             │
├─────────────────────────────────────────────────────────┤
│  2. ORCHESTRATION                                       │
│     fases p0→p1→p1.5→p2→p3→p4→p5→p6                    │
│     MODE switching · HITL gates · narración continua    │
│     → el motor de workflow, núcleo de Kestrel           │
├─────────────────────────────────────────────────────────┤
│  1. INTEL                                               │
│     WebSearch retired + blind_fingerprint.py active     │
│     intel.md · fingerprint.json · KB auto-query         │
│     → los ojos antes del dive                           │
└─────────────────────────────────────────────────────────┘
```

### Layer 1 — Intel

**Responsabilidad**: conocer el target antes de tocar la red.

**Guided mode (retired machines):**
- WebSearch 4 queries paralelas (0xdf, IppSec, community)
- WebFetch top-3 URLs → síntesis anti-spoiler
- Output: `intel.md` con confidence (high/medium/low) + chain probable

**Blind mode (active machines):**
- HTB TOS: no writeups para active → no WebSearch
- `scripts/blind_fingerprint.py` post-discovery:
  - Clasifica ports/services/banners → attack_categories con confidence scores
  - KB auto-query para categories con confidence ≥ 0.80
- Output: `fingerprint.json` con attack_categories + kb_results

**Files:**
- `phases/p1.5-intel-recon.md` — orquestador de la phase
- `phases/shared/intel-prompt.md` — template intel.md + reglas anti-spoiler
- `scripts/blind_fingerprint.py` — clasificador L1 blind mode

---

### Layer 2 — Orchestration

**Responsabilidad**: el workflow completo, las decisiones, el HITL.

**Phases:**
| Phase | File | Función |
|---|---|---|
| p0 | `p0-welcome.md` | Dashboard + detección sesión activa + resume proactivo |
| p1 | `p1-target-pick.md` | Lista máquinas via API, extrae MACHINE_RETIRED |
| p1.5 | `p1.5-intel-recon.md` | Intel guided (WebSearch) o blind (fingerprint handoff) |
| p2 | `p2-engagement-setup.md` | SESSION_DIR + roe.md + VPN + spawn + ping |
| p3 | `p3-delegate-pentest.md` | **Core**: branch guided/blind, narración continua, HITL críticos |
| p4 | `p4-flag-submit.md` | Submit user+root via HTB API, actualizar profile |
| p5 | `p5-writeup.md` | Writeup + KB synthesis + gap analysis + publish-hint |
| p6 | `p6-cleanup.md` | Release + VPN down + debrief + feedback.md |

**Decisiones de diseño clave:**
- HITL ~6 (vs ~19 pre-rediseño) — solo en vector exploit (H3) y privesc destructivo (H5 condicional)
- Narración continua 📡🔍💡➡ sin Enter mid-flight — Nico aprende mientras mira, no al final
- Stuck gate Easy threshold=1 guided skip, 1 attempt blind — agresivo para no perder tiempo
- Hash Policy 5 min max CPU → GPU/hint automático — nunca bloquear el flow por un hash

---

### Layer 3 — Execution

**Responsabilidad**: ejecutar los comandos reales contra el target.

Kestrel **no ejecuta directamente**. Delega a `/pentest --mode lab`:
- `p2-discovery.md` → nmap + recon.md
- `p3-vuln.md` → vuln checks priorizados
- `p4-exploit.md` → exploit + post-exploitation

**Contrato de handoff L2 → L3:**
```
MODE=lab                        (skip: host-opsec, MAC, DNS, host-mon, Ledger)
TARGET=<TARGET_IP>
ENGAGEMENT_DIR=<SESSION_DIR>
PLATAFORMA=kali
PRIORITY_SERVICE=<de fingerprint.json en blind> (optional)
SKIP_GENERIC_NUCLEI=true        (solo en blind con fingerprint confidence ≥ 0.70)
```

**Bottleneck actual**: handoff es one-way. Si /pentest encuentra algo inesperado (AD chain compleja, RBCD), Kestrel no replantea — solo ejecuta el stuck gate. Mejora futura: feedback loop L3→L2.

---

### Layer 4 — Memory

**Responsabilidad**: persistir estado entre sesiones + aprender de cada engagement.

**Durante engagement:**
- `estado.md` — notas narrativas del progreso
- `last-cycle.json` — state machine (current_phase, kali_listeners, next_step_hint, etc.)
- `sessions.jsonl` — audit log append-only

**Post-engagement:**
- `writeup.md` — writeup completo (8 secciones)
- KB synthesis → `sectors/red-team/kb/staging/query-syntheses/*.md`
- `publish-hint.json` → queue para eventual publicación en `cobalto-sec.tech/blog`
- `feedback.md` — debrief 2 preguntas (friction, take-away)

**Resume cross-session (v0.1):**
- `scripts/resume_validator.sh` corre en Kali — valida VPN + machine IP + listeners
- p0-welcome PASO 3 lo invoca proactivamente al detectar sesión paused
- Auto-recovery: re-up VPN + respawn machine + restart listeners

**Loop L4 → L1**: KB syntheses generadas en p5 alimentan `kb_results` de futuros blind fingerprints via `red-team-query`.

---

## Handoff Contracts

### L1 → L2
`intel.md` (guided) ó `fingerprint.json` (blind) en `SESSION_DIR/` + campos en `last-cycle.json`:
```json
{
  "intel_confidence": "high|medium|low|none",
  "htb_mode": "guided|blind",
  "blind_fingerprint_path": "...",
  "blind_fingerprint_top": "ad-abuse",
  "blind_fingerprint_conf": 0.85
}
```

### L2 → L3
Variables en `roe.md` frontmatter + override fields en el call a pentest:
```yaml
mode: lab
htb_mode: guided|blind
target: 10.10.10.x
priority_service: smb          # solo blind
skip_generic_nuclei: true      # solo blind con conf ≥ 0.70
```

### L3 → L4
Artifacts en `SESSION_DIR/`:
- `recon.md`, `findings.md`, `loot/user.txt`, `loot/root.txt`
- Updates a `estado.md` y `last-cycle.json` (techniques[], gaps_found[])

### L4 → L1 (feedback loop)
Post-engagement:
- `kb.ingest.loader_external --corpus syntheses` ingesta las syntheses
- Próxima sesión blind: `blind_fingerprint.py` hace KB auto-query con los mismos tags → chunks disponibles

---

## Decision Log

| Decisión | Por qué |
|---|---|
| **Retired-only WebSearch** | HTB TOS prohíbe writeups para active machines. Skip por compliance, no por capacidad. |
| **HITL ~6 vs ~19** | El rediseño RT-HTB-INTEL-DRIVEN (2026-05-06) redujo prompts eliminando confirmaciones triviales. Solo H3 (vector exploit) y H5 (privesc destructivo) son obligatorios. |
| **Narración continua sin Enter** | Nico aprende mejor leyendo output completo mientras corre (preferencia documentada en engram). Enter mid-flight interrumpe el flow y aumenta fricción. |
| **Hash Policy 5 min → GPU/hint** | Kobold case: bcrypt tardó 45 min CPU que era evitable. Política proactiva = no bloquear flow por un hash. |
| **Stuck gate Easy threshold=1** | Easy guided: skip (intel ya guía). Easy blind: 1 intento fallido = hint. Agresivo pero justificado — Easy nunca debería necesitar más. |
| **L3 delegado a /pentest** | Kestrel no re-implementa recon/vuln/exploit. Hereda el 90% de la lógica de pentest. Evita duplicación. El costo es rigidez en el handoff (ver bottlenecks). |
| **4 layers (no 6)** | Kestrel es una tool específica, no la plataforma completa. Con 4 layers hay separación limpia sin over-engineering. Los adapters a la plataforma (KB, session-mgr global) son interfaces, no layers propios. |

---

## Bottlenecks Identificados

| Layer | Bottleneck | Impacto | Mitigación Futura |
|---|---|---|---|
| **L1** | Blind mode sin writeups = clasificación de puertos solo. Funciona para Easy/Medium pero pierde matiz en Hard AD chains. | ~30% menos contexto en chains complejas | L1 v1.1: multi-path hypothesis (top-3 chains probable con prob) |
| **L2** | Handoff L2→L3 es one-way. Si /pentest encuentra algo inesperado, Kestrel no replantea. | Garfield: RBCD chain no estaba en el flow → pausado | L2 v1.2: feedback loop L3→L2 via estado.md parsing |
| **L3** | Contrato de handoff no fuerza que /pentest devuelva señales de "stuck". | Stuck en L3 = stuck en Kestrel | L3 v1.1: webhook/event desde p4-exploit de vuelta a Kestrel |
| **L4** | KB synthesis es opt-in (default `s` pero igual es gate). | Algunas sesiones no sintetizan | L4 v1.1: síntesis automática default=true para Medium+ |
| **L4** | Resume cross-session depende de que Kali esté accesible para validar. | Si Kali está down, resume validator falla gracefully pero no da info | L4 v1.1: cache del estado en last-cycle.json para resume offline |

---

## Iteration Log

### v0.1 — 2026-05-08 (este finde)
- **L1**: Blind fingerprinting layer implementado (`blind_fingerprint.py` + p1.5 PASO 6 + p3 PASO 1.5)
- **L2**: Snapshot hooks en p3 (next_step_hint + last_phase_completed)
- **L4**: Resume hardening: `resume_validator.sh` + p0-welcome validación proactiva + state-schema extendido
- **Docs**: este DESIGN.md + `docs/topics/htb-framework.md` v0.1

### v0.2 — Pendiente (iteración 2)
Hypothesis (confirmar con uso real):
- L1: multi-path hypothesis si confidence < 0.60
- L3: feedback loop quando /pentest encuentra AD chain compleja
- L4: KB synthesis automática sin gate para Medium+
- Test: Garfield (Hard, active) como validación real de blind mode

### v0.3 — Pendiente (iteración 3, pre-publish)
- Sanitización para repo público `cobaltosec-htb-framework`
- README.md público con ATT&CK coverage + layer model
- Garfield case study (owned o limits documented)
- Comparación vs otras tools HTB (AutoPwn, HackBot, IppSec AI)

---

## ATT&CK Coverage

| Táctica | # | Cómo la cubre Kestrel |
|---|---|---|
| Reconnaissance | 1 | p1.5 WebSearch (guided) + fingerprint.py port/banner scan (blind) |
| Initial Access | 3 | p3 exploit phase via /pentest |
| Execution | 4 | p3 post-foothold commands via /pentest |
| Privilege Escalation | 6 | p3 PASO 5-6 (LinPEAS/WinPEAS + guided vector) |
| Credential Access | 8 | p3 hash detection + Hash Policy automation |
| Discovery | 9 | p3 PASO 1 (discovery) + fingerprint.py classification |

Gaps (no cubiertos directamente):
- T1 Resource Development (2), T1 Persistence (5), T1 Lateral Movement (10): solo en chains complejas como Garfield, manejados por /pentest-ad cuando aplica.

---

## Comparación con otras tools HTB

| Tool | Approach | Diferencia vs Kestrel |
|---|---|---|
| **AutoPwn** | Fully automated, no HITL | Kestrel mantiene HITL en decisiones críticas — aprendizaje + control |
| **HackBot** | LLM-guided, genérico | Kestrel es domain-specific (HTB VMs), con state + KB + writeup pipeline |
| **IppSec AI** | Q&A sobre writeups | Kestrel no responde preguntas — ejecuta y narra |
| **Penelope** | Reverse shell handler | Solo L3, sin L1/L2/L4 |
| **Autorecon** | Recon automation | Solo recon (L3 sub-component), sin intel/orchestration/memory |
