# Kestrel — Triage de Scripts v0.2 / v0.3

> Auditoria HITL del estado de `scripts/` previo al proximo release.
> Fecha: 2026-05-16. Autor: framework maintainer.
> Repo: `github.com/CobaltoSec/kestrel` — ultimo release: **v0.1.0** (tag, 2026-05-08).
> Refs internas: `RT-KESTREL-CLOSE` (cierre v0.1), `KESTREL-V02-IMPL` (este sprint), `KESTREL-V02-VALIDATE` (sig.), `KESTREL-V02-PUBLISH` (release).

---

## 1. TL;DR

**8 scripts** auditados (5 nuevos untracked + 3 ya shipped). **5 entran en v0.2.0** con polish minimo, **0 candidatos a archive/delete**.

- Bucket dominante: **SHIP v0.2.0** (5/5 untracked production-ready).
- Test suite: **6 modulos nuevos** ya escritos (golden + 5 unit), todos verdes en CI segun CHANGELOG.
- CI workflow (`.github/workflows/test.yml`) corre **solo ruff** — falta el job de pytest.
- Skill `/kestrel` **ya invoca los 5 scripts** desde phases (`p3-delegate-pentest.md`, `learning-prompts.md`, `state-schema.md`) → **wire-up esta hecho del lado consumer**, pero el repo publico todavia esta en v0.1.0 → desincronizado.

**Recomendacion: bloque proximo = `RT-KESTREL-V02` directo (no V03).**
La logica esta escrita, los tests existen, el skill consume las APIs. Lo que falta es:
1. Validacion E2E real contra una HTB (MonitorsFour S4 propuesto en CHANGELOG).
2. Polish CI (agregar pytest job a `test.yml`).
3. CHANGELOG ya tiene draft de Unreleased — solo falta cerrar fecha + tag.
4. Bump version + push tag `v0.2.0` + GitHub Release.

Ir a v0.3 directo seria saltarse el deliverable validado que ya esta el 90% terminado. **No tiene sentido.**

---

## 2. Tabla maestra

| Script | Bucket | Purpose | Layer | LOC | Madurez | Skill lo usa | Accion |
|---|---|---|---|---|---|---|---|
| `blind_fingerprint.py` | SHIPPED v0.1 | Clasifica nmap/httpx en 8 attack categories + confidence + (v0.2) `attack_plan` con primary/alternative/parallel | Intel (L1) | 565 (estimado) | Production | si — p1.5, p3 | extender en v0.2 (golden tests + attack_plan field) |
| `resume_validator.py` | SHIPPED v0.1 | Health check cross-session: VPN/host/listeners | Memory (L4) | ~120 | Production | si — p0-welcome | sin cambios v0.2 |
| `resume_validator.sh` | SHIPPED v0.1 | Wrapper Kali-side de validator.py | Memory (L4) | 659 bytes | Production | si — p0-welcome | sin cambios v0.2 |
| `wordlist_strategy.py` | **SHIP v0.2.0** | Plan context-aware por hash-type (fast/slow), tokens machine+vhost+framework + CeWL recipe + estimaciones | Intel (L1) | 299 | Production-ready | **si** — `learning-prompts.md` § Hash Policy | Ship as-is. Test cubre bcrypt + md5 + ntlm |
| `state_inspector.py` | **SHIP v0.2.0** | Query helper para `tried_credentials[]` / `tried_endpoints[]` / `tried_hashes[]` en `last-cycle.json` | Memory (L4) | 183 | Production-ready | **si** — `p3-delegate-pentest.md` (cross-session dedup), `state-schema.md` | Ship as-is. Backward compatible (fields optional) |
| `stuck_detector.py` | **SHIP v0.2.0** | Detecta `shell_lost` / `hash_stuck` / `cred_exhausted` / `progress_stalled` desde `estado.md`+`findings.md`+`sessions.jsonl`. Emite recomendacion `switch_vector` / `escalate_gpu` / `reset_listener` / `continue` | Orchestration (L2 → L3 feedback) | 245 | Production-ready | **si** — `p3-delegate-pentest.md` (Stuck gate H3), `learning-prompts.md` § H3, auto-pivot trigger | Ship as-is. Validado contra MonitorsFour S3 segun CHANGELOG |
| `crack_status.py` | **SHIP v0.2.0** | Poll de async hash-crack job (Colab/Kaggle GPU offload). Lee `<job>.json` + `<job>.result.json`, calcula timeout, retorna status + exit code | Execution (L3) + Memory (L4) | 152 | Production-ready | **si** — `learning-prompts.md` § Hash Policy `[p]` poll | Ship as-is. Tests cubren los 6 status (complete/no_match/pending/expired/error) |
| `parallel_explorer.py` | **SHIP v0.2.0** | Thread pool (default 4 workers) que ejecuta tasks via SSH-to-Kali. Cada task = SSH command + timeout. Stdout/stderr tails (4KB). `--dry-run` para CI | Execution (L3) | 199 | Production-ready | **si** — `p3-delegate-pentest.md` PASO 4.5 (auto-pivot paralelo) | Ship as-is. Test marca skip en Windows local (bash en CI ubuntu OK) |

**Buckets:**
- SHIP v0.2.0: 5 (todos los untracked relevantes)
- POLISH v0.2.x: 0
- POC ARCHIVE: 0
- DELETE: 0

---

## 3. Ficha detallada por script

### `wordlist_strategy.py` (sub-bloque B)

**Purpose.** Reemplaza "rockyou everywhere" por un plan priorizado que tokeniza machine_name (CamelCase split) + vhosts (descarta htb/com/net/local) + framework, genera un context wordlist de ~50-200 entries (years 2024-26 + suffixes !,123,@1,01), y ramifica por hash speed: SLOW (bcrypt/argon2/scrypt/pbkdf2) → rockyou-75k + CeWL recipe + GPU full rockyou; FAST (md5/sha1/ntlm) → rockyou+best64 + CeWL+best64 + rockyou+dive GPU. Emite estimaciones de tiempo CPU pesimistas. **No ejecuta** — solo emite JSON con paths, rules y comandos CeWL para el caller. Test coverage: `test_wordlist_strategy.py` (bcrypt + md5 + ntlm + CamelCase split). **Accion: SHIP v0.2.0 sin cambios.** Skill ya lo invoca en `learning-prompts.md` § Hash Policy PASO 1.

### `state_inspector.py` (sub-bloque C)

**Purpose.** CLI de consulta sobre los 3 arrays nuevos en `last-cycle.json.data.machines.<slug>`: `tried_credentials[]`, `tried_endpoints[]`, `tried_hashes[]`. Comandos: `summary`, `list-{credentials,endpoints,hashes}`, `check-{credential,hash,endpoint}`. Exit codes 0=found/tried, 1=not-found/not-tried, 2=error. Disenado para que el skill consulte ANTES de cualquier cred test / hash crack / endpoint enum y haga append post-accion. Backward compatible (campos opcionales — sesiones viejas siguen funcionando). Test coverage: `test_state_inspector.py` + fixture `tests/fixtures/state/last-cycle-with-history.json`. **Accion: SHIP v0.2.0 sin cambios.** Skill ya lo invoca en `p3-delegate-pentest.md` PASO 0 (pre-exploit) y PASO 6 (pre-hash crack), `state-schema.md` lo documenta como helper canonico.

### `stuck_detector.py` (sub-bloque G)

**Purpose.** Lee los 3 artifacts del engagement (`estado.md`, `findings.md`, `sessions.jsonl`) y emite 4 senales: `shell_lost` (regex en EN+ES), `hash_stuck` (patterns + `hash_policy_triggered` sin resolution post), `cred_exhausted` (>=3 auth_failed o keywords EN+ES), `progress_stalled` (mtime de artifacts > 30 min). Cada senal mapea a una recomendacion: `reset_listener` / `escalate_gpu` / `switch_vector` / `continue`. Extrae `alternatives_from_findings` (winrm-lateral, smb-exploit, ad-abuse, database-exposed, docker-escape) buscando puertos/servicios en findings.md. **Es el trigger del auto-pivot paralelo del skill.** Test coverage: `test_stuck_detector.py`. Validado en sesion real (CHANGELOG cita MonitorsFour S3). **Accion: SHIP v0.2.0 sin cambios.** Skill ya lo invoca en H3 gate y en budget check de `p3-delegate-pentest.md` PASO 4.5.

### `crack_status.py` (sub-bloque D)

**Purpose.** Companion de `crack-helper.sh --async` (que ya esta en `scripts/` segun CHANGELOG, vive en repo principal). Lee `<jobs_dir>/<job_id>.json` (state, escrito por crack-helper) + `<jobs_dir>/<job_id>.result.json` (escrito por la notebook Colab/Kaggle al terminar). Calcula edad vs `timeout_hours` y retorna uno de 6 status: `complete` (exit 0), `no_match` (1), `pending_upload`/`pending_crack` (2), `expired` (3), `error` (4). Permite al skill saber "el crack que lance ayer, como va?" sin re-trabajar. Test coverage: `test_crack_status.py` cubre los 6 status. **Accion: SHIP v0.2.0 sin cambios.** Skill ya lo invoca en `learning-prompts.md` § Hash Policy opcion `[p]` (poll job anterior).

### `parallel_explorer.py` (sub-bloque F)

**Purpose.** Habilita paralelismo en el auto-pivot del skill: cuando `stuck_detector` retorna `switch_vector` Y el budget vencio Y hay `alternative_chains` >= 1 → en lugar de elegir uno serial, lanza N tasks en paralelo (winrm-spray + smb-enum + endpoint-fuzz, p.ej.) via thread pool (default 4) sobre SSH-to-Kali. Cada task: `{id, cmd, timeout}`. Captura stdout/stderr tails (4KB) y consolida en JSON. `--dry-run` ejecuta `bash -c` local para CI sin Kali. Test coverage: `test_parallel_explorer.py` con skip en Windows local (CI ubuntu corre OK). **Accion: SHIP v0.2.0 sin cambios.** Skill ya lo invoca en `p3-delegate-pentest.md` PASO 4.5 (Auto-pivot paralelo).

---

## 4. Wire-up status — skill `/kestrel`

| Script | Phase que lo invoca | Linea | Estado wire-up |
|---|---|---|---|
| `blind_fingerprint.py` | `p1.5-intel-recon.md` (blind mode) | — | OK (v0.1) |
| `resume_validator.py` | `p0-welcome.md` (resume proactivo) | — | OK (v0.1) |
| `wordlist_strategy.py` | `phases/shared/learning-prompts.md` § Hash Policy PASO 1 | L217-225 | **Wire-up OK, repo desincronizado** |
| `crack_status.py` | `phases/shared/learning-prompts.md` § Hash Policy `[p]` poll | L245, L264-266 | **Wire-up OK, repo desincronizado** |
| `state_inspector.py` | `p3-delegate-pentest.md` PASO 0 (cross-session dedup) + PASO 6 (pre-hash) | L38-46, L232-248 | **Wire-up OK, repo desincronizado** |
| `state_inspector.py` | `phases/shared/state-schema.md` (helper canonico) | L214 | **Documentado, repo desincronizado** |
| `stuck_detector.py` | `p3-delegate-pentest.md` Stuck gate H3 + budget check | L295-296, L317, L357 | **Wire-up OK, repo desincronizado** |
| `stuck_detector.py` | `phases/shared/learning-prompts.md` § H3 | L118-122 | **Wire-up OK, repo desincronizado** |
| `parallel_explorer.py` | `p3-delegate-pentest.md` PASO 4.5 (auto-pivot paralelo) | L377-379, L410 | **Wire-up OK, repo desincronizado** |

**Conclusion del wire-up.** El skill **ya consume las 5 APIs de v0.2** invocando `python3 sectors/red-team/htb-framework-public/scripts/<X>.py`. Como los scripts viven en el monorepo CobaltoSec antes de propagarse al repo publico, el skill funciona localmente. **Pero el repo publico `github.com/CobaltoSec/kestrel` esta en v0.1.0** — un usuario externo que clone el repo NO tiene estos scripts. Validar + tagear v0.2.0 cierra esa brecha.

---

## 5. Roadmap v0.2.x / v0.3

### Bloque siguiente — `RT-KESTREL-V02` (validate + publish)

**Sub-tareas ordenadas:**

1. **V02-1 · Sync repo publico.** Confirmar que los 5 scripts + 6 test modules + fixtures + `requirements.txt` + `CHANGELOG.md` Unreleased section estan en `htb-framework-public/.git` working tree (no solo en el monorepo). Si falta algo, `git add` en el repo de Kestrel.
2. **V02-2 · CI pytest job.** Editar `.github/workflows/test.yml` para agregar job `test:` con `pip install pytest` + `pytest tests/`. Mantener job `lint:` existente. Verificar que pasa en `ubuntu-latest`.
3. **V02-3 · Validacion E2E real.** Correr MonitorsFour S4 (HTB) end-to-end con el skill, ejercitando los 5 scripts: wordlist_strategy → crack async → crack_status poll → state_inspector pre-cred → stuck_detector → parallel_explorer auto-pivot. Documentar la sesion en `sectors/red-team/htb-sessions/htb-2026-MM-DD-monitorsfour-s4/`.
4. **V02-4 · Update docs.** Anadir seccion v0.2 a `docs/architecture.md` (attack_plan multi-path, async flow, stuck loop). Anadir un nuevo doc `docs/scripts-catalog.md` con una pagina por script (cli reference + JSON shape).
5. **V02-5 · CHANGELOG close.** Mover bloque Unreleased a `## [0.2.0] — YYYY-MM-DD` con la fecha real. Agregar case study de MonitorsFour S4 si la validacion paso.
6. **V02-6 · Tag + Release.** `git tag v0.2.0`, push, crear GitHub Release con notas tomadas del CHANGELOG.
7. **V02-7 · Update CLAUDE.md.** Anadir bullet de v0.2.0 con scripts y link al release, similar a la bullet de Kestrel v0.1.1 / Merlin v0.2.0.

### Bloque mas adelante — `RT-KESTREL-V03` (post-publish features nuevas)

Lo que estos scripts **habilitan** y todavia falta en el skill:

- **V03-A · Auto-pivot deeper.** Hoy `parallel_explorer.py` corre tasks pre-definidos por el caller. v0.3 podria leer `attack_plan.parallel_tracks` directamente y emitir el task spec auto-construido. Reduce HITL.
- **V03-B · Cross-session learning aggregator.** Anadir `scripts/cross_session_learner.py` que mire los `tried_*[]` de todas las machines y emita un report agregado: "passwords mas reutilizados", "endpoints comunes que dan 200", "wordlists que historicamente rinden por OS/dificultad". Memory L4 expansion.
- **V03-C · Hash policy auto-decision.** Hoy el HITL Hash Policy es manual `[g/w/s/p]`. Con datos de `crack_status` + `wordlist_strategy.estimated_time_minutes` se puede decidir automaticamente cuando ir async. Subir autonomy nivel.
- **V03-D · `attack_plan.alternative_chains` enrichment.** El campo existe (v0.2 sub-bloque E) pero `blind_fingerprint.py` lo emite con cierta probabilidad nominal. v0.3 podria poblarlo con datos historicos de KB RAG (chain X funciono N/M veces en target categoria Y).
- **V03-E · Active-machine intel safe-search.** Hoy blind mode es 100% port-based. v0.3 podria leer **comentarios genericos en HTB forums** sin spoiler (TOS-aware) para enriquecer attack_plan sin violar reglas.
- **V03-F · Cleanup integral.** Skill ya tiene p6-cleanup pero no esta wired con el ledger v2 de pentest-cleanup. v0.3 — sumar al ledger HTB en el mismo gate.

**Prioridad sugerida v0.3:** V03-A (parallel auto-spec) > V03-C (hash policy autonomy) > V03-D (chains enrichment). V03-B y V03-E son blueprints, no hay que apurarlos.

---

## 6. Review del `CHANGELOG.md` draft

**Estado actual:** seccion `## [Unreleased]` con sub-bloques A-G correctamente atribuidos. Estructura Keep a Changelog OK.

**Observaciones:**

- **Bien:** describe purpose de cada sub-bloque + filename + comportamiento clave. Util para review.
- **Bien:** indica explicitamente que v0.2 NO esta wired en el skill (corregir esto: SI esta wired desde el monorepo — ver seccion 4 de este doc). La nota refleja una realidad anterior; reescribir asi: *"v0.2 modules are wired into the skill phases (`p3-delegate-pentest.md`, `learning-prompts.md`, `state-schema.md`) but the public repo tag is v0.1.0 until KESTREL-V02-PUBLISH ships."*
- **Falta:** seccion `### Changed` con el cambio de `attack_categories` semantics (ahora coexiste con `attack_plan`).
- **Falta:** seccion `### Fixed` con la limpieza de `attempts_failed_in_phase` (declarado pero nunca implementado — `state-schema.md` L289-291 lo confirma).
- **Falta:** mencionar `requirements.txt` sigue siendo Python stdlib only (todos los nuevos scripts respetan eso — bueno mantenerlo asi).
- **Sugerencia menor:** cuando se cierre la fecha, mover los case studies de Kobold/Garfield a una seccion `[0.1.0]` separada o un `docs/case-studies.md` (van a crecer y van a ensuciar el changelog).

---

## 7. CI workflow review (`.github/workflows/test.yml`)

**Estado:** un solo job `lint:` que corre `ruff check scripts/`.

**Problemas:**

- **No corre pytest.** Hay 6 test modules y 58+ tests pero CI no los ejecuta. Esto significa que un PR podria romper logica sin que CI lo detecte.
- **No testea con varias versiones de Python.** El requirements menciona "Python 3.10+" — el CI fija `3.10`. Bueno agregar matrix con 3.10/3.11/3.12.
- **No corre lint sobre `tests/`** — agregar `tests/` al ruff check.

**Propuesta de `test.yml` para v0.2:**

```yaml
name: CI
on:
  push: {branches: [main, develop]}
  pull_request: {branches: [main]}

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.10"}
      - run: pip install ruff
      - run: ruff check scripts/ tests/

  test:
    runs-on: ubuntu-latest
    strategy:
      matrix: {python-version: ["3.10", "3.11", "3.12"]}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "${{ matrix.python-version }}"}
      - run: pip install pytest
      - run: pytest tests/ -v
```

Este es deliverable V02-2 del bloque proximo.

---

## 8. Decisiones pendientes (HITL requerido antes de mergear v0.2)

1. **Validacion E2E real obligatoria?** El CHANGELOG dice "gated by a real test run against MonitorsFour S4". Confirmar: bloqueamos el release publico hasta haber corrido la maquina, o aceptamos ship con tests sinteticos + validacion S3 ya existente?
   - **Recomendacion:** correr S4. La ventana de inversion (~1 sesion HTB) vs el riesgo de shipear logica de auto-pivot no probada en E2E real esta a favor de validar.

2. **`crack-helper.sh --async` vive en repo principal o se mueve al repo Kestrel?** El script existe en `scripts/crack-helper.sh` del monorepo CobaltoSec; `crack_status.py` (que es su companion) si esta en el repo Kestrel. Hay incongruencia.
   - **Recomendacion:** mover `crack-helper.sh` al repo Kestrel `scripts/` y agregarlo al CHANGELOG sub-bloque D como parte explicita del shipping. Test minimo: `--help` runs clean.

3. **Notebook addendum Colab del sub-bloque D.** El CHANGELOG menciona "emits a notebook addendum to paste at the end of Colab cell 7". Falta saber si ese snippet esta versionado en algun archivo (sugerencia: `docs/colab-addendum.md` o `scripts/colab-snippet.py`). Sin eso, el flujo async no es reproducible por un externo.
   - **Recomendacion:** persistir el snippet en `docs/`.

4. **CONTRIBUTING.md menciona los nuevos scripts?** El doc esta del v0.1 y no enumera convenciones para anadir scripts (style, docstring, exit codes). Si el repo recibe contribuciones externas, debe.
   - **Recomendacion:** anadir seccion "Adding a new script" con el patron observado (argparse + JSON stdout + exit codes documentados + test module en `tests/`).

5. **`org-profile/` subdir esta dentro del repo Kestrel.** Tiene su propio `.git` — es un repo anidado. Por que esta dentro del repo publico? Genera confusion para el clone externo.
   - **Recomendacion:** mover `org-profile/` fuera del repo Kestrel o documentarlo en README. Esto NO es bloqueante para v0.2.0 pero hay que decidir.

6. **`develop` branch existe (ref local).** Hay una rama `develop` ademas de `main` y tag `v0.1.0`. Confirmar el branching model: gitflow (develop → main on release) o trunk + tags. Documentar en CONTRIBUTING.md.

---

## Anexo — Inventario completo de `scripts/`

```
scripts/
├── blind_fingerprint.py    [19786 bytes] shipped v0.1
├── crack_status.py         [ 5233 bytes] SHIP v0.2.0
├── parallel_explorer.py    [ 7048 bytes] SHIP v0.2.0
├── resume_validator.py     [ 3797 bytes] shipped v0.1
├── resume_validator.sh     [  659 bytes] shipped v0.1
├── state_inspector.py      [ 6800 bytes] SHIP v0.2.0
├── stuck_detector.py       [ 8715 bytes] SHIP v0.2.0
└── wordlist_strategy.py    [11747 bytes] SHIP v0.2.0
```

Tamano total v0.2 (nuevos): ~39 KB. Tests: ~30 KB en `tests/`.
Python stdlib only — `requirements.txt` no necesita updates.

---

*Fin del triage. Aprobacion HITL Nico requerida sobre decisiones 1-6 antes de arrancar `RT-KESTREL-V02`.*
