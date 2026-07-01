# Phase p0 — Welcome / Dashboard

## Objetivo
Mostrar el estado actual de HTB (perfil + sesión activa) y presentar el menú de opciones.

---

## PASO 1 — Leer state

Leer `fleet/agents/htb/state/profile.json` y `fleet/agents/htb/state/last-cycle.json`.

Si alguno no existe → inicializar con valores default (run_count=0, todo null).

---

## PASO 2 — Dashboard

Mostrar:

```
╔══════════════════════════════════════════╗
║           HackTheBox — Cobalt0           ║
╠══════════════════════════════════════════╣
║  Rank:       <rank_text | "—">           ║
║  Points:     <points>                    ║
║  User owns:  <user_owns>                 ║
║  Root owns:  <system_owns>               ║
║  Runs:       <run_count>                 ║
╠══════════════════════════════════════════╣
║  Última sesión: <last_run | "ninguna">   ║
║  Máquina:       <última machine | "—">   ║
╚══════════════════════════════════════════╝
```

Si `updated_at` en `profile.json` es null o tiene más de 24h → agregar nota: "[perfil no actualizado — se actualizará al completar la próxima sesión]".

---

## PASO 3 — Detectar sesión activa + validar estado

Buscar directorios en `sectors/red-team/htb-sessions/` que NO sean `_template` y cuyo `roe.md` tenga `finished_at: null`.

Si hay sesión activa, **antes de ofrecer retomar**, correr validación proactiva:

### PASO 3a — Leer contexto de sesión paused

Leer `fleet/agents/htb/state/last-cycle.json` y extraer para la sesión encontrada:
- `last_machine_ip` — IP de la máquina
- `kali_listeners[]` — listeners registrados
- `next_step_hint` — qué había que hacer al retomar
- `last_phase_completed` — última fase completada

### PASO 3b — Invocar resume_validator.sh en Kali

```bash
KALI_IP=$(bash scripts/kali-vm.sh ip 2>/dev/null)
if [[ -n "$KALI_IP" ]]; then
    # Copiar script a Kali y ejecutar
    scp -i ~/.ssh/kali-pentest sectors/red-team/htb-framework-public/scripts/resume_validator.py kali@$KALI_IP:/tmp/
    VALIDATION=$(ssh -i ~/.ssh/kali-pentest kali@$KALI_IP \
        "MACHINE_IP='<last_machine_ip>' LISTENERS_JSON='<kali_listeners_JSON>' python3 /tmp/resume_validator.py")
else
    # Kali no disponible — skip validación, modo manual
    VALIDATION='{"vpn_up":null,"machine_reachable":null,"listeners_alive":[],"needs_recovery":null,"recovery_actions":[]}'
fi
```

### PASO 3c — Mostrar estado + menú

```
⚠ Sesión pausada encontrada: <SESSION_SLUG>
  Máquina:    <MACHINE_NAME> (<MACHINE_OS>, <MACHINE_DIFFICULTY>)
  Iniciada:   <started_at>
  Última fase: <last_phase_completed | current_phase>
  Próximo paso: <next_step_hint | "desconocido">

  Estado de infra:
  VPN tun0:      <✅ UP | ❌ DOWN | ❓ no verificado>
  Máquina IP:    <last_machine_ip> — <✅ alcanzable | ❌ unreachable/expirada | ❓>
  Listeners:
    :<PORT> (<TYPE>): <✅ alive (pid <PID>) | ❌ muerto>
    ...

  <Si needs_recovery=true>:
  ⚠ Acciones recomendadas: <recovery_actions narrados en español>

  [r] Retomar (<Si recovery: "con auto-recovery" | "listo">)
  [f] Fix manual antes de retomar
  [n] Nueva sesión (abandonar la activa)
  [q] Salir
```

**Si elige `r` con recovery_actions pendientes:**
Ejecutar auto-recovery ANTES de retomar:
- `revpn` → `bash scripts/kali-vm.sh wg-up && bash scripts/htb-vpn.sh up` + actualizar `vpn_iface_state` en state
- `respawn_machine` → `python3 sectors/red-team/htb/htb_cli.py spawn <id>` + pedir nueva IP + actualizar `last_machine_ip` en state
- `restart_listener_<PORT>` → SSH a Kali, relanzar el listener tipo correspondiente, actualizar PID en state

Narrar cada paso:
```
🔧 Auto-recovery:
   [1/N] Re-up VPN HTB... ✅
   [2/N] Respawn machine <NAME>... nueva IP: <NEW_IP> ✅
   [3/N] Restart listener :9001... PID <NEW_PID> ✅
➡ Todo ok. Retomando desde <last_phase_completed>.
```

Si elige `r` sin recovery → continuar directamente en la phase indicada con contexto de sesión recuperado.
Si elige `f` → mostrar comandos de fix manual + esperar confirmación.
Si elige `n` → confirmar: "¿Abandonar sesión <slug>? No se submiten flags pendientes. [s/n]". Si `s` → continuar.
Si elige `q` → terminar.

---

## PASO 4 — Menú principal (si no hay sesión activa)

```
¿Qué hacemos?

  [1] Nueva sesión — elegir máquina y arrancar
  [2] Ver perfil actualizado desde API
  [3] Ver historial de máquinas ownadas
  [q] Salir

```

- `[1]` → continuar a `p1-target-pick.md`
- `[2]` → ejecutar `python3 sectors/red-team/htb/htb_cli.py profile`, mostrar JSON formateado, volver al menú
- `[3]` → listar `machines_owned[]` de `profile.json` con fecha y tiempo, volver al menú
- `[q]` → terminar, mostrar "Próxima sesión: `/htb` para continuar"

---

## PASO 5 — Actualizar last-cycle

Actualizar `last-cycle.json`:
```json
{
  "data": {
    "current_phase": "p0-welcome"
  }
}
```

Continuar a `p1-target-pick.md` si el usuario eligió opción `[1]`.
