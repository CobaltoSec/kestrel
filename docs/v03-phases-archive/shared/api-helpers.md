# API Helpers — Invocaciones htb_cli.py

Snippets para invocar `htb_cli.py` desde phases. Todos corren en Windows (E16), no via SSH.
El token lo lee `api.py` de `~/.htb/token` (Windows: `C:\Users\nicol\.htb\token`).

## Listar machines

```bash
# Easy retired — todas
python3 sectors/red-team/htb/htb_cli.py list --difficulty Easy

# Windows only
python3 sectors/red-team/htb/htb_cli.py list --difficulty Easy --os Windows

# Todas las dificultades
python3 sectors/red-team/htb/htb_cli.py list
```

Salida: array JSON con campos `id`, `name`, `os`, `difficulty`, `points`, `rating`, `authUserInUserOwns`, `authUserInRootOwns`.

Para mostrar como tabla, filtrar en Python:
```python
import json, subprocess
out = subprocess.check_output(["python3", "sectors/red-team/htb/htb_cli.py", "list", "--difficulty", "Easy"])
machines = json.loads(out)
# Filtrar no ownadas
unowned = [m for m in machines if not m.get("authUserInUserOwns") and not m.get("authUserInRootOwns")]
```

## Ver perfil

```bash
python3 sectors/red-team/htb/htb_cli.py profile
```

Salida: dict con `id`, `name`, `rank`, `points`, `user_owns`, `system_owns`, `ranking`, `respects`.

## Ver machine activa

```bash
python3 sectors/red-team/htb/htb_cli.py active
# Devuelve {} si no hay activa
```

## Spawn machine

```bash
python3 sectors/red-team/htb/htb_cli.py spawn <MACHINE_ID>
# Ejemplo: python3 sectors/red-team/htb/htb_cli.py spawn 1
```

Salida: dict con IP asignada (campo `ip` o `assigned_ip` — verificar respuesta real de API post-spawn).

## Release machine

```bash
python3 sectors/red-team/htb/htb_cli.py release <MACHINE_ID>
# Ejemplo: python3 sectors/red-team/htb/htb_cli.py release 1
```

## Submit flag

```bash
python3 sectors/red-team/htb/htb_cli.py submit <MACHINE_ID> <FLAG>
# Ejemplo: python3 sectors/red-team/htb/htb_cli.py submit 1 "abc123def456..."
# Con dificultad custom (10-100, default 50):
python3 sectors/red-team/htb/htb_cli.py submit 1 "abc123..." --difficulty 30
```

Salida en caso de éxito: `{"success": true, ...}` o similar — verificar respuesta real.

## VPN lifecycle (via htb-vpn.sh — corre en Kali via SSH)

```bash
bash scripts/htb-vpn.sh up       # Levanta VPN en Kali, espera tun0
bash scripts/htb-vpn.sh status   # Muestra IP tun0 + ping gateway
bash scripts/htb-vpn.sh down     # Baja VPN, limpia rutas
bash scripts/htb-vpn.sh cleanup  # Force-kill + limpiar residuos
```

## Verificar conectividad a target (ping desde Kali via SSH)

```bash
# Desde Windows, SSH a Kali para hacer ping a IP HTB (VPN está en Kali)
KALI_IP=$(bash scripts/kali-vm.sh ip)
ssh -i ~/.ssh/kali-pentest kali@$KALI_IP "ping -c 3 -W 2 <TARGET_IP>"
```

Si falla → VPN probablemente no está activa. Correr `bash scripts/htb-vpn.sh status` primero.

## Error handling en phases

Si `htb_cli.py` sale con código ≠ 0:
1. Mostrar el stderr al usuario.
2. Preguntar: ¿reintentar | abortar | continuar sin API?
3. Si es `AUTH ERROR`: recordar que el token está en `~/.htb/token` (Windows `C:\Users\nicol\.htb\token`).
4. Si es rate-limit (429): esperar 30s y reintentar una vez.
