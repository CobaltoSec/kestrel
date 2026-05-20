"""intel_synthesis_template — template + rules for writing intel.md.

The LLM client uses this prompt as the contract for what an intel.md should contain.
It's served verbatim — no machine state interpolation needed.
"""

from __future__ import annotations

from kestrel.mcp import registry


INTEL_SYNTHESIS_BODY = """# Intel synthesis template

## Estructura obligatoria

```markdown
# Intel — {machine_name}

## Foothold (~120 palabras)
Vector probable + qué buscar en recon. Dirección, no comandos.

## Privesc (~100 palabras)
Camino probable post-foothold. Pista del kernel/binarios SUID/AD path.

## Gotchas
Cosas que rompen el flujo si no las sabés (timeouts, versiones, paths inusuales).

## Wordlists
Si aplica: qué wordlists priorizar y por qué.

## Sources
- https://0xdf.gitlab.io/...
- https://ippsec.rocks/...
- https://writeups.htb.com/...
```

## Reglas anti-spoiler (HARD)

✅ **Permitido:**
- Mencionar CVE-IDs ("CVE-2007-2447")
- Mencionar técnicas ("Samba username map script", "Kerberoast con GetUserSPNs")
- Mencionar herramientas ("usar MSF", "impacket-secretsdump", "evil-winrm")
- Mencionar tipos de hash ("bcrypt, requiere GPU")
- Mencionar versiones vulnerables ("Samba 3.0.20", "OpenSSH < 7.7")

❌ **Prohibido (spoiler):**
- Comandos copy-paste ejecutables exactos (`msfconsole -x "use exploit/X..."`)
- Payloads concretos (revshell strings, SQL injections completas)
- Credenciales hardcodeadas vistas en writeups
- Paths exactos de archivos sensibles ("/home/admin/.ssh/id_rsa")

## Confidence rating

Marcá al final del archivo:
- `confidence: high` — múltiples writeups consistentes, vector único claro
- `confidence: medium` — writeup parcial o ambiguo, varios posibles vectores
- `confidence: low` — info indirecta (release notes, foro posts)
- `confidence: none` — no se encontró nada → MODE=blind

## Modo guided vs blind

Si después de WebSearch + WebFetch tu intel.md tiene `confidence: high|medium` → MODE=guided
(saltás vuln scan genérico, vas dirigido al CVE).

Si `confidence: low|none` → MODE=blind (flow clásico p1-p5 sin shortcut).

## Persistencia

Una vez listo el intel.md, llamá:
```
intel_save_synthesis(
    machine="<slug>",
    content_md="<markdown completo>",
    confidence="high|medium|low|none",
    sources=["url1", "url2", ...],
)
```

Esto persiste a `<session_dir>/intel.md` Y actualiza `state.machines[slug].intel_*`.
"""


@registry.prompt(
    name="intel_synthesis_template",
    description="Template + anti-spoiler rules + confidence rating for writing machine intel.md.",
)
async def intel_synthesis_template() -> str:
    return INTEL_SYNTHESIS_BODY
