"""hint_generation — 1-line nudge prompt, anti-spoiler.

Triggered by `/kestrel hint` from the skill. The LLM should generate a single
sentence pointing Nico toward what to look at next, WITHOUT giving away the
answer.
"""

from __future__ import annotations

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry


HINT_BODY = """Estás generando un **hint** para /kestrel — una pista de 1 sola línea, anti-spoiler.

## Reglas

1. UNA LÍNEA. Máximo 25 palabras.
2. Apunta a un **área**, no a un comando. ("Mirá la versión del servicio en 445." NO "Corré usermap_script.")
3. Si Nico ya está cerca → confirmar dirección sin spoilear ("Vas bien, sigamos por SMB.")
4. Si está perdido → orientar a un área no explorada ("Probaste el puerto 8080?")
5. NUNCA mencionar CVE-ID exacto, nombres de exploit, o paths a archivos sensibles.
6. Si la sesión está en phase=p2_vector y ya hay un vector confirmado → sugerir ejecutar.
7. Si la sesión tiene `stuck_signals` → sugerir alternativa (sin spoiler).

## Estado actual

- **Phase:** {phase}
- **Machine:** {machine}
- **Session dir:** {session_dir}
- **Last narration line:** {last_narrate}

## Hint a generar

Producí UNA sola oración. Nada de listas, código, ni headers. Solo el texto del hint.
"""


def _last_narrate_line(session_dir: str | None) -> str:
    if not session_dir:
        return "(sin sesión activa)"
    from pathlib import Path
    estado = Path(session_dir) / "estado.md"
    if not estado.exists():
        return "(estado.md vacío)"
    lines = [ln for ln in estado.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
    return lines[-1] if lines else "(estado.md sin entradas)"


@registry.prompt(
    name="hint_generation",
    description="Generate a 1-line anti-spoiler hint for /kestrel hint. Provides phase + last narration as context.",
)
async def hint_generation() -> str:
    ctx = mcp_context.get_context()
    state = ctx.state_store.read()
    sess = state.data.current_session
    machine = "(ninguna)"
    session_dir_str = None
    if sess:
        for slug, m in state.data.machines.items():
            if m.session_slug == sess:
                machine = slug
                session_dir_str = str(ctx.session_root / sess)
                break
    return HINT_BODY.format(
        phase=state.data.current_phase or "(ninguna)",
        machine=machine,
        session_dir=session_dir_str or "(ninguna)",
        last_narrate=_last_narrate_line(session_dir_str),
    )
