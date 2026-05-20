"""Phase-specific prompts (p0_setup..p5_close).

Each prompt is invoked when the LLM client calls `phase_enter(<phase>)` and
wants the templated guidance for that phase.
"""

from __future__ import annotations

from jinja2 import Template

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.mcp.tools.phase import PHASE_GUIDANCE


PHASE_TEMPLATE = """# Phase: {{ phase }}

**Objetivo:** {{ description }}

## Tools sugeridas

{% for t in suggested_tools %}- `{{ t }}`
{% endfor %}

## HITL gates obligatorios

{% if hitl_gates %}{% for g in hitl_gates %}- `{{ g }}` — pausar con `request_user_confirmation`
{% endfor %}{% else %}- _(sin gates HITL en esta fase — ejecutá directo y narrá)_
{% endif %}

## Reglas operativas

- Narración 4-streams obligatoria (📡🔍💡➡) vía `narrate_emit` para cada acción significativa.
- Persistir contexto a state via `state_write_machine` después de cada hito (target_ip, vector, foothold session, etc.).
- Si la fase tiene HITL gates → ejecutar `request_user_confirmation` ANTES de avanzar a la siguiente fase.
- En caso de stuck → llamar `stuck_check(machine=<slug>)` y aplicar la recomendación.

## Estado actual

- **Phase:** {{ current_phase or 'pre-entry' }}
- **Session:** {{ current_session or 'ninguna' }}
- **Machine activa:** {{ machine_summary }}

## Próximo paso

{{ next_step }}
"""


PHASE_NEXT_STEPS = {
    "p0_setup": "Elegí machine con `htb_list_machines` + `request_user_confirmation`. Después `htb_spawn` + `vpn_up` + `kali_ping_target`.",
    "p1_recon": "Arrancá con `recon_nmap_scan(profile='quick')` → luego `recon_web_fingerprint` / `recon_smb_enum` según puertos. Cerrá con `intel_classify_blind`.",
    "p2_vector": "Por cada categoría top de classify_blind → `intel_cve_lookup` + `vuln_msf_search`. Proponé 1-3 vectores ranked. `request_user_confirmation` para que Nico elija.",
    "p3_exploit": "Ejecutá el vector confirmado (`exploit_run_msf` o `exploit_*` específico). Si abre session → `state_write_machine(session_slug=...)`. Si stuck → `stuck_check` + alternativa.",
    "p4_privesc": "`post_enum_user` + `post_enum_system` primero. Si Linux con sudo NOPASSWD → `post_privesc_sudo`. Windows con SeImpersonate → `post_check_token` + `post_privesc_potato`.",
    "p5_close": "`flag_extract` para user+root → `htb_submit_flag` (HITL submit_confirm) → `writeup_generate` → `writeup_kb_synthesize` → cleanup (`vpn_down` + `htb_release` + `session_close`) → `request_user_confirmation` debrief.",
}


def _render_phase(phase: str) -> str:
    guidance = PHASE_GUIDANCE.get(phase)
    if guidance is None:
        return f"Unknown phase: {phase}"
    ctx = mcp_context.get_context()
    state = ctx.state_store.read()
    sess = state.data.current_session
    machine_summary = "ninguna"
    if sess:
        for slug, m in state.data.machines.items():
            if m.session_slug == sess:
                machine_summary = f"{slug} (ip={m.target_ip}, mode={m.htb_mode})"
                break
    tpl = Template(PHASE_TEMPLATE)
    return tpl.render(
        phase=phase,
        description=guidance["description"],
        suggested_tools=guidance["suggested_tools"],
        hitl_gates=guidance["hitl_gates"],
        current_phase=state.data.current_phase,
        current_session=sess,
        machine_summary=machine_summary,
        next_step=PHASE_NEXT_STEPS.get(phase, "_(sin guidance)_"),
    )


@registry.prompt(name="p0_setup", description="Phase p0_setup — machine pick + intel + spawn + ping.")
async def p0_setup() -> str:
    return _render_phase("p0_setup")


@registry.prompt(name="p1_recon", description="Phase p1_recon — nmap + service enum + classify.")
async def p1_recon() -> str:
    return _render_phase("p1_recon")


@registry.prompt(name="p2_vector", description="Phase p2_vector — propose ranked vectors + HITL confirm.")
async def p2_vector() -> str:
    return _render_phase("p2_vector")


@registry.prompt(name="p3_exploit", description="Phase p3_exploit — run confirmed vector, open session.")
async def p3_exploit() -> str:
    return _render_phase("p3_exploit")


@registry.prompt(name="p4_privesc", description="Phase p4_privesc — enum + escalate to root/SYSTEM.")
async def p4_privesc() -> str:
    return _render_phase("p4_privesc")


@registry.prompt(name="p5_close", description="Phase p5_close — flags + submit + writeup + cleanup + debrief.")
async def p5_close() -> str:
    return _render_phase("p5_close")
