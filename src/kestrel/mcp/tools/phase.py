"""MCP tools — phase navigation (p0_setup ... p5_close).

Phase entry returns structured guidance (description + suggested tools + HITL gates)
so the LLM client knows what's appropriate at each step. The actual templated prompt
text lives in kestrel.mcp.prompts (Fase 7).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry


VALID_PHASES = ("p0_setup", "p1_recon", "p2_vector", "p3_exploit", "p4_privesc", "p5_close")


PHASE_GUIDANCE: dict[str, dict[str, Any]] = {
    "p0_setup": {
        "description": "Setup — pick target, gather intel (retired only), spawn machine, ping target.",
        "suggested_tools": [
            "htb_list_machines",
            "htb_machine_info",
            "intel_save_synthesis",
            "htb_spawn",
            "vpn_up",
            "kali_ping_target",
        ],
        "hitl_gates": ["machine_pick"],
    },
    "p1_recon": {
        "description": "Reconnaissance — nmap, web fingerprint, service enum, classify attack surface.",
        "suggested_tools": [
            "recon_nmap_scan",
            "recon_web_fingerprint",
            "recon_smb_enum",
            "recon_service_probe",
            "recon_dns_enum",
            "recon_ldap_enum",
            "intel_classify_blind",
            "stuck_check",
        ],
        "hitl_gates": [],
    },
    "p2_vector": {
        "description": "Vector decision — propose 1-3 ranked vectors via KB+CVE+MSF lookup, get user confirmation.",
        "suggested_tools": [
            "intel_cve_lookup",
            "intel_kb_query",
            "intel_next_step",
            "vuln_msf_search",
            "vuln_check_exploit_db",
            "stuck_check",
            "request_user_confirmation",
        ],
        "hitl_gates": ["vector_confirm"],
    },
    "p3_exploit": {
        "description": "Exploitation — run confirmed vector, get foothold. For SSH: creds_default_check → creds_themed_wordlist_gen → creds_ssh_bruteforce → session_open → session_exec. Stuck → back to p2.",
        "suggested_tools": [
            "creds_default_check",
            "creds_themed_wordlist_gen",
            "creds_ssh_bruteforce",
            "exploit_run_msf",
            "exploit_run_poc",
            "exploit_smb_psexec",
            "exploit_winrm",
            "exploit_web_lfi",
            "exploit_web_rce",
            "session_open",
            "session_exec",
            "stuck_check",
        ],
        "hitl_gates": ["destructive_action_confirm"],
    },
    "p4_privesc": {
        "description": "Privilege escalation — enum + escalate to root/SYSTEM. AD lateral if domain.",
        "suggested_tools": [
            "post_linpeas_run",
            "post_winpeas_run",
            "post_enum_user",
            "post_enum_system",
            "lolbin_suggest",
            "post_privesc_kernel",
            "post_privesc_sudo",
            "post_privesc_potato",
            "post_check_token",
            "ad_bloodhound_collect",
            "ad_kerberoast",
            "ad_dcsync",
            "stuck_check",
        ],
        "hitl_gates": ["destructive_action_confirm"],
    },
    "p5_close": {
        "description": "Close — extract flags, submit, write-up, KB synthesis, cleanup, debrief.",
        "suggested_tools": [
            "flag_extract",
            "flag_validate",
            "htb_submit_flag",
            "writeup_generate",
            "writeup_kb_synthesize",
            "writeup_publish_hint",
            "vpn_down",
            "htb_release",
            "session_close",
            "request_user_confirmation",
        ],
        "hitl_gates": ["submit_confirm", "debrief"],
    },
}


@registry.tool(
    name="phase_current",
    description="Get current phase + active session + machines that haven't been owned or abandoned.",
    category="phase",
)
async def phase_current() -> dict[str, Any]:
    ctx = mcp_context.get_context()
    state = ctx.state_store.read()
    return {
        "current_phase": state.data.current_phase,
        "current_session": state.data.current_session,
        "active_machines": [
            slug
            for slug, m in state.data.machines.items()
            if not m.abandoned and not (m.user_owned and m.root_owned)
        ],
    }


@registry.tool(
    name="phase_enter",
    description=(
        "Enter a phase (p0_setup, p1_recon, p2_vector, p3_exploit, p4_privesc, p5_close). "
        "Persists state.current_phase and returns the phase guidance (description, suggested tools, HITL gates). "
        "If machine is provided, also writes progress[phase] + last_phase_completed and emits a lifecycle event."
    ),
    category="phase",
    input_schema={
        "type": "object",
        "properties": {
            "phase": {"type": "string", "enum": list(("p0_setup", "p1_recon", "p2_vector", "p3_exploit", "p4_privesc", "p5_close"))},
            "machine": {
                "type": "string",
                "description": "Machine slug — if provided, tracks phase progress in machine state and emits a lifecycle event.",
            },
        },
        "required": ["phase"],
    },
)
async def phase_enter(phase: str, machine: str | None = None) -> dict[str, Any]:
    if phase not in VALID_PHASES:
        return {
            "error": "invalid_phase",
            "valid": list(VALID_PHASES),
            "got": phase,
        }
    ctx = mcp_context.get_context()
    ctx.state_store.set_current_phase(phase)

    # V08: write progress to machine state + emit lifecycle event
    if machine:
        try:
            m = ctx.state_store.get_machine(machine)
            progress = dict(m.progress) if m and m.progress else {}
            progress[phase] = datetime.now(timezone.utc).isoformat()
            ctx.state_store.update_machine(machine, {
                "progress": progress,
                "last_phase_completed": phase,
            })
            from kestrel.mcp.tools.state import _resolve_session_dir
            session_dir = _resolve_session_dir(machine)
            ctx.state_store.append_session_event(session_dir, phase=phase, event="phase_enter")
        except Exception:
            pass

    guidance = PHASE_GUIDANCE[phase]
    return {
        "phase": phase,
        **guidance,
    }
