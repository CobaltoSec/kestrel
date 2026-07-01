"""Bridge: MCP tool registry → Anthropic tool_use format.

Must be called after _load_handler_modules() has populated the registry.
"""

from __future__ import annotations

from typing import Any

# Tools that don't make sense headless or would cause infinite loops
_AGENT_EXCLUDED = frozenset({"request_user_confirmation"})


def load_tools_for_anthropic(
    exclude: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Return all registered MCP tools in Anthropic tool_use format.

    The 'type' field is not included — Anthropic infers it from the presence
    of 'input_schema'. request_user_confirmation is always excluded (the agent
    loop handles HITL natively via terminal input).
    """
    from kestrel.mcp import registry

    skip = _AGENT_EXCLUDED | (exclude or set())
    result: list[dict[str, Any]] = []
    for spec in registry.all_tools():
        if spec.name in skip:
            continue
        result.append(
            {
                "name": spec.name,
                "description": spec.description[:800],
                "input_schema": spec.input_schema,
            }
        )
    return result
