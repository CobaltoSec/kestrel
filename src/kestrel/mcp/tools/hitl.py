"""MCP tools — human-in-the-loop primitives.

``request_user_confirmation`` returns a structured marker that signals the
MCP client (Claude Code) to pause and present a question to the operator.
Since MCP tools can't natively block on user input, the contract is:

    1. LLM calls request_user_confirmation(question, options, context)
    2. Tool returns {"_hitl": true, "question": ..., "options": [...], ...}
    3. The LLM/client recognizes the _hitl marker and asks the operator
    4. The operator's answer comes back as the LLM's next prompt
"""

from __future__ import annotations

from typing import Any

from kestrel.mcp import registry


@registry.tool(
    name="request_user_confirmation",
    description=(
        "Request explicit operator confirmation via a HITL marker. The MCP client (Claude Code) "
        "should display the question + options and wait for the operator's answer. "
        "Use for critical gates: machine pick, vector confirm, exploit confirm, submit flag, debrief."
    ),
    category="hitl",
    input_schema={
        "type": "object",
        "properties": {
            "question": {"type": "string"},
            "options": {"type": "array", "items": {"type": "string"}},
            "context": {"type": "string"},
            "default_option": {"type": "string"},
        },
        "required": ["question"],
    },
)
async def request_user_confirmation(
    question: str,
    options: list[str] | None = None,
    context: str | None = None,
    default_option: str | None = None,
) -> dict[str, Any]:
    return {
        "_hitl": True,
        "question": question,
        "options": options or ["yes", "no"],
        "context": context,
        "default_option": default_option,
        "instruction_to_llm": (
            "Stop, present this question to the operator verbatim with the options listed, "
            "wait for their answer, then proceed only after receiving it. Do not auto-answer."
        ),
    }
