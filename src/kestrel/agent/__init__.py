"""Public agent runner (ReAct loop + provider abstraction) — DEFERRED to v0.5.

In v0.4 the only supported client is Claude Code via MCP. For external use with own API key,
see the v0.5 roadmap in CHANGELOG.md.
"""


def run_agent(*args, **kwargs):
    raise NotImplementedError(
        "Public agent runner is deferred to v0.5. "
        "Use Claude Code with the kestrel MCP server in v0.4."
    )
