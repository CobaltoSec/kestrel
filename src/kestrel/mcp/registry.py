"""Central registry for Kestrel MCP tools, prompts, and resources.

Tool modules import the decorators here and register their callables. The
registry is collected at import time and bound to the ``mcp.server.Server``
inside ``kestrel.mcp.server.build_server()``.

Why a custom registry on top of MCP SDK decorators:
- SDK decorators (``server.call_tool()``, ``server.list_tools()``) require a
  bound Server instance. We want tool *definitions* to live across the codebase
  in ``kestrel.mcp.tools.*`` independently of any server lifecycle.
- The registry collects (name, schema, handler) tuples that ``build_server()``
  iterates over to register with the SDK.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T", bound=Callable[..., Any])

ToolHandler = Callable[..., Awaitable[Any]]
PromptHandler = Callable[..., Awaitable[str]]
ResourceHandler = Callable[[str], Awaitable[str]]


@dataclass
class ToolSpec:
    """A registered tool spec ready to bind to mcp.server.Server."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler
    category: str = "misc"


@dataclass
class PromptSpec:
    """A registered prompt spec."""

    name: str
    description: str
    handler: PromptHandler
    arguments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ResourceSpec:
    """A registered resource (read-only URI)."""

    uri: str
    name: str
    description: str
    mime_type: str
    handler: ResourceHandler


# ── Global registries (collected at module import) ───────────────────────────

_tools: dict[str, ToolSpec] = {}
_prompts: dict[str, PromptSpec] = {}
_resources: dict[str, ResourceSpec] = {}


# ── Decorators ───────────────────────────────────────────────────────────────


def tool(
    name: str | None = None,
    description: str = "",
    input_schema: dict[str, Any] | None = None,
    category: str = "misc",
) -> Callable[[ToolHandler], ToolHandler]:
    """Register an async handler as an MCP tool.

    Example::

        @tool(name="state_read", description="Read current Kestrel state.")
        async def state_read(machine: str | None = None) -> dict:
            ...
    """

    def decorator(fn: ToolHandler) -> ToolHandler:
        tool_name = name or fn.__name__
        schema = input_schema or _infer_schema_from_signature(fn)
        _tools[tool_name] = ToolSpec(
            name=tool_name,
            description=description or (fn.__doc__ or "").strip().split("\n")[0],
            input_schema=schema,
            handler=fn,
            category=category,
        )
        return fn

    return decorator


def prompt(
    name: str | None = None,
    description: str = "",
    arguments: list[dict[str, Any]] | None = None,
) -> Callable[[PromptHandler], PromptHandler]:
    """Register an async handler as an MCP prompt (returns text string)."""

    def decorator(fn: PromptHandler) -> PromptHandler:
        prompt_name = name or fn.__name__
        _prompts[prompt_name] = PromptSpec(
            name=prompt_name,
            description=description or (fn.__doc__ or "").strip().split("\n")[0],
            handler=fn,
            arguments=arguments or [],
        )
        return fn

    return decorator


def resource(
    uri: str,
    name: str | None = None,
    description: str = "",
    mime_type: str = "application/json",
) -> Callable[[ResourceHandler], ResourceHandler]:
    """Register a read-only resource at a kestrel:// URI."""

    def decorator(fn: ResourceHandler) -> ResourceHandler:
        res_name = name or fn.__name__
        _resources[uri] = ResourceSpec(
            uri=uri,
            name=res_name,
            description=description or (fn.__doc__ or "").strip().split("\n")[0],
            mime_type=mime_type,
            handler=fn,
        )
        return fn

    return decorator


# ── Inspectors used by build_server ──────────────────────────────────────────


def all_tools() -> list[ToolSpec]:
    return list(_tools.values())


def all_prompts() -> list[PromptSpec]:
    return list(_prompts.values())


def all_resources() -> list[ResourceSpec]:
    return list(_resources.values())


def get_tool(name: str) -> ToolSpec | None:
    return _tools.get(name)


def get_prompt(name: str) -> PromptSpec | None:
    return _prompts.get(name)


def get_resource(uri: str) -> ResourceSpec | None:
    return _resources.get(uri)


def _reset_for_tests() -> None:
    """Clear registries — used in test setup/teardown."""
    _tools.clear()
    _prompts.clear()
    _resources.clear()


# ── Schema inference (best-effort, simple) ───────────────────────────────────


def _infer_schema_from_signature(fn: Callable[..., Any]) -> dict[str, Any]:
    """Build a JSON schema {type: object, properties: {...}, required: [...]} from fn signature.

    Maps Python type hints to JSON Schema types:
        str -> "string"
        int -> "integer"
        float -> "number"
        bool -> "boolean"
        list -> "array"
        dict -> "object"
        Optional[X] / X | None -> X with required=False
    """
    sig = inspect.signature(fn)
    properties: dict[str, dict[str, Any]] = {}
    required: list[str] = []

    type_map = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
    }

    for param_name, param in sig.parameters.items():
        if param_name in ("self", "cls", "context", "ctx"):
            continue
        annotation = param.annotation
        is_optional = False

        # Unwrap Optional[X] / X | None
        if hasattr(annotation, "__args__"):
            args = annotation.__args__
            non_none = [a for a in args if a is not type(None)]
            if len(non_none) == 1 and len(args) == 2:
                annotation = non_none[0]
                is_optional = True

        json_type = type_map.get(annotation, "string")
        prop: dict[str, Any] = {"type": json_type}

        if param.default is not inspect.Parameter.empty:
            if param.default is not None:
                prop["default"] = param.default
            is_optional = True

        properties[param_name] = prop
        if not is_optional:
            required.append(param_name)

    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


__all__ = [
    "PromptSpec",
    "ResourceSpec",
    "ToolSpec",
    "all_prompts",
    "all_resources",
    "all_tools",
    "get_prompt",
    "get_resource",
    "get_tool",
    "prompt",
    "resource",
    "tool",
]
