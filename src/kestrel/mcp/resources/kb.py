"""MCP resource — KB categories enum (from core.fingerprint RULES)."""

from __future__ import annotations

import json

from kestrel.core.fingerprint import RULES
from kestrel.mcp import registry


@registry.resource(
    uri="kestrel://kb/categories",
    name="kb-categories",
    description="Attack category catalog used by intel_classify_blind (category, description, tactics, kb_tags).",
)
async def kb_categories(uri: str) -> str:
    cats = [
        {
            "category": r["category"],
            "description": r["description"],
            "tactics": r["tactics"],
            "kb_tags": r["kb_tags"],
        }
        for r in RULES
    ]
    return json.dumps({"count": len(cats), "categories": cats}, indent=2, ensure_ascii=False)
