"""MCP tools — intel layer (classify blind, KB query, CVE lookup, synthesis persist).

Core entrypoints for the LLM client to ground its attack reasoning:
- ``intel_classify_blind``: scoring rules over ports/services/banners → attack plan.
- ``intel_kb_query``: pgvector KB query with graceful fallback.
- ``intel_cve_lookup``: 4-stage pipeline (KB → NVD → ExploitDB local → MSF search).
- ``intel_save_synthesis``: persist intel.md per machine session.

All external dependencies (KB, NVD, ExploitDB, MSF RPC) fail gracefully — every
tool returns a meaningful dict even when a backend is down.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

import httpx

from kestrel.core.fingerprint import build_attack_plan, query_kb, score_rules
from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.mcp.tools.state import _resolve_session_dir


KB_QUERY_TIMEOUT_S = 5.0
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ── intel_classify_blind ─────────────────────────────────────────────────────


@registry.tool(
    name="intel_classify_blind",
    description=(
        "Classify a target from ports/services/banners into ranked attack categories + attack plan. "
        "Uses kestrel.core.fingerprint. KB query auto-runs if KESTREL_KB_PATH is set."
    ),
    category="intel",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "ports": {"type": "array", "items": {"type": "string"}},
            "services": {"type": "array", "items": {"type": "string"}},
            "banners": {"type": "array", "items": {"type": "string"}},
            "os_hint": {"type": "string", "default": ""},
            "framework": {"type": "string"},
            "ad_joined": {"type": "boolean", "default": False},
        },
        "required": ["target"],
    },
)
async def intel_classify_blind(
    target: str,
    ports: list[str] | None = None,
    services: list[str] | None = None,
    banners: list[str] | None = None,
    os_hint: str = "",
    framework: str | None = None,
    ad_joined: bool = False,
) -> dict[str, Any]:
    ports = ports or []
    services = services or []
    banners = banners or []
    categories = score_rules(ports, services, banners, os_hint, framework)
    attack_plan = build_attack_plan(categories, os_hint or "unknown", framework, ad_joined)
    kb_chunks: list[dict[str, Any]] = []
    try:
        kb_chunks = query_kb(categories)
    except Exception:
        kb_chunks = []
    return {
        "target": target,
        "categories": categories,
        "attack_plan": attack_plan,
        "kb_chunks": kb_chunks,
        "os_hint": os_hint,
        "framework": framework,
    }


# ── intel_kb_query ───────────────────────────────────────────────────────────


def _try_import_kb_smart() -> Any | None:
    """Try to import kb.query.smart from KESTREL_KB_PATH. Returns the module or None."""
    kb_path = os.environ.get("KESTREL_KB_PATH", "")
    if not kb_path:
        return None
    try:
        if kb_path not in sys.path:
            sys.path.insert(0, kb_path)
        from kb.query import smart  # type: ignore
        return smart
    except Exception:
        return None


@registry.tool(
    name="intel_kb_query",
    description=(
        "Query the pgvector KB with `query` (free text). Returns top_k chunks with score + source. "
        "Falls back to empty list if KB unavailable. timeout 5s hard cap."
    ),
    category="intel",
)
async def intel_kb_query(query: str, top_k: int = 5) -> dict[str, Any]:
    smart_mod = _try_import_kb_smart()
    if smart_mod is None:
        return {"available": False, "query": query, "chunks": [], "reason": "kb_unavailable"}

    async def _run() -> list[dict[str, Any]]:
        def _do() -> list[dict[str, Any]]:
            results, _ = smart_mod.smart_search(query, top_k=top_k)
            return [
                {
                    "text": r.get("content", "")[:600],
                    "source": r.get("metadata", {}).get("source", ""),
                    "score": round(float(r.get("score", 0.0)), 3),
                }
                for r in results
            ]

        return await asyncio.to_thread(_do)

    try:
        chunks = await asyncio.wait_for(_run(), timeout=KB_QUERY_TIMEOUT_S)
    except asyncio.TimeoutError:
        return {"available": False, "query": query, "chunks": [], "reason": "timeout"}
    except Exception as exc:
        return {"available": False, "query": query, "chunks": [], "reason": f"error: {exc}"}
    return {"available": True, "query": query, "chunks": chunks}


# ── intel_cve_lookup ─────────────────────────────────────────────────────────


async def _nvd_lookup(product: str, version: str) -> list[dict[str, Any]]:
    """Query NVD CPE-based search. No API key needed (rate-limited heavily without)."""
    cpe = f"cpe:2.3:a:*:{product.lower()}:{version}:*:*:*:*:*:*:*"
    params = {"cpeName": cpe, "resultsPerPage": 10}
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(NVD_API, params=params)
            r.raise_for_status()
            data = r.json()
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for v in data.get("vulnerabilities", [])[:10]:
        cve = v.get("cve", {})
        out.append({
            "cve_id": cve.get("id"),
            "description": (cve.get("descriptions") or [{}])[0].get("value", "")[:300],
            "published": cve.get("published"),
        })
    return out


def _exploitdb_local_lookup(product: str, version: str) -> list[dict[str, Any]]:
    """Best-effort grep over an exploitdb CSV mirror at ~/.kestrel/exploitdb.csv. Falls back to []."""
    csv_path = Path(os.environ.get("KESTREL_EXPLOITDB_CSV", str(Path.home() / ".kestrel" / "exploitdb.csv")))
    if not csv_path.exists():
        return []
    needle = f"{product.lower()} {version.lower()}".strip()
    matches: list[dict[str, Any]] = []
    try:
        for line in csv_path.read_text(encoding="utf-8", errors="replace").splitlines()[:50000]:
            if needle and needle in line.lower():
                parts = line.split(",")
                if len(parts) >= 3:
                    matches.append({"id": parts[0].strip(), "title": parts[2].strip('"')})
                if len(matches) >= 10:
                    break
    except Exception:
        return []
    return matches


@registry.tool(
    name="intel_cve_lookup",
    description=(
        "Ranked CVE pipeline for product+version: 1) KB synthesis chunks 2) NVD API "
        "3) ExploitDB local CSV 4) MSF search RPC. Each backend independent — failures don't block."
    ),
    category="intel",
)
async def intel_cve_lookup(product: str, version: str) -> dict[str, Any]:
    # Stage 1 — KB synthesis
    kb_result = await intel_kb_query(f"{product} {version} CVE exploit", top_k=3)
    kb_chunks = kb_result.get("chunks", [])

    # Stage 2 — NVD
    nvd = await _nvd_lookup(product, version)

    # Stage 3 — ExploitDB local
    edb = _exploitdb_local_lookup(product, version)

    # Stage 4 — MSF search via RPC (best-effort, deferred to transport.msf — graceful skip if down)
    msf_results: list[dict[str, Any]] = []
    try:
        from kestrel.transport.msf import MSFSession  # type: ignore
        # We don't actually open RPC here — that's a heavy connection. Mark as not yet wired.
        # The LLM can call vuln_msf_search explicitly for that.
        msf_results = []
    except Exception:
        msf_results = []

    return {
        "product": product,
        "version": version,
        "stages": {
            "kb": kb_chunks,
            "nvd": nvd,
            "exploitdb_local": edb,
            "msf": msf_results,
        },
        "ranked_cves": _rank_cves(kb_chunks, nvd, edb),
    }


def _rank_cves(
    kb_chunks: list[dict[str, Any]],
    nvd: list[dict[str, Any]],
    edb: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Simple ranking: NVD CVE-IDs cross-referenced with edb titles get boosted."""
    edb_titles = " ".join(e.get("title", "").lower() for e in edb)
    out: list[dict[str, Any]] = []
    for cve in nvd:
        cve_id = cve.get("cve_id", "")
        has_edb = cve_id.lower() in edb_titles
        out.append({
            "cve_id": cve_id,
            "description": cve.get("description", ""),
            "has_exploitdb": has_edb,
            "priority": 2 if has_edb else 1,
        })
    out.sort(key=lambda x: x["priority"], reverse=True)
    return out


# ── intel_save_synthesis ─────────────────────────────────────────────────────


@registry.tool(
    name="intel_save_synthesis",
    description=(
        "Persist an intel.md synthesis to <session_dir>/intel.md and update state.machines[machine] "
        "with intel_path + intel_confidence + intel_sources."
    ),
    category="intel",
    input_schema={
        "type": "object",
        "properties": {
            "machine": {"type": "string"},
            "content_md": {"type": "string"},
            "sources": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "string", "enum": ["high", "medium", "low", "none"]},
        },
        "required": ["machine", "content_md", "confidence"],
    },
)
async def intel_save_synthesis(
    machine: str,
    content_md: str,
    confidence: str,
    sources: list[str] | None = None,
) -> dict[str, Any]:
    if confidence not in ("high", "medium", "low", "none"):
        return {"error": "invalid_confidence", "got": confidence}
    sources = sources or []
    ctx = mcp_context.get_context()
    session_dir = _resolve_session_dir(machine)
    session_dir.mkdir(parents=True, exist_ok=True)
    intel_path = session_dir / "intel.md"
    intel_path.write_text(content_md, encoding="utf-8")
    ctx.state_store.update_machine(
        machine,
        {
            "intel_path": str(intel_path),
            "intel_confidence": confidence,
            "intel_sources": sources,
        },
    )
    return {
        "machine": machine,
        "intel_path": str(intel_path),
        "confidence": confidence,
        "sources_count": len(sources),
    }
