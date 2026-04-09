"""Tool-call schema validation.

Validates ``(name, params)`` tuples coming out of the LLM before they hit
``ToolRunner.execute()``. Without this, the tool runner happily dispatches
whatever the LLM emitted, and shape mistakes (wrong parameter name, off-by-
one limit, malformed address) surface as opaque Ghidra errors later.

This module defines the canonical schema for every tool Agent-G exposes
and a single ``validate_tool_call(name, params)`` function that returns
``(ok, normalized_params, error_message)``. The ConversationRuntime can
call it before dispatching; if ``ok`` is False it should feed the error
message back to the LLM as a tool result so the model can correct itself.

Scope
-----
  - Required vs optional parameters
  - Type coercion (LLM emits "10" for int, we coerce)
  - Range clamping (``limit > 100`` gets clamped to 100 with a warning)
  - Hex-address normalization (``"0x1234"`` → ``"00001234"``)
  - Unknown-tool detection
  - Unknown-param detection (strict mode)

Not in scope (yet)
------------------
  - Output schema validation — tool runners are trusted
  - Resource limit enforcement (covered by Budget)
  - Permission policies (covered by future ContentFilter framework)
"""
from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("agent-g.tool_schema")


# ── Coercers ──

def _coerce_int(v: Any, *, default: Optional[int] = None) -> Optional[int]:
    if v is None:
        return default
    if isinstance(v, bool):
        return default  # bool is a subtype of int; treat as invalid
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s.startswith("0x"):
            try:
                return int(s, 16)
            except ValueError:
                return default
        try:
            return int(s)
        except ValueError:
            return default
    return default


def _coerce_str(v: Any, *, default: str = "") -> str:
    if v is None:
        return default
    if isinstance(v, str):
        return v
    return str(v)


_ADDR_RE = re.compile(r"^(0x)?([0-9a-fA-F]+)$")


def _coerce_address(v: Any) -> Optional[str]:
    """Normalize an address to 8-hex-digit form without 0x prefix.

    Accepts "0x1234", "1234", "0x001012e0", "001012e0", etc. Returns
    None if the value can't be parsed as a hex address.
    """
    s = _coerce_str(v).strip()
    if not s:
        return None
    m = _ADDR_RE.match(s)
    if not m:
        return None
    hex_part = m.group(2)
    # Normalize to 8 hex digits; Ghidra-style addresses are typically 8
    if len(hex_part) < 8:
        hex_part = hex_part.rjust(8, "0")
    return hex_part.lower()


# ── Parameter spec ──

@dataclass
class Param:
    name: str
    kind: str  # "int" | "str" | "address" | "any"
    required: bool = False
    default: Any = None
    min: Optional[int] = None
    max: Optional[int] = None
    choices: Optional[List[Any]] = None
    description: str = ""

    def coerce(self, value: Any) -> Tuple[Any, Optional[str]]:
        """Coerce ``value`` to the declared type.

        Returns ``(normalized, error)`` where error is None on success.
        """
        if value is None:
            if self.required:
                return None, f"missing required param '{self.name}'"
            return self.default, None

        if self.kind == "int":
            c = _coerce_int(value, default=None)
            if c is None:
                return None, f"param '{self.name}' must be an integer (got {value!r})"
            if self.min is not None and c < self.min:
                return None, f"param '{self.name}'={c} below minimum {self.min}"
            if self.max is not None and c > self.max:
                # Clamp loudly rather than reject — mirrors GhidraMCPClient
                logger.warning("clamping %s from %d to %d", self.name, c, self.max)
                c = self.max
            return c, None

        if self.kind == "address":
            c = _coerce_address(value)
            if c is None:
                return None, f"param '{self.name}' must be a hex address (got {value!r})"
            return c, None

        if self.kind == "str":
            c = _coerce_str(value)
            if self.choices is not None and c not in self.choices:
                return None, f"param '{self.name}'={c!r} not in choices {self.choices}"
            return c, None

        # "any"
        return value, None


@dataclass
class ToolSpec:
    name: str
    description: str
    params: List[Param] = field(default_factory=list)
    strict: bool = True  # reject unknown params if True

    def validate(self, raw_params: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """Return ``(ok, normalized_params, error)``."""
        if not isinstance(raw_params, dict):
            return False, {}, f"params must be a dict, got {type(raw_params).__name__}"

        normalized: Dict[str, Any] = {}
        known_names = {p.name for p in self.params}

        # Known params
        for p in self.params:
            raw = raw_params.get(p.name)
            value, err = p.coerce(raw)
            if err:
                return False, {}, err
            if value is not None or p.required:
                normalized[p.name] = value

        # Unknown params (strict mode)
        if self.strict:
            extras = [k for k in raw_params.keys() if k not in known_names]
            if extras:
                return False, {}, (
                    f"unknown params for {self.name!r}: {extras} "
                    f"(known: {sorted(known_names)})"
                )

        return True, normalized, None


# ── Canonical tool registry ──

_TOOL_REGISTRY: Dict[str, ToolSpec] = {}


def register_tool(spec: ToolSpec) -> None:
    _TOOL_REGISTRY[spec.name] = spec


def known_tools() -> List[str]:
    return sorted(_TOOL_REGISTRY.keys())


def get_tool_spec(name: str) -> Optional[ToolSpec]:
    return _TOOL_REGISTRY.get(name)


def validate_tool_call(
    name: str,
    params: Dict[str, Any],
    *,
    strict_unknown_tool: bool = False,
) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    """Validate an LLM-emitted tool call.

    Returns ``(ok, normalized_params, error_message)``.

    By default, unknown tools are allowed to pass through (strict_unknown_tool=False)
    so this module can be layered onto existing tool runners without
    breaking third-party tools not listed here. Set strict_unknown_tool=True
    to reject anything not in the registry.
    """
    spec = _TOOL_REGISTRY.get(name)
    if spec is None:
        if strict_unknown_tool:
            return False, {}, f"unknown tool: {name!r}; known={known_tools()}"
        return True, dict(params or {}), None
    return spec.validate(params or {})


# ── Registered tools ──
# Only the high-value Ghidra tools that every investigation uses. Callers
# can register additional tools from their own code if they want strict
# validation for custom tools.

register_tool(ToolSpec(
    name="list_functions",
    description="Paginated list of functions in the analyzed binary.",
    params=[
        Param("limit", "int", default=20, min=1, max=200),
        Param("offset", "int", default=0, min=0),
        Param("filter", "str", required=False),
    ],
))

register_tool(ToolSpec(
    name="list_imports",
    description="List the binary's imported symbols.",
    params=[
        Param("limit", "int", default=20, min=1, max=200),
        Param("offset", "int", default=0, min=0),
        Param("filter", "str", required=False),
    ],
))

register_tool(ToolSpec(
    name="list_exports",
    description="List the binary's exported symbols.",
    params=[
        Param("limit", "int", default=20, min=1, max=200),
        Param("offset", "int", default=0, min=0),
        Param("filter", "str", required=False),
    ],
))

register_tool(ToolSpec(
    name="list_strings",
    description="Paginated list of strings in the binary's data sections.",
    params=[
        Param("limit", "int", default=20, min=1, max=200),
        Param("offset", "int", default=0, min=0),
        Param("filter", "str", required=False),
    ],
))

register_tool(ToolSpec(
    name="list_segments",
    description="List memory segments and their ranges.",
    params=[],
))

register_tool(ToolSpec(
    name="decompile_function_by_address",
    description="Decompile a function at the given address.",
    params=[
        Param("address", "address", required=True),
    ],
))

register_tool(ToolSpec(
    name="decompile_function",
    description="Decompile a function by symbol name.",
    params=[
        Param("name", "str", required=True),
    ],
))

register_tool(ToolSpec(
    name="disassemble_function",
    description="Raw disassembly of a function.",
    params=[
        Param("address", "address", required=True),
    ],
))

register_tool(ToolSpec(
    name="get_xrefs_to",
    description="Cross-references TO a given address.",
    params=[
        Param("address", "address", required=True),
    ],
))

register_tool(ToolSpec(
    name="get_xrefs_from",
    description="Cross-references FROM a given address.",
    params=[
        Param("address", "address", required=True),
    ],
))

register_tool(ToolSpec(
    name="read_bytes",
    description="Read raw bytes from memory at the given address.",
    params=[
        Param("address", "address", required=True),
        Param("length", "int", default=16, min=1, max=4096),
    ],
))

register_tool(ToolSpec(
    name="search_functions_by_name",
    description="Search for functions whose name matches a query.",
    params=[
        Param("query", "str", required=True),
        Param("limit", "int", default=20, min=1, max=100),
    ],
))


# ── Session management meta-tools (chat mode) ────────────────────

register_tool(ToolSpec(
    name="list_directory",
    description="List files and subdirectories at a path. Helps find binaries to analyze.",
    params=[
        Param("path", "str", required=False),
    ],
))

register_tool(ToolSpec(
    name="file_info",
    description="Get file size, type (PE/ELF/Mach-O), and modification date.",
    params=[
        Param("path", "str", required=True),
    ],
))

register_tool(ToolSpec(
    name="web_search",
    description="Search the web for security references, CVEs, or string analysis. Only use when the user asks.",
    params=[
        Param("query", "str", required=True),
        Param("max_results", "int", default=5, min=1, max=10),
    ],
))

register_tool(ToolSpec(
    name="load_binary",
    description="Load a new binary for analysis. Spins up a Ghidra instance and runs discovery.",
    params=[
        Param("path", "str", required=True),
        Param("name", "str", required=False),
    ],
))

register_tool(ToolSpec(
    name="switch_binary",
    description="Switch the active binary. All subsequent tool calls target this binary.",
    params=[
        Param("name", "str", required=True),
    ],
))

register_tool(ToolSpec(
    name="list_sessions",
    description="List all loaded binary sessions and which one is active.",
    params=[],
))


def tool_schema_document() -> Dict[str, Any]:
    """Produce a JSON-serializable schema document for meta-agent consumption.

    Shape is loosely Anthropic tool-use / OpenAI function-calling compatible.
    A meta-agent that embeds Agent-G can list these to know what tools are
    available without reading Python source.
    """
    out: List[Dict[str, Any]] = []
    for name in sorted(_TOOL_REGISTRY.keys()):
        spec = _TOOL_REGISTRY[name]
        props: Dict[str, Any] = {}
        required: List[str] = []
        for p in spec.params:
            t = "string"
            if p.kind == "int":
                t = "integer"
            elif p.kind == "address":
                t = "string"
            props[p.name] = {"type": t, "description": p.description or ""}
            if p.min is not None:
                props[p.name]["minimum"] = p.min
            if p.max is not None:
                props[p.name]["maximum"] = p.max
            if p.choices is not None:
                props[p.name]["enum"] = p.choices
            if p.required:
                required.append(p.name)
        out.append({
            "name": name,
            "description": spec.description,
            "input_schema": {
                "type": "object",
                "properties": props,
                "required": required,
            },
        })
    return {"tools": out, "count": len(out)}
