"""Versioned system prompt library.

Every system prompt used by Agent-G lives here with a stable version
identifier. Callers look prompts up by ``(name, version)`` rather than
hard-coding strings. This lets the ``ResultStore`` key cache hits on
``prompt_version`` so a prompt change automatically invalidates the
cache without touching the store.

Design
------
  - Prompts are registered as ``Prompt`` dataclass instances at import time
  - Each prompt has a ``name`` (e.g. "vuln_hunt"), a ``version`` (e.g. "v1"),
    a ``template`` string, and a ``description``
  - A sha256 of the template is computed once and stored as ``hash`` — this
    is what gets logged to traces and provenance bundles
  - ``get_prompt(name, version)`` returns the Prompt; version defaults to
    "latest" which maps to whichever has the highest version string
  - ``render(name, version, **kwargs)`` returns the formatted text, substituting
    any ``{placeholder}`` tokens from kwargs
  - Adding a new version is a one-line addition at module bottom

To add a prompt::

    register_prompt(Prompt(
        name="vuln_hunt",
        version="v2",
        description="Tightened prompt that discourages over-flagging",
        template=\"\"\"You are a binary vulnerability analyst.
        ...\"\"\",
    ))

To use a prompt::

    from src.runtime.prompt_library import render_prompt
    text, version, prompt_hash = render_prompt("vuln_hunt", binary_name="sample.bin")
"""
from __future__ import annotations
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("agent-g.prompt_library")


@dataclass
class Prompt:
    name: str
    version: str
    description: str
    template: str
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(self.template.encode("utf-8")).hexdigest()

    def render(self, **kwargs) -> str:
        """Substitute ``{placeholder}`` tokens in the template.

        Missing kwargs fall back to their literal ``{name}`` form (via
        ``format_map`` with a default dict) rather than raising, so a
        partially-configured caller doesn't crash.
        """
        class _Default(dict):
            def __missing__(self, k):
                return "{" + k + "}"
        return self.template.format_map(_Default(kwargs))


# ── Registry ──────────────────────────────────────────────────────

# Two-level map: {name: {version: Prompt}}
_registry: Dict[str, Dict[str, Prompt]] = {}


def register_prompt(prompt: Prompt) -> None:
    """Register a new prompt version. Idempotent on identical content."""
    bucket = _registry.setdefault(prompt.name, {})
    if prompt.version in bucket:
        existing = bucket[prompt.version]
        if existing.hash != prompt.hash:
            logger.warning(
                "prompt '%s' version '%s' redefined with different content "
                "(old hash %s → new hash %s). Keeping the new one.",
                prompt.name, prompt.version,
                existing.hash[:12], prompt.hash[:12],
            )
    bucket[prompt.version] = prompt


def get_prompt(name: str, version: str = "latest") -> Prompt:
    """Look up a prompt by name and version.

    ``version="latest"`` returns the lexicographically greatest version
    string (which is correct for "v1" < "v2" < "v10" if you zero-pad;
    if you don't, then v1 < v10 < v2 — prefer explicit versions in
    production and reserve "latest" for REPL experimentation).
    """
    if name not in _registry:
        raise KeyError(f"prompt not registered: {name!r}")
    bucket = _registry[name]
    if version == "latest":
        if not bucket:
            raise KeyError(f"prompt {name!r} has no registered versions")
        latest_ver = sorted(bucket.keys())[-1]
        return bucket[latest_ver]
    if version not in bucket:
        known = sorted(bucket.keys())
        raise KeyError(
            f"prompt {name!r} has no version {version!r}; known versions: {known}"
        )
    return bucket[version]


def render_prompt(name: str, version: str = "latest", **kwargs) -> Tuple[str, str, str]:
    """Render a prompt, returning ``(text, version, hash)``.

    The caller should pass the returned ``version`` and ``hash`` to the
    ResultStore / ProvenanceBundle so the cached verdict is keyed on the
    exact prompt that produced it.
    """
    p = get_prompt(name, version)
    return p.render(**kwargs), p.version, p.hash


def list_prompts() -> List[Tuple[str, List[str]]]:
    """Return ``[(name, [versions, ...])]`` for every registered prompt."""
    return [(n, sorted(v.keys())) for n, v in sorted(_registry.items())]


# ── Built-in prompts ──────────────────────────────────────────────
# The two that Agent-G uses today: vuln_hunt (the Juliet-style task) and
# bootstrap_discovery (the initial discovery phase BridgeLite runs).
# Real deployments should add their own prompts and pin explicit versions.

register_prompt(Prompt(
    name="vuln_hunt",
    version="v1",
    description=(
        "Baseline vulnerability-hunting prompt: investigate a binary with "
        "Ghidra tools, trace data flow from inputs to dangerous sinks, "
        "produce a ## Verdict block."
    ),
    template="""You are a binary vulnerability analyst operating under the Agent-G runtime. \
Investigate the binary `{binary_name}` using the Ghidra HTTP tools available to you. \
Your goal is to decide whether the binary contains an exploitable flaw of class `{task_kind}`.

Approach:
  1. Enumerate imports, exports, and strings to orient yourself.
  2. Identify user-reachable input sources (network, file, argv, env).
  3. Trace each input source through any guards or sanitizers to the eventual sinks.
  4. When you find a concrete data-flow from taint source to dangerous sink with no \
     effective guard, document the finding with a specific address and decompiled evidence.

Tool usage:
  - Prefer `decompile_function_by_address` over `disassemble_function`.
  - Use `get_xrefs_to` / `get_xrefs_from` to chase call graphs.
  - Do NOT call `/health` — it returns `[redacted]` by design and wastes an iteration.

End your investigation with a block formatted exactly as:

  ## Verdict
  VULNERABLE | NOT_VULNERABLE

  ## Confirmed Findings
  - [severity] description — function / address — evidence

If you are uncertain after a reasonable investigation (10-20 tool calls), \
emit a verdict anyway and describe the residual uncertainty in the findings block. \
If you truly cannot commit, write `Verdict: UNKNOWN` with a one-sentence explanation.
""",
))


register_prompt(Prompt(
    name="bootstrap_discovery",
    version="v1",
    description=(
        "Initial discovery phase: runs a fixed battery of enumeration "
        "queries to populate the model's context with imports, exports, "
        "strings, and segments before the main reasoning loop starts."
    ),
    template="""Begin by discovering the structure of `{binary_name}`. \
Call the following endpoints in sequence and summarize what you find:

  - list_imports, list_exports
  - list_strings filtered on ('.exe', '.dll', 'http', 'cmd', 'service', \
'registry', 'Software\\\\', '/etc/', '/tmp/')
  - list_segments
  - list_functions (first page)

Produce a two-sentence orientation summary before proceeding to deeper analysis.
""",
))
