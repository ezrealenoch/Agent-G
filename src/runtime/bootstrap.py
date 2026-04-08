"""Discovery bootstrap — pre-loads imports/exports/strings into the session.

Inspired by CLAW Code's static prompt context (project files, git status).
For binary analysis, the equivalent is the binary's surface map: imports,
exports, and security-relevant strings. We run these tools deterministically
ONCE before the LLM starts, then inject the results as a synthetic message.

This saves the model from wasting reasoning steps on `list_imports` and
ensures every investigation starts with full surface awareness.
"""

import logging
from typing import Optional

from src.runtime.session import Session, Message, ContentBlock, MessageRole
from src.runtime.tool_runner import ToolRunner

logger = logging.getLogger("agent-g.bootstrap")


# String filters that capture security-relevant content
DEFAULT_STRING_FILTERS = [
    ".exe", ".dll", "http", "cmd", "service", "registry",
    "..", "Software\\\\", "/etc/", "/tmp/",
]


def run_discovery_bootstrap(
    tool_runner: ToolRunner,
    binary_name: str = "binary",
    string_filters: Optional[list] = None,
    max_imports: int = 100,
    max_exports: int = 100,
) -> str:
    """Run discovery tools deterministically, return a markdown summary.

    This summary is injected as a synthetic message at the start of the
    session so the model has full surface awareness from step 1.

    Returns: A markdown-formatted preamble describing the binary.
    """
    string_filters = string_filters or DEFAULT_STRING_FILTERS

    sections = [f"# Binary Discovery: {binary_name}\n"]

    # ── Program info ──
    program_section = _try_tool(
        tool_runner, "check_health", {},
        section_name="Program Info",
    )
    if program_section:
        sections.append(program_section)

    # ── Imports ──
    imports_text, _ = tool_runner.execute("list_imports", {"offset": 0, "limit": max_imports})
    if imports_text and "ERROR" not in imports_text:
        sections.append(f"## Imports\n```\n{imports_text}\n```\n")

    # ── Exports ──
    exports_text, _ = tool_runner.execute("list_exports", {"offset": 0, "limit": max_exports})
    if exports_text and "ERROR" not in exports_text:
        sections.append(f"## Exports\n```\n{exports_text}\n```\n")

    # ── Function count ──
    funcs_text, _ = tool_runner.execute("list_functions", {"offset": 0, "limit": 1})
    if funcs_text and "ERROR" not in funcs_text:
        # Just extract the total count line
        first_line = funcs_text.split("\n")[0]
        sections.append(f"## Functions\n{first_line}\n")

    # ── Security-relevant strings ──
    string_findings = []
    for filt in string_filters:
        result, is_err = tool_runner.execute("list_strings", {"filter": filt, "limit": 30})
        if not is_err and result and "[Total: 0]" not in result:
            string_findings.append(f"### Strings matching `{filt}`\n```\n{result}\n```\n")

    if string_findings:
        sections.append("## Security-Relevant Strings\n" + "\n".join(string_findings))
    else:
        sections.append("## Security-Relevant Strings\n_(no matches in default filters)_\n")

    # ── Segments ──
    segments_text, _ = tool_runner.execute("list_segments", {})
    if segments_text and "ERROR" not in segments_text:
        sections.append(f"## Memory Segments\n```\n{segments_text}\n```\n")

    return "\n".join(sections)


def install_bootstrap_in_session(
    session: Session,
    tool_runner: ToolRunner,
    binary_name: str = "binary",
) -> None:
    """Run discovery bootstrap and append it to the session as a user message.

    The model treats this as initial context: 'here is what I already know
    about the binary before you start investigating.'
    """
    logger.info("Running discovery bootstrap for %s", binary_name)
    discovery_text = run_discovery_bootstrap(tool_runner, binary_name=binary_name)

    preamble = (
        "I am about to investigate the following binary. The discovery phase "
        "has already been performed automatically. Here is the surface data:\n\n"
        f"{discovery_text}\n\n"
        "Use this data to plan your investigation. You do NOT need to call "
        "list_imports/list_exports/list_strings again unless you need different filters."
    )

    session.append(Message.user(preamble))
    logger.info("Bootstrap installed (%d chars)", len(preamble))


def _try_tool(tool_runner: ToolRunner, name: str, params: dict,
              section_name: str) -> Optional[str]:
    """Best-effort tool call; returns formatted section or None on failure."""
    try:
        result, is_err = tool_runner.execute(name, params)
        if is_err or not result:
            return None
        return f"## {section_name}\n{result}\n"
    except Exception as e:
        logger.debug("Bootstrap tool %s failed: %s", name, e)
        return None
