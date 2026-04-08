"""Tool runner — adapts the existing ToolExecutor for the runtime loop.

Inspired by CLAW Code's ``ToolExecutor`` trait. The runtime needs:
  - Execute a named tool with parameters
  - Get back a string result (or error)

This adapter wraps the existing ``src.tool_executor.ToolExecutor`` so the
runtime loop doesn't need to know about Ghidra-specific details.
"""

import logging
from typing import Any, Dict, Tuple

from src.command_parser import CommandParser

logger = logging.getLogger("agent-g.tool_runner")


# Per-tool result truncation budgets — keep large results manageable
_TOOL_RESULT_LIMITS = {
    # Decompile results: keep most of the function (vital for analysis)
    "decompile_function": 8000,
    "decompile_function_by_address": 8000,
    "disassemble_function": 6000,
    # XRefs and listings: medium budget
    "get_xrefs_to": 3000,
    "get_xrefs_from": 3000,
    "get_function_xrefs": 3000,
    # Discovery listings: smaller budget (paginated anyway)
    "list_imports": 4000,
    "list_exports": 4000,
    "list_strings": 4000,
    "list_functions": 4000,
    "list_segments": 2000,
    "list_namespaces": 2000,
    # Default for unknown tools
    "_default": 2000,
}


class ToolRunner:
    """Adapter that executes tools and returns truncated string results.

    The wrapped ToolExecutor handles all the Ghidra-specific logic (caching,
    coverage tracking, command normalization). This adapter only adds:
      - Result-to-string conversion
      - Per-tool truncation
      - Error handling that returns instead of raising
    """

    def __init__(self, tool_executor, command_parser: CommandParser):
        self.executor = tool_executor
        self.parser = command_parser

    def execute(self, tool_name: str, params: Dict[str, Any]) -> Tuple[str, bool]:
        """Execute a tool, return (result_string, is_error).

        Args:
            tool_name: Name of the tool (e.g., "decompile_function_by_address")
            params: Parameter dict (will be validated by ToolExecutor)

        Returns:
            (result_string, is_error_flag)
        """
        try:
            raw_result = self.executor.execute_command(tool_name, params)
            result_str = self._stringify(raw_result)
            truncated = self._truncate(tool_name, result_str)
            return truncated, False
        except ValueError as e:
            # Validation error — give the model the actionable error message
            return f"[ERROR] {e}", True
        except Exception as e:
            logger.exception("Tool execution failed: %s", tool_name)
            return f"[ERROR] {tool_name} failed: {e}", True

    @staticmethod
    def _stringify(result: Any) -> str:
        """Convert tool result to a string (handles list/dict/str/None)."""
        if result is None:
            return "(no result)"
        if isinstance(result, str):
            return result
        if isinstance(result, list):
            return "\n".join(str(item) for item in result)
        if isinstance(result, dict):
            return "\n".join(f"{k}: {v}" for k, v in result.items())
        return str(result)

    @staticmethod
    def _truncate(tool_name: str, text: str) -> str:
        """Truncate result based on per-tool budget."""
        limit = _TOOL_RESULT_LIMITS.get(tool_name, _TOOL_RESULT_LIMITS["_default"])
        if len(text) <= limit:
            return text
        return text[:limit] + f"\n... [truncated, {len(text) - limit} more chars]"
