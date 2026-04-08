"""Interactive headless REPL for Agent-G.

Provides a terminal-based reverse engineering interface with:
- Preset analysis modes (vuln hunting, describe, malware check)
- Direct access to all Ghidra tools
- Free-form AI-assisted queries
"""

import logging
import re
import sys
import traceback
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger("agent-g.repl")

# Maps direct tool shortcuts to (tool_name, param_extraction_regex)
DIRECT_TOOLS = {
    "list_functions":   ("list_functions",      r"(.*)"),
    "list_imports":     ("list_imports",         r"(.*)"),
    "list_exports":     ("list_exports",         r"(.*)"),
    "list_strings":     ("list_strings",         r"(.*)"),
    "list_segments":    ("list_segments",        r"(.*)"),
    "list_namespaces":  ("list_namespaces",      r"(.*)"),
    "decompile":        ("decompile_function",   r"(\S+)"),
    "decompile_at":     ("decompile_function_by_address", r"(\S+)"),
    "disassemble":      ("disassemble_function", r"(\S+)"),
    "xrefs_to":         ("get_xrefs_to",         r"(\S+)"),
    "xrefs_from":       ("get_xrefs_from",       r"(\S+)"),
    "get_function_at":  ("get_function_by_address", r"(\S+)"),
    "search_functions": ("search_functions_by_name", r"(.+)"),
    "read_bytes":       ("read_bytes",           r"(\S+)\s+(\d+)"),
}

# Preset queries: each maps to (label, task_name, opening_query)
# task_name selects the system prompt (vuln/malware/describe)
PRESET_QUERIES = {
    "1": (
        "Perform Vulnerability Analysis",
        "vuln",
        "Find specific exploitable vulnerabilities in this binary. "
        "Trace data flow from external inputs to sensitive sinks. "
        "Provide concrete addresses and decompiled evidence for each finding.",
    ),
    "2": (
        "Describe the Binary",
        "describe",
        "Describe what this binary does, its architecture, key subsystems, "
        "and primary data flow. Provide a structured technical overview.",
    ),
    "3": (
        "Determine if Malicious",
        "malware",
        "Determine if this binary is malicious. Extract IOCs, identify "
        "behavioral capabilities (injection, persistence, C2, anti-analysis), "
        "and provide a verdict with evidence.",
    ),
}


class HeadlessREPL:
    """Interactive terminal for headless binary analysis."""

    def __init__(self, bridge, config, binary_name: str = "unknown"):
        self.bridge = bridge
        self.config = config
        self.binary_name = binary_name
        self.console = Console()
        self._tool_executor = bridge.tool_executor if hasattr(bridge, 'tool_executor') else None

    def _print_banner(self):
        """Print the startup banner with quick-start options."""
        model = getattr(self.config, "ollama", None)
        model_name = getattr(model, "model", "unknown") if model else "unknown"

        banner = Text()
        banner.append(f"  Agent-G", style="bold cyan")
        banner.append(f" - {self.binary_name}\n", style="white")
        banner.append(f"  LLM: {model_name}", style="dim")

        self.console.print(Panel(banner, border_style="cyan", padding=(0, 2)))
        self.console.print()

        # Quick start options
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Key", style="bold yellow", width=4)
        table.add_column("Action", style="white")

        for key, (label, _) in PRESET_QUERIES.items():
            table.add_row(f"[{key}]", label)

        self.console.print("  [bold]Quick Start:[/bold]")
        self.console.print(table)
        self.console.print()

        # Tool shortcuts
        tools_text = ", ".join(sorted(DIRECT_TOOLS.keys()))
        self.console.print(f"  [dim]Tools: {tools_text}[/dim]")
        self.console.print(f"  [dim]Prefix with ! to skip AI interpretation (e.g., !list_imports)[/dim]")
        self.console.print(f"  [dim]Type 'help' for more info, 'exit' to quit[/dim]")
        self.console.print()

    def _print_help(self):
        """Print detailed help."""
        self.console.print("\n[bold]Agent-G Commands:[/bold]\n")
        self.console.print("  [yellow]1, 2, 3[/yellow]          Quick-start preset analyses")
        self.console.print("  [yellow]<tool> <args>[/yellow]    Run a Ghidra tool directly")
        self.console.print("  [yellow]!<tool> <args>[/yellow]   Run tool without AI interpretation")
        self.console.print("  [yellow]<free text>[/yellow]      Send query to AI orchestrator")
        self.console.print("  [yellow]help[/yellow]             Show this help")
        self.console.print("  [yellow]exit / quit[/yellow]      Exit Agent-G")
        self.console.print()

        self.console.print("[bold]Available Tools:[/bold]\n")
        table = Table(show_header=True, box=None, padding=(0, 2))
        table.add_column("Command", style="cyan")
        table.add_column("Ghidra Tool", style="dim")
        table.add_column("Example", style="green")

        examples = {
            "list_functions": "list_functions",
            "list_imports": "list_imports",
            "list_exports": "list_exports",
            "list_strings": "list_strings .exe",
            "decompile": "decompile main",
            "decompile_at": "decompile_at 0x00401000",
            "xrefs_to": "xrefs_to 0x00401000",
            "xrefs_from": "xrefs_from 0x00401000",
            "search_functions": "search_functions bad",
            "read_bytes": "read_bytes 0x00401000 64",
        }
        for shortcut, (tool_name, _) in DIRECT_TOOLS.items():
            ex = examples.get(shortcut, shortcut)
            table.add_row(shortcut, tool_name, ex)

        self.console.print(table)
        self.console.print()

    def _execute_direct_tool(self, user_input: str, skip_ai: bool = False) -> Optional[str]:
        """Try to execute a direct tool command. Returns result or None if not a tool."""
        # Strip ! prefix
        cmd_text = user_input.lstrip("!")

        # Match against known tool shortcuts
        for shortcut, (tool_name, param_pattern) in DIRECT_TOOLS.items():
            if cmd_text.startswith(shortcut):
                args_text = cmd_text[len(shortcut):].strip()
                params = {}

                # Parse arguments based on tool
                if tool_name in ("list_imports", "list_exports", "list_functions",
                                 "list_segments", "list_namespaces"):
                    # Optional offset/limit
                    parts = args_text.split() if args_text else []
                    if len(parts) >= 1:
                        try:
                            params["offset"] = int(parts[0])
                        except ValueError:
                            pass
                    if len(parts) >= 2:
                        try:
                            params["limit"] = int(parts[1])
                        except ValueError:
                            pass

                elif tool_name == "list_strings":
                    if args_text:
                        params["filter"] = args_text

                elif tool_name == "decompile_function":
                    if args_text:
                        params["name"] = args_text
                    else:
                        self.console.print("[red]Usage: decompile <function_name>[/red]")
                        return ""

                elif tool_name == "decompile_function_by_address":
                    if args_text:
                        params["address"] = args_text
                    else:
                        self.console.print("[red]Usage: decompile_at <address>[/red]")
                        return ""

                elif tool_name in ("get_xrefs_to", "get_xrefs_from",
                                   "disassemble_function", "get_function_by_address"):
                    if args_text:
                        params["address"] = args_text
                    else:
                        self.console.print(f"[red]Usage: {shortcut} <address>[/red]")
                        return ""

                elif tool_name == "search_functions_by_name":
                    if args_text:
                        params["query"] = args_text
                    else:
                        self.console.print("[red]Usage: search_functions <pattern>[/red]")
                        return ""

                elif tool_name == "read_bytes":
                    parts = args_text.split()
                    if len(parts) >= 2:
                        params["address"] = parts[0]
                        params["length"] = int(parts[1])
                    else:
                        self.console.print("[red]Usage: read_bytes <address> <length>[/red]")
                        return ""

                # Execute the tool
                try:
                    if self._tool_executor:
                        result = self._tool_executor.execute_command(tool_name, params)
                    else:
                        # Fallback: use ghidra_client directly
                        method = getattr(self.bridge.ghidra_client, tool_name, None)
                        if method:
                            result = method(**params)
                        else:
                            return f"Tool '{tool_name}' not found"
                except Exception as e:
                    return f"Tool error: {e}"

                result_str = str(result) if result else "(empty result)"

                # Print raw result
                self.console.print(f"\n[dim]--- {tool_name}({params}) ---[/dim]")
                self.console.print(result_str)

                # AI interpretation (unless skipped)
                if not skip_ai and result_str and result_str != "(empty result)":
                    self.console.print("\n[dim]AI Analysis:[/dim]")
                    try:
                        truncated = result_str[:3000]
                        query = (
                            f"The user ran the tool `{tool_name}({params})` on the "
                            f"binary '{self.binary_name}' and got this result:\n\n"
                            f"```\n{truncated}\n```\n\n"
                            f"Provide a brief analysis of what this tells us about "
                            f"the binary. Be concise (2-4 sentences)."
                        )
                        # Use simple LLM call, not orchestrator
                        ai_response = self.bridge.ollama.generate(query)
                        self.console.print(ai_response)
                    except Exception as e:
                        self.console.print(f"[dim](AI interpretation unavailable: {e})[/dim]")

                return result_str

        return None  # Not a tool command

    def run(self):
        """Main REPL loop."""
        self._print_banner()

        while True:
            try:
                user_input = input("\n> ").strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n[dim]Exiting...[/dim]")
                break

            if not user_input:
                continue

            # Exit commands
            if user_input.lower() in ("exit", "quit", "q"):
                self.console.print("[dim]Exiting Agent-G...[/dim]")
                break

            # Help
            if user_input.lower() == "help":
                self._print_help()
                continue

            # Preset queries (now task-aware)
            if user_input in PRESET_QUERIES:
                label, task_name, query = PRESET_QUERIES[user_input]
                self.console.print(f"\n[bold cyan]Running: {label}[/bold cyan]")
                self.console.print(f"[dim]Task mode: {task_name}[/dim]\n")
                try:
                    # Switch runtime to the appropriate task prompt
                    self.bridge.switch_task(task_name)
                    result = self.bridge.process_query(query, task=task_name)
                    self.console.print(result)
                except Exception as e:
                    self.console.print(f"[red]Error: {e}[/red]")
                    logger.exception("Preset query failed")
                continue

            # Direct tool (with optional ! prefix)
            skip_ai = user_input.startswith("!")
            tool_result = self._execute_direct_tool(user_input, skip_ai=skip_ai)
            if tool_result is not None:
                continue

            # Free-form query → use freeform task prompt
            self.console.print(f"\n[bold cyan]Investigating...[/bold cyan]\n")
            try:
                result = self.bridge.process_query(user_input, task="freeform")
                self.console.print(result)
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
                logger.exception("Query failed")
