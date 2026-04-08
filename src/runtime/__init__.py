"""Agent-G Runtime — CLAW Code-inspired ReAct loop for binary analysis.

This module replaces the OGhidra orchestrator/worker multi-tier architecture
with a single-loop ReAct runtime adapted from CLAW Code's design philosophy:

  * Append-only Session as the only state
  * Single LLM call per reasoning step (no separate planner/synthesizer)
  * Trait-based ApiClient and ToolExecutor for clean abstraction
  * Token-aware compaction for long investigations
  * Task-specific system prompts (vuln, malware, describe)
  * Bootstrap preamble pre-loads discovery data

Public API:
    from src.runtime import ConversationRuntime, Session, build_system_prompt
"""

from src.runtime.session import Session, Message, ContentBlock, MessageRole
from src.runtime.conversation import ConversationRuntime, TurnSummary
from src.runtime.prompts import (
    build_vuln_hunting_prompt,
    build_malware_hunting_prompt,
    build_binary_description_prompt,
    build_freeform_prompt,
)

__all__ = [
    "ConversationRuntime",
    "TurnSummary",
    "Session",
    "Message",
    "ContentBlock",
    "MessageRole",
    "build_vuln_hunting_prompt",
    "build_malware_hunting_prompt",
    "build_binary_description_prompt",
    "build_freeform_prompt",
]
