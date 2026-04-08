"""ApiClient adapter — wraps existing LLM clients in a uniform interface.

Inspired by CLAW Code's `ApiClient` trait. The runtime only needs:
  - Send a list of messages + system prompt
  - Get back a text response (and optionally token usage)

This adapter wraps OllamaClient / ExternalClient / CustomAPIClient so the
ConversationRuntime stays decoupled from any specific LLM provider.
"""

import logging
from typing import List, Optional, Tuple

from src.runtime.session import Message, MessageRole, TokenUsage

logger = logging.getLogger("agent-g.api_client")


def messages_to_prompt(messages: List[Message]) -> str:
    """Render conversation history as a single prompt string.

    Most local LLMs (Ollama with text completion) don't support a structured
    messages array, so we serialize to a chat-style transcript with role labels.
    """
    parts = []
    for msg in messages:
        if msg.role == MessageRole.SYSTEM:
            continue  # System message handled separately

        role_label = {
            MessageRole.USER: "User",
            MessageRole.ASSISTANT: "Assistant",
            MessageRole.TOOL: "Tool",
        }[msg.role]

        if msg.role == MessageRole.TOOL:
            # Render tool result
            for block in msg.blocks:
                if block.block_type == "tool_result":
                    err = " (error)" if block.is_error else ""
                    parts.append(
                        f"Tool [{block.tool_name}]{err}:\n{block.tool_output}"
                    )
        else:
            # Render text + tool_use blocks (using EXECUTE: format)
            text_parts = []
            for block in msg.blocks:
                if block.block_type == "text" and block.text:
                    text_parts.append(block.text)
                elif block.block_type == "tool_use":
                    # Show what tool the assistant called
                    params_str = ", ".join(
                        f"{k}={v!r}" for k, v in (block.tool_input or {}).items()
                    )
                    text_parts.append(f"EXECUTE: {block.tool_name}({params_str})")
            if text_parts:
                parts.append(f"{role_label}: " + "\n".join(text_parts))

    return "\n\n".join(parts)


class ApiClient:
    """Adapter wrapping an existing LLM client (Ollama / External / Custom).

    Provides a single ``call(messages, system_prompt)`` method that returns
    ``(response_text, usage)``. The wrapped client is used as-is — no
    monkey-patching, no inheritance.
    """

    def __init__(self, llm_client, phase: str = "investigation"):
        self.llm = llm_client
        self.phase = phase

    def call(
        self,
        messages: List[Message],
        system_prompt: str,
        max_tokens: Optional[int] = None,
    ) -> Tuple[str, TokenUsage]:
        """Send messages + system prompt to the LLM, return (text, usage).

        Args:
            messages: Conversation transcript (excluding system).
            system_prompt: System instruction prefix.
            max_tokens: Optional cap on response length.

        Returns:
            (response_text, token_usage)
        """
        prompt = messages_to_prompt(messages)

        # Append a final cue so the LLM knows it's the assistant's turn
        if not prompt.endswith("Assistant:"):
            prompt += "\n\nAssistant:"

        try:
            # Use generate_with_phase if available (Ollama supports phase routing)
            if hasattr(self.llm, "generate_with_phase"):
                response = self.llm.generate_with_phase(
                    prompt,
                    phase=self.phase,
                    system_prompt=system_prompt,
                )
            else:
                response = self.llm.generate(
                    prompt,
                    system_prompt=system_prompt,
                    max_tokens=max_tokens,
                )
        except Exception as e:
            logger.exception("LLM call failed")
            return f"[LLM ERROR: {e}]", TokenUsage()

        # Estimate token usage (no exact tokenization for local models)
        usage = TokenUsage(
            input_tokens=_estimate_tokens(prompt) + _estimate_tokens(system_prompt),
            output_tokens=_estimate_tokens(response),
        )

        return response, usage


def _estimate_tokens(text: str) -> int:
    """Fast token estimate: ~4 chars per token (CLAW Code's heuristic)."""
    if not text:
        return 0
    return len(text) // 4 + 1
