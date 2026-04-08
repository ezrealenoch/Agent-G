"""Append-only conversation session — the only state in the runtime.

Inspired by CLAW Code's session.rs:
  - Messages are immutable, written once
  - Tagged ContentBlock enum prevents invalid states
  - Token usage tracked per-message for accurate budgeting
  - JSON-serializable for persistence and replay
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any


class MessageRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class ContentBlock:
    """Tagged content block — exactly one of: text, tool_use, tool_result."""
    block_type: str  # "text" | "tool_use" | "tool_result"

    # text block
    text: Optional[str] = None

    # tool_use block
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    tool_use_id: Optional[str] = None

    # tool_result block
    tool_output: Optional[str] = None
    is_error: bool = False

    @classmethod
    def text_block(cls, text: str) -> "ContentBlock":
        return cls(block_type="text", text=text)

    @classmethod
    def tool_use_block(cls, name: str, input_data: Dict[str, Any],
                        use_id: Optional[str] = None) -> "ContentBlock":
        return cls(
            block_type="tool_use",
            tool_name=name,
            tool_input=input_data,
            tool_use_id=use_id or f"tool_{datetime.now().strftime('%H%M%S%f')}",
        )

    @classmethod
    def tool_result_block(cls, name: str, output: str,
                          use_id: Optional[str] = None,
                          is_error: bool = False) -> "ContentBlock":
        return cls(
            block_type="tool_result",
            tool_name=name,
            tool_use_id=use_id,
            tool_output=output,
            is_error=is_error,
        )

    def to_dict(self) -> Dict[str, Any]:
        d = {"type": self.block_type}
        if self.text is not None:
            d["text"] = self.text
        if self.tool_name is not None:
            d["tool_name"] = self.tool_name
        if self.tool_input is not None:
            d["tool_input"] = self.tool_input
        if self.tool_use_id is not None:
            d["tool_use_id"] = self.tool_use_id
        if self.tool_output is not None:
            d["tool_output"] = self.tool_output
        if self.is_error:
            d["is_error"] = True
        return d


@dataclass
class TokenUsage:
    """Per-message token accounting."""
    input_tokens: int = 0
    output_tokens: int = 0

    def add(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
        )


@dataclass
class Message:
    """Single message in the conversation transcript."""
    role: MessageRole
    blocks: List[ContentBlock] = field(default_factory=list)
    usage: Optional[TokenUsage] = None
    timestamp: datetime = field(default_factory=datetime.now)

    @classmethod
    def system(cls, text: str) -> "Message":
        return cls(role=MessageRole.SYSTEM, blocks=[ContentBlock.text_block(text)])

    @classmethod
    def user(cls, text: str) -> "Message":
        return cls(role=MessageRole.USER, blocks=[ContentBlock.text_block(text)])

    @classmethod
    def assistant(cls, blocks: List[ContentBlock],
                   usage: Optional[TokenUsage] = None) -> "Message":
        return cls(role=MessageRole.ASSISTANT, blocks=blocks, usage=usage)

    @classmethod
    def tool_result(cls, tool_name: str, output: str,
                    use_id: Optional[str] = None,
                    is_error: bool = False) -> "Message":
        return cls(
            role=MessageRole.TOOL,
            blocks=[ContentBlock.tool_result_block(tool_name, output, use_id, is_error)],
        )

    def text_content(self) -> str:
        """Concatenate all text blocks (skips tool_use/tool_result)."""
        return "\n".join(b.text or "" for b in self.blocks if b.block_type == "text")

    def tool_uses(self) -> List[ContentBlock]:
        """Return all tool_use blocks in this message."""
        return [b for b in self.blocks if b.block_type == "tool_use"]


@dataclass
class Session:
    """Append-only conversation transcript.

    The Session is the SOLE state of the runtime. No notebook, no blackboard,
    no separate coverage tracker. The model's reasoning emerges from the
    transcript and is preserved in the transcript.
    """
    version: int = 1
    messages: List[Message] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def append(self, message: Message) -> None:
        """Add a message to the end of the transcript (only mutation allowed)."""
        self.messages.append(message)

    def system_messages(self) -> List[Message]:
        return [m for m in self.messages if m.role == MessageRole.SYSTEM]

    def conversation_messages(self) -> List[Message]:
        """All non-system messages (user/assistant/tool)."""
        return [m for m in self.messages if m.role != MessageRole.SYSTEM]

    def total_usage(self) -> TokenUsage:
        total = TokenUsage()
        for m in self.messages:
            if m.usage:
                total = total.add(m.usage)
        return total

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "metadata": self.metadata,
            "messages": [
                {
                    "role": m.role.value,
                    "blocks": [b.to_dict() for b in m.blocks],
                    "usage": (
                        {"input_tokens": m.usage.input_tokens,
                         "output_tokens": m.usage.output_tokens}
                        if m.usage else None
                    ),
                    "timestamp": m.timestamp.isoformat(),
                }
                for m in self.messages
            ],
        }
