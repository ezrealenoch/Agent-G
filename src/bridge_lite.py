"""Lightweight bridge for headless Agent-G operation.

Wires together the LLM client, Ghidra client, ToolExecutor, and the new
CLAW-inspired ConversationRuntime. Replaces OGhidra's monolithic Bridge
class with a slim adapter that has no GUI, no CAG, no vector DB.
"""

import logging

from src.config import BridgeConfig
from src.ghidra_client import GhidraMCPClient
from src.lazy_ghidra import LazyGhidraClient
from src.tool_executor import ToolExecutor
from src.command_parser import CommandParser

from src.runtime.api_client import ApiClient
from src.runtime.tool_runner import ToolRunner
from src.runtime.conversation import ConversationRuntime
from src.runtime.bootstrap import install_bootstrap_in_session
from src.runtime.prompts import (
    build_vuln_hunting_prompt,
    build_malware_hunting_prompt,
    build_binary_description_prompt,
    build_freeform_prompt,
)


logger = logging.getLogger("agent-g.bridge")


# Map task names to prompt builders
PROMPT_BUILDERS = {
    "vuln": build_vuln_hunting_prompt,
    "malware": build_malware_hunting_prompt,
    "describe": build_binary_description_prompt,
    "freeform": build_freeform_prompt,
}


class BridgeLite:
    """Minimal bridge connecting LLM, Ghidra, and the new ReAct runtime.

    Unlike OGhidra's Bridge, this has no UI, no CAG, no vector DB,
    and no session history persistence. It's designed for single-session
    headless terminal usage with the CLAW-inspired runtime.
    """

    def __init__(self, config: BridgeConfig, binary_name: str = "binary"):
        self.config = config
        self.binary_name = binary_name
        self.provider = getattr(config, "llm_provider", "ollama")

        # Handle provider aliases
        if self.provider == "google":
            self.provider = "external"

        # Initialize LLM client
        if self.provider == "external":
            from src.external_client import ExternalClient
            self.llm_config = config.external
            self.llm = ExternalClient(config=self.llm_config)
        elif self.provider == "custom_api":
            from src.custom_api_client import CustomAPIClient
            self.llm_config = config.custom_api
            self.llm = CustomAPIClient(config=self.llm_config)
        else:
            from src.ollama_client import OllamaClient
            self.llm_config = config.ollama
            self.llm = OllamaClient(config=self.llm_config)

        logger.info("LLM provider: %s", self.provider)

        # Ghidra client (lazy — connects on first use)
        self.ghidra_client = LazyGhidraClient(
            GhidraMCPClient, config=config.ghidra, ollama_client=self.llm
        )

        # Command parser & tool executor (existing OGhidra components)
        self.command_parser = CommandParser()
        self.tool_executor = ToolExecutor(
            ghidra_client=self.ghidra_client,
            command_parser=self.command_parser,
        )

        # Runtime adapters
        self.api_client = ApiClient(self.llm, phase="investigation")
        self.tool_runner = ToolRunner(self.tool_executor, self.command_parser)

        # Backward compat alias for direct tool calls in REPL
        self.ollama = self.llm

        # Runtime is created lazily per task — see start_task()
        self.runtime: ConversationRuntime = None
        self._bootstrap_done = False
        self._discovery_text = None  # Cached bootstrap result for task switching

        logger.info("BridgeLite initialized")

    def start_task(self, task: str = "vuln") -> ConversationRuntime:
        """Initialize a new ConversationRuntime for the given task.

        Runs the discovery bootstrap once (cached for subsequent tasks).
        Returns the configured runtime.
        """
        prompt_builder = PROMPT_BUILDERS.get(task, build_freeform_prompt)
        system_prompt = prompt_builder()

        self.runtime = ConversationRuntime(
            api_client=self.api_client,
            tool_runner=self.tool_runner,
            command_parser=self.command_parser,
            system_prompt=system_prompt,
        )

        # Run bootstrap once and cache it
        if not self._bootstrap_done:
            print(f"[BridgeLite] Running discovery bootstrap...")
            install_bootstrap_in_session(
                self.runtime.session, self.tool_runner, self.binary_name
            )
            # Cache the bootstrap message for replay on task switch
            convo = self.runtime.session.conversation_messages()
            if convo:
                self._discovery_text = convo[0].text_content()
            self._bootstrap_done = True
        else:
            # Replay cached bootstrap into the new runtime
            if self._discovery_text:
                from src.runtime.session import Message
                self.runtime.session.append(Message.user(self._discovery_text))

        return self.runtime

    def process_query(self, query: str, task: str = "vuln") -> str:
        """Run a single user query through the runtime, return final text.

        If task is provided and differs from current, the runtime is
        re-initialized with the new system prompt (bootstrap replayed).
        """
        if self.runtime is None:
            self.start_task(task)

        result = self.runtime.run_turn(query)
        return result.final_text

    def switch_task(self, task: str) -> None:
        """Switch the runtime to a different task without re-running bootstrap."""
        self.start_task(task)

    def set_tool_runner(self, runner) -> None:
        """Replace the active tool runner.

        Used by test harnesses to install a wrapping filter (e.g. LeakFilter)
        that strips leaky content from tool results before the LLM sees them.
        Must be called BEFORE start_task() so the bootstrap also runs through
        the filter.
        """
        self.tool_runner = runner
        if self.runtime is not None:
            self.runtime.tools = runner
