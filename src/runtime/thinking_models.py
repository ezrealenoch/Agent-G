"""Registry of known "thinking" / reasoning LLM models.

Thinking models do substantial internal reasoning before producing visible
output. They have different performance characteristics from standard chat
models and often require specific configuration to work with iterative
ReAct loops:

  - Higher max_tokens budgets (thinking tokens count against output budget)
  - Specific thinkingConfig settings (e.g., Gemini 3.x)
  - Native function-calling disabled (e.g., Gemini 3.x MALFORMED_FUNCTION_CALL)
  - Longer timeouts (5-10x slower per call than non-thinking models)
  - Blank-response handling (thinking can exhaust the output budget)

This module centralizes the "which models are thinking models" knowledge
so it can be referenced from ExternalClient, ConversationRuntime, and the
test harness without hardcoding model name substrings in multiple places.

To add support for a new thinking model, add a regex pattern to the
appropriate list below. Patterns are case-insensitive.
"""

from __future__ import annotations
import re
from typing import Optional


# ── Patterns ──────────────────────────────────────────────────────────

# Models whose architecture USES thinking heavily.
# These need: higher max_tokens, potentially longer timeouts,
# and blank-response retry handling.
THINKING_MODEL_PATTERNS: list[str] = [
    # ──────────────────────────────────────────────────────────────
    # Google Gemini 3.x family
    # ──────────────────────────────────────────────────────────────
    # Note: gemini-3.1-flash-LITE does NOT use thinking — exclude it
    # via negative lookahead. It's a stripped-down triage model
    # designed for speed/cost with thinking disabled by default.
    r"gemini-3(?!\.\d+-flash-lite)(?!-flash-lite)\b",  # gemini-3-pro, gemini-3-flash
    r"gemini-3\.(?!\d+-flash-lite)",                    # gemini-3.1-pro, gemini-3.1-flash
    r"gemini-.*-thinking",                              # any gemini-*-thinking variant

    # ──────────────────────────────────────────────────────────────
    # OpenAI reasoning models (o-series and gpt-*-reasoning)
    # ──────────────────────────────────────────────────────────────
    # The o-series introduced "reasoning tokens" — hidden thought tokens
    # that occupy context window space and are billed as output tokens.
    # Source: https://platform.openai.com/docs/guides/reasoning
    r"^o1(-|$)",                # o1, o1-mini, o1-preview
    r"^o3(-|$)",                # o3, o3-mini, o3-pro
    r"^o4(-|$)",                # o4, o4-mini (released April 2025, 128K context)
    r"^o5(-|$)",                # future-proof o5 family
    r"^gpt-5(\b|[-.])",         # gpt-5, gpt-5.1-codex, gpt-5-mini, etc.
    r"gpt-.*-reasoning",        # hypothetical gpt-5/6-reasoning variants
    r"gpt-5-.*thinking",        # GPT-5 thinking variants if released

    # ──────────────────────────────────────────────────────────────
    # Anthropic Claude with extended thinking
    # ──────────────────────────────────────────────────────────────
    # Claude thinking is OPT-IN via the request parameter `thinking:
    # {type: "enabled", budget_tokens: N}`. Model names don't usually
    # change — it's the SAME model with thinking on or off. We match
    # explicit "-thinking" variants some deployments tag.
    r"claude-.*-thinking",
    r"claude-opus-4.*\bthink",
    r"claude-sonnet-4.*\bthink",

    # ──────────────────────────────────────────────────────────────
    # DeepSeek reasoning
    # ──────────────────────────────────────────────────────────────
    # DeepSeek-R1 was the first open-weight reasoning model trained with
    # RL. R2 is anticipated but not yet released as of this registry.
    # Source: https://www.nature.com/articles/s41586-025-09422-z
    r"deepseek-r1\b",
    r"deepseek-r2\b",           # future-proof
    r"deepseek-reasoner",
    r"deepseek-v3\.1\b",        # V3.1 and V3.2 have reasoning capabilities
    r"deepseek-v3\.2\b",

    # ──────────────────────────────────────────────────────────────
    # Alibaba Qwen reasoning
    # ──────────────────────────────────────────────────────────────
    # Qwen3 is a hybrid reasoning model — thinking is toggled via
    # <think></think> tags in the tokenizer. Qwen3-Next-Thinking
    # auto-enables thinking mode. Qwen3.5 and later default to
    # thinking-on behaviour and require higher token budgets even
    # when tools aren't involved.
    r"\bqwq[-:]",               # qwq-32b, qwq:32b (the original QwQ)
    r"qwen3\.5",                # qwen3.5:397b-cloud and siblings (thinking-on default)
    r"qwen3\.6",                # future-proof qwen3.6
    r"qwen3\.\d+",              # any qwen3.X series
    r"qwen4",                   # future-proof
    r"qwen3.*thinking",
    r"qwen-?3.*reasoning",
    r"qwen3-next.*thinking",
    r"qwen3-max.*thinking",

    # ──────────────────────────────────────────────────────────────
    # Small-model capacity fix (NOT real thinking)
    # ──────────────────────────────────────────────────────────────
    # gemma4:e4b is a 4B active-param MoE that is not a thinking model,
    # but empirically it truncates to an empty completion on long
    # agentic prompts unless num_predict is bumped. Listing it here
    # triggers the OllamaClient's auto num_predict bump, which gives
    # the model enough headroom to actually emit a verdict. This is a
    # capacity fix, not a reasoning configuration.
    r"^gemma4:e4b",
    r"^gemma4:.*4b",

    # ──────────────────────────────────────────────────────────────
    # Google Gemma 4 family (via Gemini API)
    # ──────────────────────────────────────────────────────────────
    # Gemma 4 models are REAL thinking models — they emit a separate
    # "thought": true content part with internal reasoning, then the
    # visible answer in a second part. Direct probes show ~88% of the
    # output token budget goes to thought tokens, so without a bumped
    # max_tokens the visible budget is exhausted before the verdict.
    # These are exposed through Google's generativelanguage.googleapis.com
    # endpoint, so they hit the _generate_google path (not Ollama).
    r"^gemma-4-\d+b(-[a-z0-9]+)?-it$",   # gemma-4-31b-it, gemma-4-26b-a4b-it
    r"^gemma-4",                          # future-proof any gemma-4* variant

    # ──────────────────────────────────────────────────────────────
    # Moonshot AI (Kimi K-series)
    # ──────────────────────────────────────────────────────────────
    # Kimi K2 Thinking is a 1T-param MoE model that ONLY outputs in
    # thinking format with <think></think> blocks. It can execute
    # 200-300 tool calls per reasoning session.
    r"kimi-k2.*thinking",
    r"kimi-k2-reasoning",
    r"kimi-k3",                 # future-proof K3 family
    r"moonshot-.*thinking",

    # ──────────────────────────────────────────────────────────────
    # Zhipu AI (GLM family)
    # ──────────────────────────────────────────────────────────────
    # GLM-5 and GLM-5.1 support "thinking mode" for complex multi-step
    # reasoning, similar to chain-of-thought in GPT-5 and Claude.
    r"glm-5(\.\d+)?.*thinking",
    r"glm-5\.1",                # GLM-5.1 has reasoning as core capability
    r"chatglm-.*reasoning",

    # ──────────────────────────────────────────────────────────────
    # Mistral reasoning
    # ──────────────────────────────────────────────────────────────
    r"magistral",               # Mistral's reasoning model family

    # ──────────────────────────────────────────────────────────────
    # xAI Grok
    # ──────────────────────────────────────────────────────────────
    r"grok-.*reasoning",
    r"grok-.*thinking",
    r"grok-4",                  # grok-4 is reasoning-heavy
    r"grok-5",                  # future-proof

    # ──────────────────────────────────────────────────────────────
    # NVIDIA Nemotron reasoning variants
    # ──────────────────────────────────────────────────────────────
    r"nemotron-.*reasoning",
    r"nemotron-.*think",

    # ──────────────────────────────────────────────────────────────
    # Ollama-hosted reasoning variants and open weights
    # ──────────────────────────────────────────────────────────────
    r"^marco-o1",               # Alibaba's open o1-style model
    r"^openthinker",            # Open-source thinking model family
    r"^thinking-",              # Generic "thinking-*" tags users apply
    r"phi-4-reasoning",         # Microsoft Phi-4 reasoning variants
    r"llama-.*-reasoning",      # Meta reasoning variants (hypothetical)
]

# Models where thinking CANNOT be disabled (thinkingBudget=0 is rejected,
# or there is no way to opt out). These REQUIRE higher budgets and the
# blank-response retry because the model WILL sometimes burn the whole
# output budget on internal reasoning.
MANDATORY_THINKING_PATTERNS: list[str] = [
    # ── Google: Gemini 3.x Pro and full Flash (not Lite) ──
    # Flash-Lite does NOT require thinking — it's the non-thinking tier.
    r"gemini-3\.1?-pro",
    r"gemini-3\.1?-flash(?!-lite)",    # confirmed via API: thinkingBudget=0 rejected
    r"gemini-3-pro",
    r"gemini-3-flash(?!-lite)",

    # ── OpenAI: entire o-series is reasoning-only ──
    # Confirmed: "reasoning tokens are not visible via the API, they still
    # occupy space in the model's context window and are billed as output."
    # There is no way to disable reasoning on o-series models.
    r"^o1(-|$)",                # o1, o1-mini, o1-preview
    r"^o3(-|$)",                # o3, o3-mini, o3-pro
    r"^o4(-|$)",                # o4, o4-mini (Apr 2025+)
    r"^o5(-|$)",                # future-proof

    # ── DeepSeek: R1 is reasoning-only ──
    # R1 was trained with RL to DIRECTLY optimize reasoning. There is no
    # "non-reasoning mode" — the model always produces <think> blocks.
    r"deepseek-r1\b",
    r"deepseek-r2\b",
    r"deepseek-reasoner",

    # ── Moonshot Kimi K2 Thinking ──
    # Confirmed: "Kimi K2 only outputs in a 'thinking' format with
    # <think>...</think> blocks, enforcing chain-of-thought." It is
    # architecturally incapable of producing non-thinking output.
    r"kimi-k2.*thinking",
    r"kimi-k2-reasoning",

    # ── QwQ (original Qwen reasoning model) ──
    # QwQ always emits <think> blocks. Qwen3 is hybrid (toggleable) so
    # it's NOT in the mandatory list.
    r"\bqwq[-:]",
]


# ── Compiled regexes (at import time) ────────────────────────────────

def _compile(patterns: list[str]) -> re.Pattern:
    """Compile a list of pattern strings into a single regex with alternation."""
    if not patterns:
        # Match nothing
        return re.compile(r"(?!)")
    joined = "|".join(f"(?:{p})" for p in patterns)
    return re.compile(joined, re.IGNORECASE)


_THINKING_REGEX = _compile(THINKING_MODEL_PATTERNS)
_MANDATORY_REGEX = _compile(MANDATORY_THINKING_PATTERNS)


# ── Budget defaults ───────────────────────────────────────────────────

# Standard completion models can do fine with ~4-8k output tokens.
DEFAULT_MAX_TOKENS = 8192

# Thinking models need substantially more headroom — thinking tokens count
# against the same budget as visible output, so with 8k total a model that
# thinks for 7k will only produce 1k of visible text. 32k gives typical
# thinking models (5-15k thoughts) plenty of room for a verdict report.
THINKING_MODEL_MAX_TOKENS = 32768

# Absolute ceiling the runtime will escalate retries to. Set high enough to
# accommodate even very verbose reasoning, but not infinite (prevents
# runaway costs on APIs that bill per token).
MAX_THINKING_RETRY_CEILING = 131072

# Sentinel string returned by the LLM clients (Google, Anthropic, OpenAI,
# Ollama) when the empty-response retry escalation has exhausted its budget
# and the model has STILL produced no visible output. The conversation
# runtime detects this exact string and sets exit_reason="blank_response"
# so the harness can classify it as BLANK_RESPONSE rather than a generic
# UNKNOWN. Keep the wording stable; downstream parsers match on substrings.
BLANK_RESPONSE_SENTINEL = "[Model returned a blank response — thinking budget exhausted]"


# ── Public API ────────────────────────────────────────────────────────

def is_thinking_model(model_name: Optional[str]) -> bool:
    """Return True if the named model is a known thinking/reasoning model.

    Case-insensitive. Matches on substring so prefixed/suffixed variants
    (e.g., "models/gemini-3-flash-preview") are also detected.
    """
    if not model_name:
        return False
    return bool(_THINKING_REGEX.search(model_name))


def requires_thinking(model_name: Optional[str]) -> bool:
    """Return True if the model CANNOT have thinking disabled.

    These models will sometimes return empty visible output even on
    simple prompts because the thinking budget consumed all the output
    tokens. The runtime should apply the blank-response retry and use
    a higher default max_tokens budget.
    """
    if not model_name:
        return False
    return bool(_MANDATORY_REGEX.search(model_name))


def recommended_max_tokens(
    model_name: Optional[str],
    default: int = DEFAULT_MAX_TOKENS,
) -> int:
    """Return the recommended initial max_tokens budget for a model.

    For thinking models returns max(default, THINKING_MODEL_MAX_TOKENS).
    For standard models returns the caller-supplied default.
    """
    if is_thinking_model(model_name):
        return max(default, THINKING_MODEL_MAX_TOKENS)
    return default


def describe_model(model_name: Optional[str]) -> str:
    """Human-readable classification of a model's thinking status."""
    if not model_name:
        return "unknown model"
    if requires_thinking(model_name):
        return "mandatory-thinking (cannot disable, empty-output risk high)"
    if is_thinking_model(model_name):
        return "optional-thinking (deeper reasoning, slower per call)"
    return "standard completion model"


def get_known_thinking_models() -> list[str]:
    """Return a list of example model IDs that are known thinking models.

    For documentation/help-text purposes — not exhaustive.
    Last updated: April 2026 (as of this registry version).
    """
    return [
        # ── Google ──
        "gemini-3-pro-preview",
        "gemini-3-flash-preview",
        "gemini-3.1-pro-preview",
        "gemini-3.1-flash-preview",
        # Note: gemini-3.1-flash-lite-preview is NOT a thinking model

        # ── OpenAI o-series (reasoning tokens) ──
        "o1",
        "o1-mini",
        "o1-preview",
        "o3",
        "o3-mini",
        "o3-pro",
        "o4",
        "o4-mini",            # released 2025-04-16, 128K context

        # ── Anthropic (with extended thinking explicitly enabled) ──
        "claude-opus-4-thinking",
        "claude-sonnet-4-thinking",
        "claude-opus-4.6-thinking",

        # ── DeepSeek ──
        "deepseek-r1",
        "deepseek-reasoner",
        "deepseek-v3.1",
        "deepseek-v3.2",

        # ── Alibaba Qwen ──
        "qwq-32b",
        "qwq:32b",
        "qwen3-next-80b-thinking",
        "qwen3-max-thinking",

        # ── Moonshot Kimi K2 Thinking ──
        "kimi-k2-thinking",     # 1T params MoE, thinking-only
        "kimi-k2-reasoning",

        # ── Zhipu GLM ──
        "glm-5.1",              # 744B MoE with thinking mode
        "glm-5-thinking",

        # ── Mistral ──
        "magistral-medium",
        "magistral-small",

        # ── xAI Grok ──
        "grok-4",
        "grok-4-reasoning",

        # ── Microsoft Phi ──
        "phi-4-reasoning",

        # ── NVIDIA Nemotron ──
        "nemotron-reasoning",

        # ── Open-source / other ──
        "marco-o1",             # Alibaba's open o1-style
        "openthinker-32b",
    ]
