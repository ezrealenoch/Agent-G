"""Runtime budget enforcement + cost tracking.

Defines a ``Budget`` dataclass capturing the hard limits for an investigation
(wall time, tokens, tool calls, iterations, dollar cost) and a tracker
protocol. The ConversationRuntime calls ``budget.check()`` after every
iteration; if any limit is exceeded the loop breaks cleanly with
``exit_reason="budget_exceeded"``.

Pricing table is intentionally small but easy to extend. For models not
listed the cost defaults to 0 and only token/time/call limits apply.

Design:
  - ``Budget`` is immutable — captures the hard caps
  - ``BudgetTracker`` is mutable — accumulates spend and answers check()
  - Callers can construct either (a) a Budget with caps and derive a
    tracker via ``Budget.new_tracker()``, or (b) a bare tracker for
    no-cap use (everything counted, nothing enforced)
"""
from __future__ import annotations
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("agent-g.budget")


# ── Pricing table ────────────────────────────────────────────────────
# USD per 1K tokens. Input and output are billed at different rates on most
# providers. Values are rough order-of-magnitude as of 2026-04; keep this
# updated as providers adjust published pricing.
#
# The lookup is substring-based (case-insensitive) against the model name so
# "claude-sonnet-4-5" matches "claude-sonnet-4-5-20250929" etc. Matches
# run in order and the first hit wins — put more specific entries FIRST.
PRICING_USD_PER_1K = [
    # Anthropic
    ("claude-opus-4-6",           {"input": 0.015, "output": 0.075}),
    ("claude-opus-4-5",           {"input": 0.015, "output": 0.075}),
    ("claude-sonnet-4-6",         {"input": 0.003, "output": 0.015}),
    ("claude-sonnet-4-5",         {"input": 0.003, "output": 0.015}),
    ("claude-haiku-4-5",          {"input": 0.001, "output": 0.005}),
    ("claude-",                   {"input": 0.003, "output": 0.015}),  # generic Claude fallback
    # OpenAI
    ("gpt-5.4-mini",              {"input": 0.00015, "output": 0.0006}),
    ("gpt-5.4",                   {"input": 0.00125, "output": 0.01}),
    ("gpt-5-mini",                {"input": 0.00015, "output": 0.0006}),
    ("gpt-5",                     {"input": 0.00125, "output": 0.01}),
    ("o4-mini",                   {"input": 0.0011,  "output": 0.0044}),
    ("o4",                        {"input": 0.015,   "output": 0.060}),
    ("o3-mini",                   {"input": 0.0011,  "output": 0.0044}),
    ("o3",                        {"input": 0.015,   "output": 0.060}),
    ("gpt-4.1",                   {"input": 0.002,   "output": 0.008}),
    ("gpt-4o-mini",               {"input": 0.00015, "output": 0.0006}),
    ("gpt-4o",                    {"input": 0.0025,  "output": 0.010}),
    # Google Gemini
    ("gemini-3.1-pro",            {"input": 0.00125, "output": 0.010}),
    ("gemini-3.1-flash-lite",     {"input": 0.000075,"output": 0.0003}),
    ("gemini-3.1-flash",          {"input": 0.00015, "output": 0.0006}),
    ("gemini-3",                  {"input": 0.00125, "output": 0.010}),  # future-proof
    # Google Gemma (via Gemini API) — free tier, no spend
    ("gemma-4",                   {"input": 0.0,     "output": 0.0}),
    ("gemma-3",                   {"input": 0.0,     "output": 0.0}),
    # Ollama local — zero marginal cost (electricity only, not tracked)
    ("gemma4:e4b",                {"input": 0.0,     "output": 0.0}),
    ("ollama:",                   {"input": 0.0,     "output": 0.0}),
    # Ollama cloud — pass-through billing; treat as pricing unknown
    ("qwen3.5:397b-cloud",        {"input": 0.0012,  "output": 0.006}),
    ("gemma4:31b-cloud",          {"input": 0.0003,  "output": 0.0012}),
]


def lookup_pricing(model_name: str) -> dict:
    """Return {input, output} USD per 1K tokens for a model name.

    Falls back to {0, 0} if no entry matches, so unknown/local models
    simply won't accumulate cost. Caller can decide whether that's OK.
    """
    if not model_name:
        return {"input": 0.0, "output": 0.0}
    name_l = model_name.lower()
    for needle, rates in PRICING_USD_PER_1K:
        if needle.lower() in name_l:
            return rates
    return {"input": 0.0, "output": 0.0}


# ── Budget ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Budget:
    """Hard limits for a single investigation. None = no limit on that axis."""
    wall_time_s: Optional[float] = None
    max_input_tokens: Optional[int] = None
    max_output_tokens: Optional[int] = None
    max_total_tokens: Optional[int] = None
    max_tool_calls: Optional[int] = None
    max_iterations: Optional[int] = None
    max_cost_usd: Optional[float] = None

    def new_tracker(self, model_name: str = "") -> "BudgetTracker":
        """Construct a fresh tracker bound to this budget."""
        return BudgetTracker(budget=self, model_name=model_name)

    @classmethod
    def unlimited(cls) -> "Budget":
        """Factory: no hard limits, only tracking. Useful for interactive REPL."""
        return cls()

    @classmethod
    def default_production(cls) -> "Budget":
        """Sensible safety limits for an autonomous production run."""
        return cls(
            wall_time_s=600.0,          # 10 min per investigation
            max_total_tokens=200_000,   # ~50k words
            max_tool_calls=80,
            max_iterations=30,
            max_cost_usd=1.00,          # $1 ceiling
        )


class BudgetExceeded(Exception):
    """Raised by ``BudgetTracker.check()`` when any limit is hit."""
    def __init__(self, axis: str, limit, actual):
        self.axis = axis
        self.limit = limit
        self.actual = actual
        super().__init__(f"Budget exceeded on {axis}: {actual} >= {limit}")


@dataclass
class BudgetTracker:
    """Mutable accumulator for a single investigation.

    Call ``add_usage(...)`` after each LLM round-trip and
    ``add_tool_call()`` after each tool dispatch. Call ``check()`` anywhere
    you want a hard-stop — the ConversationRuntime calls it between iterations.
    """
    budget: Budget = field(default_factory=Budget.unlimited)
    model_name: str = ""
    started_at: float = field(default_factory=time.time)

    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    iterations: int = 0
    cost_usd: float = 0.0

    def add_usage(self, input_tokens: int, output_tokens: int, model: str = "") -> None:
        """Accumulate token usage and derived cost from a single LLM round-trip."""
        self.input_tokens += max(0, int(input_tokens or 0))
        self.output_tokens += max(0, int(output_tokens or 0))
        m = model or self.model_name
        if m:
            rates = lookup_pricing(m)
            self.cost_usd += (input_tokens or 0) / 1000.0 * rates["input"]
            self.cost_usd += (output_tokens or 0) / 1000.0 * rates["output"]

    def add_tool_call(self) -> None:
        self.tool_calls += 1

    def add_iteration(self) -> None:
        self.iterations += 1

    @property
    def elapsed_s(self) -> float:
        return time.time() - self.started_at

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def check(self, raise_on_exceeded: bool = False) -> Optional[str]:
        """Return None if OK, or a human-readable reason if any limit is hit.

        When ``raise_on_exceeded=True`` the tracker raises ``BudgetExceeded``
        instead of returning the reason — useful in deep call sites that
        can't cleanly propagate a string.
        """
        b = self.budget
        reason = None
        if b.wall_time_s is not None and self.elapsed_s >= b.wall_time_s:
            reason = f"wall_time ({self.elapsed_s:.0f}s >= {b.wall_time_s:.0f}s)"
        elif b.max_input_tokens is not None and self.input_tokens >= b.max_input_tokens:
            reason = f"input_tokens ({self.input_tokens} >= {b.max_input_tokens})"
        elif b.max_output_tokens is not None and self.output_tokens >= b.max_output_tokens:
            reason = f"output_tokens ({self.output_tokens} >= {b.max_output_tokens})"
        elif b.max_total_tokens is not None and self.total_tokens >= b.max_total_tokens:
            reason = f"total_tokens ({self.total_tokens} >= {b.max_total_tokens})"
        elif b.max_tool_calls is not None and self.tool_calls >= b.max_tool_calls:
            reason = f"tool_calls ({self.tool_calls} >= {b.max_tool_calls})"
        elif b.max_iterations is not None and self.iterations >= b.max_iterations:
            reason = f"iterations ({self.iterations} >= {b.max_iterations})"
        elif b.max_cost_usd is not None and self.cost_usd >= b.max_cost_usd:
            reason = f"cost_usd (${self.cost_usd:.4f} >= ${b.max_cost_usd:.4f})"
        if reason and raise_on_exceeded:
            axis = reason.split(" ", 1)[0]
            raise BudgetExceeded(axis=axis, limit=reason, actual=reason)
        return reason

    def snapshot(self) -> dict:
        """Return a read-only dict for logging / provenance bundles."""
        return {
            "model": self.model_name,
            "elapsed_s": round(self.elapsed_s, 2),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "tool_calls": self.tool_calls,
            "iterations": self.iterations,
            "cost_usd": round(self.cost_usd, 6),
            "budget": {
                "wall_time_s": self.budget.wall_time_s,
                "max_input_tokens": self.budget.max_input_tokens,
                "max_output_tokens": self.budget.max_output_tokens,
                "max_total_tokens": self.budget.max_total_tokens,
                "max_tool_calls": self.budget.max_tool_calls,
                "max_iterations": self.budget.max_iterations,
                "max_cost_usd": self.budget.max_cost_usd,
            },
        }
