"""Circuit breaker for LLM providers.

Every HTTP call to a cloud provider passes through a per-provider circuit.
When sustained failures (5xx, 429, network errors) cross a threshold the
circuit OPENs and subsequent requests short-circuit without touching the
provider for a cooldown window. After the cooldown the circuit goes
HALF_OPEN and allows a single probe — success closes it, failure re-opens
it with an exponentially extended cooldown.

This is deliberately simple:
  - In-memory state keyed by provider name (shared process-wide)
  - Thread-safe via a module-level lock
  - No persistence across process restarts (add JSON dump if needed)

Integration: call ``cb = get_breaker(provider).before_request()`` before any
cloud HTTP call. If it raises ``CircuitOpenError`` the caller should either
fall back to a secondary provider or return a ``BLANK_RESPONSE_SENTINEL``
immediately. On completion call ``cb.record_success()`` or
``cb.record_failure(status_code, exc)``.

Configuration lives in the dataclass defaults — override via env vars if
needed. Tune per-provider if a provider has unusual quota semantics.
"""
from __future__ import annotations
import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, Optional

logger = logging.getLogger("agent-g.circuit_breaker")


class CircuitState(str, Enum):
    CLOSED = "closed"       # normal operation
    OPEN = "open"           # tripped, rejecting all requests
    HALF_OPEN = "half_open"  # probing, single request allowed through


class CircuitOpenError(RuntimeError):
    """Raised when a request is blocked by an open circuit."""
    def __init__(self, provider: str, reopen_at: float):
        self.provider = provider
        self.reopen_at = reopen_at
        secs = max(0, reopen_at - time.time())
        super().__init__(
            f"Circuit OPEN for '{provider}'. Retry in {secs:.0f}s."
        )


@dataclass
class BreakerConfig:
    """Per-circuit configuration. Tune per provider as needed."""
    # Trip when this fraction of the last `window_size` requests failed
    failure_threshold: float = 0.5
    # Require at least this many samples in the window before tripping
    min_samples: int = 5
    # Size of the sliding window (requests, not seconds)
    window_size: int = 20
    # Initial cooldown on trip
    cooldown_initial_s: float = 30.0
    # Max cooldown on repeated trips (exponential backoff)
    cooldown_max_s: float = 600.0
    # Multiplier applied on each re-trip from HALF_OPEN
    cooldown_multiplier: float = 2.0
    # HTTP status codes that count as "failure" for tripping purposes.
    # 429 is included because sustained rate-limiting is a health signal.
    failure_status_codes: tuple = (429, 500, 502, 503, 504)
    # Statuses that should be treated as "server broken" even without quota
    # (gets a faster trip via a lower threshold when only these are seen)
    fast_trip_status_codes: tuple = (500, 502, 503, 504)
    fast_trip_consecutive: int = 3  # N consecutive fast-trip statuses = instant trip


@dataclass
class Breaker:
    """A single circuit. Thread-safe via ``self._lock``."""
    provider: str
    config: BreakerConfig = field(default_factory=BreakerConfig)
    state: CircuitState = CircuitState.CLOSED
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _window: Deque[bool] = field(default_factory=deque, repr=False)
    _cooldown_s: float = 0.0
    _reopen_at: float = 0.0
    _consecutive_fast_trip: int = 0
    _trip_count: int = 0

    def before_request(self) -> None:
        """Check state and raise ``CircuitOpenError`` if blocked.

        Called before every cloud request. Transitions OPEN→HALF_OPEN when
        the cooldown has elapsed and allows a single probe through.
        """
        with self._lock:
            now = time.time()
            if self.state == CircuitState.OPEN:
                if now >= self._reopen_at:
                    self.state = CircuitState.HALF_OPEN
                    logger.info(
                        "circuit '%s' HALF_OPEN — probing", self.provider,
                    )
                else:
                    raise CircuitOpenError(self.provider, self._reopen_at)

    def record_success(self) -> None:
        """Call after a successful request (2xx)."""
        with self._lock:
            self._window.append(True)
            if len(self._window) > self.config.window_size:
                self._window.popleft()
            self._consecutive_fast_trip = 0
            if self.state == CircuitState.HALF_OPEN:
                logger.info(
                    "circuit '%s' CLOSED — probe succeeded", self.provider,
                )
                self.state = CircuitState.CLOSED
                self._cooldown_s = 0.0  # reset backoff on recovery

    def record_failure(
        self,
        status_code: Optional[int] = None,
        exception: Optional[BaseException] = None,
    ) -> None:
        """Call after a failed request. Status code 0 for network errors."""
        with self._lock:
            code = status_code or 0
            is_failure = (
                code in self.config.failure_status_codes
                or (exception is not None and status_code is None)
            )
            if not is_failure:
                # Not a failure-worthy status — don't pollute the window
                return

            self._window.append(False)
            if len(self._window) > self.config.window_size:
                self._window.popleft()

            if code in self.config.fast_trip_status_codes:
                self._consecutive_fast_trip += 1
            else:
                self._consecutive_fast_trip = 0

            # Fast trip on sustained 5xx
            if self._consecutive_fast_trip >= self.config.fast_trip_consecutive:
                logger.warning(
                    "circuit '%s' FAST-TRIP — %d consecutive %s errors",
                    self.provider, self._consecutive_fast_trip, code,
                )
                self._trip(reason=f"{self._consecutive_fast_trip}×{code}")
                return

            # Half-open probe failed → re-open with extended cooldown
            if self.state == CircuitState.HALF_OPEN:
                logger.warning(
                    "circuit '%s' RE-OPEN — probe failed (%s)",
                    self.provider, code,
                )
                self._trip(reason=f"probe-fail-{code}")
                return

            # Window-based trip
            if len(self._window) >= self.config.min_samples:
                fail_count = sum(1 for ok in self._window if not ok)
                fail_rate = fail_count / len(self._window)
                if fail_rate >= self.config.failure_threshold:
                    logger.warning(
                        "circuit '%s' TRIP — failure rate %.0f%% over %d samples",
                        self.provider, fail_rate * 100, len(self._window),
                    )
                    self._trip(reason=f"fail-rate-{fail_rate:.0%}")

    def _trip(self, reason: str) -> None:
        """Move to OPEN with exponential-backoff cooldown. Caller holds lock."""
        self._trip_count += 1
        if self._cooldown_s == 0:
            self._cooldown_s = self.config.cooldown_initial_s
        else:
            self._cooldown_s = min(
                self._cooldown_s * self.config.cooldown_multiplier,
                self.config.cooldown_max_s,
            )
        self._reopen_at = time.time() + self._cooldown_s
        self.state = CircuitState.OPEN
        self._window.clear()
        self._consecutive_fast_trip = 0
        logger.warning(
            "circuit '%s' OPEN — reason=%s cooldown=%.0fs reopen_at=%.0f",
            self.provider, reason, self._cooldown_s, self._reopen_at,
        )

    def snapshot(self) -> dict:
        """Return a read-only snapshot for observability/logging."""
        with self._lock:
            return {
                "provider": self.provider,
                "state": self.state.value,
                "window_size": len(self._window),
                "failures_in_window": sum(1 for ok in self._window if not ok),
                "cooldown_s": self._cooldown_s,
                "reopen_at": self._reopen_at,
                "trip_count": self._trip_count,
            }


# ── Module-level registry ─────────────────────────────────────────────

_registry: Dict[str, Breaker] = {}
_registry_lock = threading.RLock()


def get_breaker(provider: str, config: Optional[BreakerConfig] = None) -> Breaker:
    """Return the process-wide breaker for a provider, creating on first use."""
    with _registry_lock:
        b = _registry.get(provider)
        if b is None:
            b = Breaker(provider=provider, config=config or BreakerConfig())
            _registry[provider] = b
            logger.debug("created circuit breaker for '%s'", provider)
        return b


def all_snapshots() -> list:
    """Return snapshots of every registered breaker (for /healthz etc)."""
    with _registry_lock:
        return [b.snapshot() for b in _registry.values()]


def reset_all() -> None:
    """Reset all circuits to CLOSED. Used by tests and manual recovery."""
    with _registry_lock:
        for b in _registry.values():
            with b._lock:
                b.state = CircuitState.CLOSED
                b._window.clear()
                b._cooldown_s = 0.0
                b._reopen_at = 0.0
                b._consecutive_fast_trip = 0


# Allow env override of key thresholds without editing code.
def _load_env_config() -> BreakerConfig:
    cfg = BreakerConfig()
    if os.getenv("AGENT_G_CB_FAILURE_THRESHOLD"):
        cfg.failure_threshold = float(os.environ["AGENT_G_CB_FAILURE_THRESHOLD"])
    if os.getenv("AGENT_G_CB_COOLDOWN_INITIAL_S"):
        cfg.cooldown_initial_s = float(os.environ["AGENT_G_CB_COOLDOWN_INITIAL_S"])
    if os.getenv("AGENT_G_CB_COOLDOWN_MAX_S"):
        cfg.cooldown_max_s = float(os.environ["AGENT_G_CB_COOLDOWN_MAX_S"])
    return cfg


DEFAULT_CONFIG = _load_env_config()
