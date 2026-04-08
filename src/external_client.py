#!/usr/bin/env python3
"""
External Generic Client for OGhidra
-----------------------------------
Handles communication with external LLM APIs (Google Gemini, OpenAI, etc.).
Currently implements Google Gemini v1beta interface.
"""

import json
import logging
import requests
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Tuple
from tenacity import Retrying, stop_after_attempt, wait_exponential, retry_if_exception

# Reuse text chunking utilities from ollama_client
from src.ollama_client import chunk_text_for_embedding, average_embeddings

def is_retryable_exception(e):
    """Check if an exception is retryable (429, 500, 503, or connection/timeout)."""
    # Never retry a circuit-open error — the circuit breaker has already decided
    # that the provider is dead and further retries would just waste wall time.
    from src.runtime.circuit_breaker import CircuitOpenError
    if isinstance(e, CircuitOpenError):
        return False
    if isinstance(e, requests.exceptions.HTTPError):
        # Retry on 429 (Rate Limit), 500 (Server Error), and 503 (Service Unavailable)
        return e.response is not None and e.response.status_code in [429, 500, 503]
    # Also retry on connection and timeout errors
    return isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))


# Sentinel string returned when a thinking model exhausts its thinking budget
# and can't produce any visible output even after the retry escalation.
# Downstream code (ConversationRuntime, test harness) can detect this marker
# to distinguish "model said nothing deliberate" from "model crashed" from
# "model produced a verdict". The full phrase is designed to be self-explanatory
# if it ever leaks into a report.
# Re-export for backwards compatibility — canonical definition lives in
# src.runtime.thinking_models so all clients (Google, Anthropic, OpenAI,
# Ollama) reference the same sentinel.
from src.runtime.thinking_models import BLANK_RESPONSE_SENTINEL  # noqa: E402,F401
from src.runtime.circuit_breaker import (  # noqa: E402
    get_breaker, CircuitOpenError,
)

class ExternalClient:
    """Generic Client for interacting with External LLM APIs."""
    
    def __init__(self, config):
        """
        Initialize the External client.
        
        Args:
            config: ExternalConfig object with attributes:
                - provider: 'google', 'openai', etc.
                - api_key: API Key
                - model: Default model to use
                - ...
        """
        self.config = config
        self.provider = getattr(config, 'provider', 'google').lower()
        self.api_key = config.api_key
        self.default_model = config.model
        self.embedding_model = config.embedding_model
        
        # Generation Config
        self.temperature = getattr(config, 'temperature', 0.7)
        self.max_tokens = getattr(config, 'max_tokens', 8192)
        self.top_p = getattr(config, 'top_p', 0.95)
        self.top_k = getattr(config, 'top_k', 40)
        
        # Use default system prompt from config if available, else empty
        self.default_system_prompt = getattr(config, 'default_system_prompt', '')
        
        self.timeout = getattr(config, 'timeout', 120)
        self.logger = logging.getLogger("external-client")
        self.model_map = config.model_map
        
        # LLM Logging setup
        self.llm_logging_enabled = getattr(config, 'llm_logging_enabled', False)
        # We'll use a generic log file name unless specified
        self.llm_log_file = getattr(config, 'llm_log_file', 'logs/llm_interactions_external.log')
        self.llm_log_prompts = getattr(config, 'llm_log_prompts', True)
        self.llm_log_responses = getattr(config, 'llm_log_responses', True)
        self.llm_log_tokens = getattr(config, 'llm_log_tokens', True)
        self.llm_log_timing = getattr(config, 'llm_log_timing', True)
        self.llm_log_format = getattr(config, 'llm_log_format', 'json')
        self.llm_logger = None
        
        # Retry and Delay Config
        self.request_delay = getattr(config, 'request_delay', 0.0)
        self.max_retries = getattr(config, 'max_retries', 3)
        
        print(f"[ExternalClient] Initialized: provider={self.provider} model={self.default_model} delay={self.request_delay}s")
        
        if self.llm_logging_enabled:
            self._setup_llm_logger()
            
    def _setup_llm_logger(self):
        """Setup dedicated logger for LLM interactions."""
        # Create logs directory if it doesn't exist
        log_dir = Path(self.llm_log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create dedicated LLM logger
        self.llm_logger = logging.getLogger("llm-interactions-external")
        self.llm_logger.setLevel(logging.INFO)
        self.llm_logger.propagate = False
        
        # Remove any existing handlers
        self.llm_logger.handlers.clear()
        
        # Add file handler
        file_handler = logging.FileHandler(self.llm_log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Format depends on log format setting
        if self.llm_log_format == 'json':
            formatter = logging.Formatter('%(message)s')
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        
        file_handler.setFormatter(formatter)
        self.llm_logger.addHandler(file_handler)
        
        self.logger.info(f"External LLM logging initialized. Log file: {self.llm_log_file}")

    def _log_llm_interaction(self, interaction_type: str, data: Dict[str, Any]):
        """Log LLM interaction to dedicated log file."""
        if not self.llm_logging_enabled or not self.llm_logger:
            return
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'interaction_type': interaction_type,
            'provider': self.provider
        }
        
        if self.llm_log_format == 'json':
            log_entry.update(data)
            self.llm_logger.info(json.dumps(log_entry))
        else:
            # Simple text logging
            lines = [f"Type: {interaction_type}"]
            for key, value in data.items():
                lines.append(f"{key}: {value}")
            self.llm_logger.info('\n'.join(lines))

    def _guarded_post(self, provider_key: str, url, headers, json, stream=False, timeout=None):
        """Wrap ``requests.post`` with circuit-breaker state management.

        - Raises ``CircuitOpenError`` up to the caller if the provider is
          currently tripped. Caller should catch and return the
          ``BLANK_RESPONSE_SENTINEL`` so the runtime can tag the investigation
          as blocked rather than crashing.
        - Records success (2xx) or failure (5xx / 429 / connection error) on
          the per-provider circuit so sustained degradation auto-trips.
        """
        breaker = get_breaker(provider_key)
        breaker.before_request()  # raises CircuitOpenError if OPEN
        try:
            resp = requests.post(
                url,
                headers=headers,
                json=json,
                stream=stream,
                timeout=timeout or self.timeout,
            )
        except Exception as e:
            breaker.record_failure(status_code=None, exception=e)
            raise
        if 200 <= resp.status_code < 300:
            breaker.record_success()
        else:
            breaker.record_failure(status_code=resp.status_code)
        return resp

    def query(self, prompt: Union[str, Tuple[str, str]], phase: Optional[str] = None) -> str:
        """
        High-level query interface compatible with Bridge.
        Handles both string prompts and (system, user) tuples.
        
        Args:
            prompt: String prompt or (system_prompt, user_prompt) tuple
            phase: Optional phase name for model selection
            
        Returns:
            Generated response string
        """
        system_prompt = None
        user_prompt = prompt
        
        # Handle tuple prompt (system, user)
        if isinstance(prompt, tuple) and len(prompt) == 2:
            system_prompt, user_prompt = prompt
            
        return self.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            phase=phase
        )

    def generate(self, 
                prompt: str, 
                model: Optional[str] = None,
                system_prompt: Optional[str] = None,
                temperature: Optional[float] = None,
                max_tokens: Optional[int] = None,
                phase: Optional[str] = None) -> str:
        """
        Generate a response from the External API.
        Currently supports: Google (Gemini)
        """
        start_time = time.time() if self.llm_log_timing else None
        
        # Request Delay
        if self.request_delay > 0:
            self.logger.debug(f"Sleeping for {self.request_delay}s before request")
            time.sleep(self.request_delay)
            
        used_model = model or self.default_model
        used_system = system_prompt or self.default_system_prompt
        
        # --- Provider: Google ---
        if self.provider == 'google':
             return self._generate_google(prompt, used_model, used_system, temperature, max_tokens, start_time, phase)
        # --- Provider: Anthropic (Claude) ---
        elif self.provider == 'anthropic':
             return self._generate_anthropic(prompt, used_model, used_system, temperature, max_tokens, start_time, phase)
        # --- Provider: OpenAI ---
        elif self.provider == 'openai':
             return self._generate_openai(prompt, used_model, used_system, temperature, max_tokens, start_time, phase)
        else:
             self.logger.error(f"Provider '{self.provider}' not implemented yet.")
             return ""

    def _circuit_gate(self, provider_key: str):
        """Raise nothing but return the sentinel text if the circuit is open.

        Wraps ``breaker.before_request()`` for the call-site pattern:
            if (gate := self._circuit_gate("google")) is not None:
                return gate
        """
        try:
            get_breaker(provider_key).before_request()
        except CircuitOpenError as e:
            self.logger.warning(
                "provider '%s' circuit OPEN — short-circuiting request: %s",
                provider_key, e,
            )
            return f"[CIRCUIT_OPEN: {e}]"
        return None

    def _generate_anthropic(self, prompt, model, system_prompt, temperature, max_tokens, start_time, phase=None):
        """Anthropic Claude Implementation.

        Uses the v1/messages endpoint. Differs from Google in that:
          - Auth header is `x-api-key` (not `X-goog-api-key`)
          - System prompt is a top-level `system` string (not nested)
          - Messages array uses `role` + `content` (not `parts`)
          - max_tokens is REQUIRED at the top level
          - Anthropic auto-respects extended thinking for thinking-enabled models
            via the `thinking` parameter; for the benchmark we let it run with
            default behaviour and rely on the empty-response retry escalation
            (same as Google) for any models that exhaust their visible budget.
        """
        from src.runtime.thinking_models import (
            is_thinking_model, THINKING_MODEL_MAX_TOKENS, MAX_THINKING_RETRY_CEILING,
        )

        # Fast-path: short-circuit if the Anthropic provider is currently OPEN
        if (gate := self._circuit_gate("anthropic")) is not None:
            return gate

        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        # Apply thinking-model auto-bump (same logic as Google path)
        used_max_tokens = max_tokens or self.max_tokens
        model_is_thinking = is_thinking_model(model)
        if model_is_thinking and used_max_tokens < THINKING_MODEL_MAX_TOKENS:
            self.logger.info(
                "Anthropic thinking model '%s' detected, bumping max_tokens %d -> %d",
                model, used_max_tokens, THINKING_MODEL_MAX_TOKENS,
            )
            used_max_tokens = THINKING_MODEL_MAX_TOKENS

        payload = {
            "model": model,
            "max_tokens": used_max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            payload["system"] = system_prompt
        if temperature is not None:
            payload["temperature"] = temperature
        elif self.temperature is not None:
            payload["temperature"] = self.temperature

        # Empty-response retry loop (same shape as Google path)
        attempt = 0
        max_attempts = 3
        current_max = used_max_tokens
        while attempt < max_attempts:
            attempt += 1
            print(f"[ExternalClient] Sending request to Anthropic (timeout={self.timeout}s, max_tokens={current_max}, attempt={attempt})...")
            try:
                resp = self._guarded_post("anthropic", url, headers=headers, json=payload)
                print(f"[ExternalClient] Received response: {resp.status_code}")
                resp.raise_for_status()
                data = resp.json()
            except CircuitOpenError as e:
                return f"[CIRCUIT_OPEN: {e}]"
            except Exception as e:
                print(f"[ExternalClient] Anthropic request failed: {e}")
                return f"[LLM ERROR: {e}]"

            # Extract visible text content
            content_blocks = data.get("content") or []
            visible = "".join(
                b.get("text", "") for b in content_blocks if b.get("type") == "text"
            )
            stop_reason = data.get("stop_reason")
            usage = data.get("usage", {})

            if visible.strip():
                # Optional logging
                if self.llm_logging_enabled:
                    self._log_llm_interaction("anthropic_response", {
                        "model": model,
                        "stop_reason": stop_reason,
                        "input_tokens": usage.get("input_tokens"),
                        "output_tokens": usage.get("output_tokens"),
                        "elapsed_s": (time.time() - start_time) if start_time else None,
                    })
                return visible

            # Empty response — escalate max_tokens if we haven't hit ceiling
            self.logger.warning(
                "Anthropic empty visible output (stop=%s, usage=%s). Retry %d/%d.",
                stop_reason, usage, attempt, max_attempts,
            )
            new_max = min(current_max * 2, MAX_THINKING_RETRY_CEILING)
            if new_max == current_max:
                break
            current_max = new_max
            payload["max_tokens"] = current_max

        # All retries exhausted with empty output
        from src.runtime.thinking_models import BLANK_RESPONSE_SENTINEL
        return BLANK_RESPONSE_SENTINEL

    def _generate_openai(self, prompt, model, system_prompt, temperature, max_tokens, start_time, phase=None):
        """OpenAI Chat Completions implementation.

        Targets the v1/chat/completions endpoint. Works with the standard
        OpenAI API and any OpenAI-compatible provider that respects the same
        message shape (Together, Fireworks, Groq, etc.) by setting
        EXTERNAL_BASE_URL accordingly. Reasoning models (o-series, gpt-5
        with reasoning) are detected via the thinking_models registry and
        get the same max_tokens auto-bump.
        """
        from src.runtime.thinking_models import (
            is_thinking_model, THINKING_MODEL_MAX_TOKENS, MAX_THINKING_RETRY_CEILING,
            BLANK_RESPONSE_SENTINEL,
        )

        # Fast-path: short-circuit if the OpenAI provider is currently OPEN
        if (gate := self._circuit_gate("openai")) is not None:
            return gate

        # Determine base URL — default to api.openai.com unless overridden
        base_url = getattr(self.config, 'base_url', '') or "https://api.openai.com/v1"
        base_url = base_url.rstrip('/')
        if not base_url.endswith("/chat/completions"):
            url = f"{base_url}/chat/completions"
        else:
            url = base_url

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        used_max_tokens = max_tokens or self.max_tokens
        if is_thinking_model(model) and used_max_tokens < THINKING_MODEL_MAX_TOKENS:
            self.logger.info(
                "OpenAI reasoning model '%s' detected, bumping max_tokens %d -> %d",
                model, used_max_tokens, THINKING_MODEL_MAX_TOKENS,
            )
            used_max_tokens = THINKING_MODEL_MAX_TOKENS

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
        }
        # OpenAI uses max_completion_tokens for o-series and max_tokens for chat
        if model.startswith(("o1", "o3", "o4", "o5", "gpt-5")):
            payload["max_completion_tokens"] = used_max_tokens
        else:
            payload["max_tokens"] = used_max_tokens
        if temperature is not None:
            payload["temperature"] = temperature

        attempt = 0
        max_attempts = 3
        current_max = used_max_tokens
        while attempt < max_attempts:
            attempt += 1
            print(f"[ExternalClient] Sending request to OpenAI (url={url}, max_tokens={current_max}, attempt={attempt})...")
            try:
                resp = self._guarded_post("openai", url, headers=headers, json=payload)
                print(f"[ExternalClient] Received response: {resp.status_code}")
                resp.raise_for_status()
                data = resp.json()
            except CircuitOpenError as e:
                return f"[CIRCUIT_OPEN: {e}]"
            except Exception as e:
                print(f"[ExternalClient] OpenAI request failed: {e}")
                return f"[LLM ERROR: {e}]"

            choices = data.get("choices") or []
            visible = ""
            finish_reason = None
            if choices:
                msg = choices[0].get("message") or {}
                visible = msg.get("content") or ""
                finish_reason = choices[0].get("finish_reason")

            if visible.strip():
                if self.llm_logging_enabled:
                    self._log_llm_interaction("openai_response", {
                        "model": model,
                        "finish_reason": finish_reason,
                        "usage": data.get("usage"),
                        "elapsed_s": (time.time() - start_time) if start_time else None,
                    })
                return visible

            self.logger.warning(
                "OpenAI empty visible output (finish=%s). Retry %d/%d.",
                finish_reason, attempt, max_attempts,
            )
            new_max = min(current_max * 2, MAX_THINKING_RETRY_CEILING)
            if new_max == current_max:
                break
            current_max = new_max
            if "max_completion_tokens" in payload:
                payload["max_completion_tokens"] = current_max
            else:
                payload["max_tokens"] = current_max

        return BLANK_RESPONSE_SENTINEL

    def _generate_google(self, prompt, model, system_prompt, temperature, max_tokens, start_time, phase=None):
        """Google Gemini Implementation"""

        # Fast-path: short-circuit if the Google provider is currently OPEN
        if (gate := self._circuit_gate("google")) is not None:
            return gate

        # URL Construction
        # Ensure we don't double-prefix 'models/'
        clean_model = model.replace('models/', '')
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:generateContent"
        
        # Headers
        headers = {
            'Content-Type': 'application/json',
            'X-goog-api-key': self.api_key
        }
        
        # Payload Construction
        # 1. System Instruction
        payload = {}
        if system_prompt:
            payload["system_instruction"] = {
                "parts": [{"text": system_prompt}]
            }
            
        # 2. Contents (User Prompt)
        payload["contents"] = [
            {
                "parts": [{"text": prompt}]
            }
        ]
        
        # Use the thinking-models registry to decide per-model configuration.
        # This centralizes "which models need special handling" so we don't
        # have to maintain model-name substring checks in multiple places.
        from src.runtime.thinking_models import (
            is_thinking_model, requires_thinking,
            THINKING_MODEL_MAX_TOKENS,
        )

        model_lower = clean_model.lower()
        model_is_thinking = is_thinking_model(clean_model)
        model_requires_thinking = requires_thinking(clean_model)

        # ── Auto-bump max_tokens for thinking models ──
        # Thinking tokens count against the same budget as visible output.
        # With 8k total a model that thinks for 7k only has 1k left for the
        # final answer. Bump to at least 32k for thinking models so there's
        # headroom for both deep reasoning AND a detailed response.
        effective_max = max_tokens if max_tokens is not None else self.max_tokens
        if model_is_thinking and effective_max < THINKING_MODEL_MAX_TOKENS:
            print(f"[ExternalClient] Thinking model detected ({clean_model}), "
                  f"bumping maxOutputTokens {effective_max} -> {THINKING_MODEL_MAX_TOKENS}")
            effective_max = THINKING_MODEL_MAX_TOKENS

        # 3. Generation Config
        gen_config = {
            "temperature": temperature if temperature is not None else self.temperature,
            "maxOutputTokens": effective_max,
            "topP": self.top_p,
            "topK": self.top_k
        }

        # For thinking models the API requires a thinkingConfig. For Gemini 3.x
        # specifically, thinkingBudget=0 is REJECTED ("model only works in
        # thinking mode"). Dynamic/auto (-1) is the safest setting — lets the
        # model pick its own thinking budget per-prompt based on complexity.
        if model_is_thinking and ("gemini" in model_lower):
            gen_config["thinkingConfig"] = {
                "thinkingBudget": -1,   # dynamic / auto
                "includeThoughts": False,
            }

        payload["generationConfig"] = gen_config

        # 4. Safety Settings (Disable strict filtering for security research)
        payload["safetySettings"] = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
        ]

        # 5. Disable native function calling for Gemini 3.x thinking models.
        # Gemini 3 Pro/Flash default to AUTO function-calling mode, which causes
        # the model to try emitting structured function-call payloads that get
        # truncated by the token budget and returned as empty content with
        # finishReason: MALFORMED_FUNCTION_CALL. Since Agent-G uses plain-text
        # "EXECUTE: ..." syntax instead of native function calls, we force the
        # mode to NONE so the model is required to produce plain-text output.
        if model_requires_thinking and "gemini" in model_lower:
            payload["toolConfig"] = {
                "functionCallingConfig": {
                    "mode": "NONE"
                }
            }

        try:
            # Setup retryer
            retryer = Retrying(
                stop=stop_after_attempt(self.max_retries + 1),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception(is_retryable_exception),
                reraise=True
            )
            
            # Execute request with retries. Wrapped in the circuit breaker
            # so sustained 5xx / 429 storms trip the Google circuit and stop
            # hammering the endpoint.
            def do_post():
                print(f"[ExternalClient] Sending request to Google (timeout={self.timeout}s)...")
                try:
                    resp = self._guarded_post("google", url, headers=headers, json=payload)
                    print(f"[ExternalClient] Received response: {resp.status_code}")
                    resp.raise_for_status()
                    return resp
                except CircuitOpenError:
                    # Don't retry — the circuit breaker already decided. Re-raise
                    # so Tenacity treats this as a terminal failure.
                    raise
                except Exception as e:
                    print(f"[ExternalClient] Request failed: {e}")
                    raise
                
            response = retryer(do_post)
            data = response.json()

            # Response Parsing
            def _parse_response(d):
                """Extract text, finish_reason, thoughts, and candidate tokens from a response dict.

                Gemma 4 and Gemini thinking models emit multi-part candidate
                content: one or more parts with ``"thought": true`` containing
                internal reasoning, followed by one or more visible-answer
                parts. The previous implementation grabbed only parts[0] which
                returned the THOUGHT part on these models, producing apparently
                empty visible output even when the answer was present.

                This version concatenates all non-thought text parts and
                returns that as the visible text. Thought parts are still
                counted implicitly via usageMetadata.thoughtsTokenCount for
                the empty-output retry heuristic.
                """
                cands = d.get("candidates", [])
                text = ""
                fr = "UNKNOWN"
                if cands:
                    content_ = cands[0].get("content", {})
                    parts_ = content_.get("parts", []) or []
                    visible_chunks = [
                        p.get("text", "") for p in parts_
                        if not p.get("thought", False) and p.get("text")
                    ]
                    text = "".join(visible_chunks)
                    fr = cands[0].get("finishReason", "UNKNOWN")
                um = d.get("usageMetadata", {})
                return {
                    "text": text,
                    "finish_reason": fr,
                    "thoughts_tokens": um.get("thoughtsTokenCount", 0),
                    "candidates_tokens": um.get("candidatesTokenCount", 0),
                    "prompt_tokens": um.get("promptTokenCount", 0),
                }

            parsed = _parse_response(data)
            response_text = parsed["text"]
            finish_reason = parsed["finish_reason"]

            # ── Thinking-model empty-output retry ──────────────────────────
            # Thinking models can exhaust their maxOutputTokens budget on
            # internal thought tokens and return zero visible output. Detect
            # this case and retry with 2x the budget up to a ceiling.
            #
            # The thinking-models registry identifies which models need this
            # treatment (Gemini 3.x, o1, o3, DeepSeek R1, QwQ, etc.).
            #
            # Signals of thinking-budget exhaustion:
            #   - response_text is empty
            #   - finish_reason is STOP or MAX_TOKENS (successful completion)
            #   - thoughts_tokens > 0 (model DID think, just didn't output)
            #   - OR candidates_tokens == 0 even though prompt was valid
            from src.runtime.thinking_models import MAX_THINKING_RETRY_CEILING

            THINKING_RETRY_CEILING = MAX_THINKING_RETRY_CEILING  # 131072
            MAX_THINKING_RETRIES = 2

            if (model_is_thinking and not response_text.strip()
                    and (parsed["thoughts_tokens"] > 0 or parsed["candidates_tokens"] == 0)):

                current_max = effective_max
                retry_count = 0
                while (not response_text.strip()
                       and retry_count < MAX_THINKING_RETRIES
                       and current_max < THINKING_RETRY_CEILING):
                    retry_count += 1
                    new_max = min(current_max * 2, THINKING_RETRY_CEILING)
                    print(f"[ExternalClient] Thinking model produced no visible output "
                          f"(thoughts={parsed['thoughts_tokens']}, "
                          f"candidates={parsed['candidates_tokens']}, "
                          f"finish={parsed['finish_reason']}). "
                          f"Retry {retry_count}/{MAX_THINKING_RETRIES}: "
                          f"maxOutputTokens {current_max} -> {new_max}")
                    self.logger.warning(
                        "Thinking-model empty output. Retrying with maxOutputTokens=%d (was %d). "
                        "thoughts=%d, candidates=%d",
                        new_max, current_max,
                        parsed["thoughts_tokens"], parsed["candidates_tokens"],
                    )

                    # Build retry payload with doubled budget
                    retry_payload = dict(payload)
                    retry_gen = dict(gen_config)
                    retry_gen["maxOutputTokens"] = new_max
                    # Also give thinking more room if set
                    if "thinkingConfig" in retry_gen:
                        tc = dict(retry_gen["thinkingConfig"])
                        if tc.get("thinkingBudget", 0) > 0:
                            tc["thinkingBudget"] = min(new_max // 2, tc["thinkingBudget"] * 2)
                        retry_gen["thinkingConfig"] = tc
                    retry_payload["generationConfig"] = retry_gen

                    try:
                        retry_resp = requests.post(url, headers=headers, json=retry_payload, timeout=self.timeout)
                        if retry_resp.ok:
                            retry_data = retry_resp.json()
                            parsed = _parse_response(retry_data)
                            response_text = parsed["text"]
                            finish_reason = parsed["finish_reason"]
                            data = retry_data
                            current_max = new_max
                            if response_text.strip():
                                print(f"[ExternalClient] Retry succeeded: {len(response_text)} chars, "
                                      f"thoughts={parsed['thoughts_tokens']}, "
                                      f"candidates={parsed['candidates_tokens']}")
                                self.logger.info(
                                    "Thinking-model retry succeeded: %d chars of visible output",
                                    len(response_text),
                                )
                        else:
                            print(f"[ExternalClient] Retry HTTP error: {retry_resp.status_code}")
                            break
                    except Exception as e:
                        print(f"[ExternalClient] Retry exception: {e}")
                        self.logger.warning("Thinking-model retry failed: %s", e)
                        break

                if not response_text.strip():
                    print(f"[ExternalClient] Exhausted {MAX_THINKING_RETRIES} thinking-model retries; "
                          f"model still returns empty output. Giving up on this call.")
                    self.logger.error(
                        "Thinking-model retries exhausted (final maxOutputTokens=%d). "
                        "Model continues to return empty visible output despite thinking budget scaling.",
                        current_max,
                    )
                    # Return a distinct sentinel instead of empty string so the
                    # calling runtime can distinguish "model returned blank"
                    # from "model said nothing deliberate". Downstream code can
                    # look for BLANK_RESPONSE_SENTINEL to report a clear error.
                    response_text = BLANK_RESPONSE_SENTINEL

            # ── Fallback: legacy empty-STOP prompt-hint retry ──────────────
            # For non-thinking models that return empty output with STOP, try
            # adding a hint to the prompt. This was the original retry path.
            elif not response_text.strip() and finish_reason == "STOP":
                self.logger.warning("Empty response received with STOP. Retrying with hint...")

                retry_prompt = prompt + "\n\n[SYSTEM NOTE: Your previous response was empty. If you cannot determine the next step, explain why. If the investigation is complete, respond with 'INVESTIGATION COMPLETE'.]"

                retry_payload = dict(payload)
                retry_payload["contents"] = [{"parts": [{"text": retry_prompt}]}]

                try:
                    retry_resp = requests.post(url, headers=headers, json=retry_payload, timeout=self.timeout)
                    if retry_resp.ok:
                        retry_data = retry_resp.json()
                        parsed = _parse_response(retry_data)
                        if parsed["text"]:
                            response_text = parsed["text"]
                            finish_reason = parsed["finish_reason"]
                            data = retry_data
                            self.logger.info(f"Prompt-hint retry successful, got {len(response_text)} chars")
                except Exception as e:
                    self.logger.warning("Prompt-hint retry failed: %s", e)
            
            # Log interaction
            if self.llm_logging_enabled:
                log_data = {
                    'model': clean_model,
                    'method': 'generate',
                    'status': 'success',
                    'phase': phase
                }
                if self.llm_log_prompts:
                    log_data['prompt'] = prompt
                    log_data['system_prompt'] = system_prompt
                if self.llm_log_responses:
                    log_data['response'] = response_text
                
                # Token usage metadata
                usage = data.get("usageMetadata", {})
                
                log_data['finish_reason'] = finish_reason

                if self.llm_log_tokens:
                    log_data['tokens'] = {
                        'prompt_token_count': usage.get("promptTokenCount", 0),
                        'candidates_token_count': usage.get("candidatesTokenCount", 0),
                        'total_token_count': usage.get("totalTokenCount", 0)
                    }
                
                if self.llm_log_timing and start_time:
                    log_data['timing'] = {'total_duration_seconds': time.time() - start_time}
                    
                self._log_llm_interaction('generate', log_data)
                
            return response_text

        except requests.exceptions.RequestException as e:
            # Extract detailed error info from response body if available
            error_detail = str(e)
            prompt_size = len(prompt) if prompt else 0
            system_size = len(system_prompt) if system_prompt else 0
            
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_body = e.response.text
                    error_detail = f"{str(e)} | Response: {error_body[:1000]}"
                except:
                    pass
                    
            self.logger.error(f"Error calling External API (Google): {error_detail}")
            self.logger.error(f"Request sizes - prompt: {prompt_size:,} chars, system: {system_size:,} chars, total: {prompt_size + system_size:,} chars")
            
            if self.llm_logging_enabled:
                self._log_llm_interaction('generate', {
                    'model': model,
                    'status': 'error',
                    'error': error_detail,
                    'prompt_chars': prompt_size,
                    'system_chars': system_size
                })
            raise
            
    def generate_with_phase(self,
                          prompt: str,
                          phase: Optional[str] = None,
                          system_prompt: Optional[str] = None) -> str:
        """Generate using phase-specific model configuration."""
        model = self.model_map.get(phase) if phase else None
        
        # Defensive Check: Validate model against provider
        if self.provider == 'google':
             if model and not (model.lower().startswith("gemini") or model.lower().startswith("learnlm")):
                  self.logger.warning(f"Ignoring invalid model '{model}' for Google provider. Using default.")
                  model = None
                  
        return self.generate(prompt=prompt, model=model, system_prompt=system_prompt, phase=phase)
    
    def embed(self, text: str, model: str = None) -> List[float]:
        """
        Generate embeddings.
        """
        start_time = time.time() if self.llm_log_timing else None
        
        # Request Delay
        if self.request_delay > 0:
            self.logger.debug(f"Sleeping for {self.request_delay}s before request")
            time.sleep(self.request_delay)
            
        used_model = model or self.embedding_model
        
        if self.provider == 'google':
             # Use chunking strategy
             if len(text) > 8000:
                  return self._embed_chunked(text, used_model, start_time)
             return self._embed_single_google(text, used_model, start_time)
        else:
             self.logger.error("Embeddings not implemented for this provider yet.")
             return []

    def _embed_chunked(self, text: str, embedding_model: str, start_time: Optional[float]) -> List[float]:
        chunks = chunk_text_for_embedding(text, max_chars=8000)
        chunk_embeddings = []
        for chunk in chunks:
            try:
                # Dispatch based on provider
                if self.provider == 'google':
                    emb = self._embed_single_google(chunk, embedding_model, None)
                else:
                    emb = []
                    
                if emb:
                    chunk_embeddings.append(emb)
            except Exception as e:
                self.logger.error(f"Failed to embed chunk: {e}")
                
        if not chunk_embeddings:
            return []
            
        return average_embeddings(chunk_embeddings)

    def _embed_single_google(self, text: str, embedding_model: str, start_time: Optional[float]) -> List[float]:
        if not text.strip():
            return []
            
        clean_model = embedding_model.replace('models/', '')
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:embedContent"
        
        headers = {
            'Content-Type': 'application/json',
            'X-goog-api-key': self.api_key
        }
        
        payload = {
            "content": {
                "parts": [{"text": text}]
            },
            "model": f"models/{clean_model}" # Redundant but safe
        }
        
        try:
            # Setup retryer
            retryer = Retrying(
                stop=stop_after_attempt(self.max_retries + 1),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception(is_retryable_exception),
                reraise=True
            )
            
            # Execute request with retries
            def do_post():
                resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
                resp.raise_for_status()
                return resp
                
            response = retryer(do_post)
            
            data = response.json()
            embedding = data.get("embedding", {}).get("values", [])
            
            if self.llm_logging_enabled:
                self._log_llm_interaction('embed', {
                    'model': embedding_model,
                    'status': 'success',
                    'embedding_dim': len(embedding)
                })
                
            return embedding
        except Exception as e:
            self.logger.error(f"Error calling External Embed API: {e}")
            raise

    def check_health(self) -> bool:
        try:
            # Simple check - list models if possible, or just assume true if instantiated
             if self.provider == 'google':
                 # Try a lightweight call or just return True if API key valid format
                 return bool(self.api_key)
             return True
        except:
            return False
