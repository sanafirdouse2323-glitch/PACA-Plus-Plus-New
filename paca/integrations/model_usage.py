"""Privacy-preserving token-usage and request-latency instrumentation.

The recorder wraps OpenAI-compatible Chat Completions clients discovered inside
an AgentDojo pipeline. It records usage counters and timing only; it never
stores prompts, completions, tool arguments, headers, credentials or raw
responses. One call to the SDK's create() method is one logical request; any
internal HTTP retries performed by the SDK are not separately observable here.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any


def _field(value: object, name: str) -> object | None:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return round(ordered[index], 6)


class OpenAIUsageRecorder:
    """Collect token usage and latency from OpenAI-compatible pipeline clients."""

    def __init__(self, condition: str) -> None:
        if not isinstance(condition, str) or not condition:
            raise ValueError("condition must be a non-empty string")
        self.condition = condition
        self._lock = threading.Lock()
        self._instrumented_completion_ids: set[int] = set()
        self._instrumented_clients = 0
        self._request_attempts = 0
        self._successful_responses = 0
        self._failed_requests = 0
        self._responses_with_usage = 0
        self._responses_without_usage = 0
        self._input_tokens = 0
        self._output_tokens = 0
        self._total_tokens = 0
        self._cached_input_tokens = 0
        self._reasoning_output_tokens = 0
        self._latencies: list[float] = []
        self._models: set[str] = set()

    def instrument_pipeline(self, pipeline: object) -> int:
        """Wrap every unique OpenAI-compatible client found in pipeline elements."""
        stack = [pipeline]
        visited: set[int] = set()
        instrumented = 0
        while stack:
            element = stack.pop()
            element_id = id(element)
            if element_id in visited:
                continue
            visited.add(element_id)

            children = getattr(element, "elements", None)
            if isinstance(children, Sequence) and not isinstance(
                children, (str, bytes, bytearray)
            ):
                stack.extend(children)

            client = getattr(element, "client", None)
            chat = getattr(client, "chat", None)
            completions = getattr(chat, "completions", None)
            if completions is None:
                continue
            create = getattr(completions, "create", None)
            if not callable(create):
                continue
            completion_id = id(completions)
            if completion_id in self._instrumented_completion_ids:
                continue
            self._wrap_completion_create(completions, create)
            self._instrumented_completion_ids.add(completion_id)
            instrumented += 1

        with self._lock:
            self._instrumented_clients += instrumented
        return instrumented

    def _wrap_completion_create(self, completions: object, original_create: Any) -> None:
        def measured_create(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            with self._lock:
                self._request_attempts += 1
            try:
                response = original_create(*args, **kwargs)
            except Exception:
                elapsed = time.perf_counter() - started
                with self._lock:
                    self._failed_requests += 1
                    if math.isfinite(elapsed) and elapsed >= 0:
                        self._latencies.append(elapsed)
                raise

            elapsed = time.perf_counter() - started
            usage = _field(response, "usage")
            input_tokens = _non_negative_int(
                _field(usage, "prompt_tokens")
                if _field(usage, "prompt_tokens") is not None
                else _field(usage, "input_tokens")
            )
            output_tokens = _non_negative_int(
                _field(usage, "completion_tokens")
                if _field(usage, "completion_tokens") is not None
                else _field(usage, "output_tokens")
            )
            total_tokens = _non_negative_int(_field(usage, "total_tokens"))
            prompt_details = _field(usage, "prompt_tokens_details")
            completion_details = _field(usage, "completion_tokens_details")
            cached_tokens = _non_negative_int(_field(prompt_details, "cached_tokens"))
            reasoning_tokens = _non_negative_int(
                _field(completion_details, "reasoning_tokens")
            )
            model = _field(response, "model")
            model_name = model if isinstance(model, str) and model else None

            with self._lock:
                self._successful_responses += 1
                if usage is None or (
                    input_tokens is None
                    and output_tokens is None
                    and total_tokens is None
                ):
                    self._responses_without_usage += 1
                else:
                    self._responses_with_usage += 1
                if input_tokens is not None:
                    self._input_tokens += input_tokens
                if output_tokens is not None:
                    self._output_tokens += output_tokens
                if total_tokens is not None:
                    self._total_tokens += total_tokens
                if cached_tokens is not None:
                    self._cached_input_tokens += cached_tokens
                if reasoning_tokens is not None:
                    self._reasoning_output_tokens += reasoning_tokens
                if model_name is not None:
                    self._models.add(model_name)
                if math.isfinite(elapsed) and elapsed >= 0:
                    self._latencies.append(elapsed)
            return response

        try:
            setattr(completions, "create", measured_create)
        except (AttributeError, TypeError) as exc:
            raise RuntimeError(
                "OpenAI-compatible completion client does not allow usage instrumentation"
            ) from exc

    def snapshot(self) -> dict[str, Any]:
        """Return aggregate usage metadata without exposing model input/output data."""
        with self._lock:
            attempts = self._request_attempts
            successes = self._successful_responses
            with_usage = self._responses_with_usage
            without_usage = self._responses_without_usage
            latencies = list(self._latencies)
            return {
                "condition": self.condition,
                "instrumented_openai_clients": self._instrumented_clients,
                "logical_sdk_request_attempts": attempts,
                "successful_responses": successes,
                "failed_requests": self._failed_requests,
                "responses_with_usage": with_usage,
                "responses_without_usage": without_usage,
                "input_tokens": self._input_tokens,
                "output_tokens": self._output_tokens,
                "total_tokens": self._total_tokens,
                "cached_input_tokens": self._cached_input_tokens,
                "reasoning_output_tokens": self._reasoning_output_tokens,
                "models_observed": sorted(self._models),
                "request_latency_seconds": {
                    "p50": _percentile(latencies, 0.50),
                    "p95": _percentile(latencies, 0.95),
                    "p99": _percentile(latencies, 0.99),
                },
                "usage_capture_status": (
                    "no_successful_responses"
                    if successes == 0
                    else "complete_for_successful_responses"
                    if without_usage == 0
                    else "partial_or_provider_did_not_return_usage"
                ),
                "measurement_qualification": (
                    "Counts successful SDK responses that expose provider usage fields. "
                    "One create() call is one logical SDK request; HTTP retries performed "
                    "inside the SDK are not separately counted. Prompts, completions, "
                    "tool arguments, headers and credentials are not stored. Token counts "
                    "are not dollar cost; cost requires the provider's dated billing rates "
                    "and all applicable cached/reasoning/discount dimensions."
                ),
            }


__all__ = ["OpenAIUsageRecorder"]
