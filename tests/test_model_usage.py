from __future__ import annotations

from types import SimpleNamespace

import pytest

from paca.integrations.model_usage import OpenAIUsageRecorder


class _Completions:
    def __init__(self, create):
        self.create = create


class _Client:
    def __init__(self, completions):
        self.chat = SimpleNamespace(completions=completions)


class _Element:
    def __init__(self, client=None, elements=()):
        if client is not None:
            self.client = client
        self.elements = list(elements)


def test_openai_usage_recorder_collects_usage_and_does_not_store_content():
    response = SimpleNamespace(
        model="test-model",
        usage=SimpleNamespace(
            prompt_tokens=120,
            completion_tokens=30,
            total_tokens=150,
            prompt_tokens_details=SimpleNamespace(cached_tokens=20),
            completion_tokens_details=SimpleNamespace(reasoning_tokens=8),
        ),
        choices=[SimpleNamespace(message=SimpleNamespace(content="sensitive response"))],
    )
    completions = _Completions(lambda **_kwargs: response)
    pipeline = _Element(
        elements=[_Element(client=_Client(completions))]
    )
    recorder = OpenAIUsageRecorder("paca_plus_plus")

    assert recorder.instrument_pipeline(pipeline) == 1
    returned = completions.create(model="test-model", messages=[{"content": "secret"}])

    assert returned is response
    snapshot = recorder.snapshot()
    assert snapshot["condition"] == "paca_plus_plus"
    assert snapshot["instrumented_openai_clients"] == 1
    assert snapshot["logical_sdk_request_attempts"] == 1
    assert snapshot["successful_responses"] == 1
    assert snapshot["failed_requests"] == 0
    assert snapshot["responses_with_usage"] == 1
    assert snapshot["input_tokens"] == 120
    assert snapshot["output_tokens"] == 30
    assert snapshot["total_tokens"] == 150
    assert snapshot["cached_input_tokens"] == 20
    assert snapshot["reasoning_output_tokens"] == 8
    assert snapshot["models_observed"] == ["test-model"]
    assert "sensitive response" not in repr(snapshot)
    assert "secret" not in repr(snapshot)
    assert "dollar cost" in snapshot["measurement_qualification"]


def test_openai_usage_recorder_counts_missing_usage_without_inventing_tokens():
    completions = _Completions(
        lambda **_kwargs: SimpleNamespace(model="local-model", usage=None)
    )
    recorder = OpenAIUsageRecorder("agentdojo_no_defense")
    recorder.instrument_pipeline(_Element(client=_Client(completions)))

    completions.create()

    snapshot = recorder.snapshot()
    assert snapshot["successful_responses"] == 1
    assert snapshot["responses_without_usage"] == 1
    assert snapshot["input_tokens"] == 0
    assert snapshot["output_tokens"] == 0
    assert snapshot["total_tokens"] == 0
    assert snapshot["usage_capture_status"] == "partial_or_provider_did_not_return_usage"


def test_openai_usage_recorder_propagates_provider_failure_and_counts_it():
    def fail(**_kwargs):
        raise TimeoutError("provider unavailable")

    completions = _Completions(fail)
    recorder = OpenAIUsageRecorder("agentdojo_tool_filter")
    recorder.instrument_pipeline(_Element(client=_Client(completions)))

    with pytest.raises(TimeoutError, match="provider unavailable"):
        completions.create()

    snapshot = recorder.snapshot()
    assert snapshot["logical_sdk_request_attempts"] == 1
    assert snapshot["successful_responses"] == 0
    assert snapshot["failed_requests"] == 1
    assert snapshot["input_tokens"] == 0
    assert snapshot["usage_capture_status"] == "no_successful_responses"


def test_openai_usage_recorder_deduplicates_shared_clients_in_nested_pipeline():
    completions = _Completions(
        lambda **_kwargs: SimpleNamespace(
            model="test-model",
            usage=SimpleNamespace(prompt_tokens=1, completion_tokens=2, total_tokens=3),
        )
    )
    shared_client = _Client(completions)
    child = _Element(client=shared_client)
    pipeline = _Element(elements=[child, _Element(elements=[child])])
    recorder = OpenAIUsageRecorder("shared")

    assert recorder.instrument_pipeline(pipeline) == 1
    assert recorder.instrument_pipeline(pipeline) == 0
    completions.create()

    snapshot = recorder.snapshot()
    assert snapshot["instrumented_openai_clients"] == 1
    assert snapshot["logical_sdk_request_attempts"] == 1
    assert snapshot["total_tokens"] == 3
