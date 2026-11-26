from __future__ import annotations

import pytest

from paca.integrations.agentdojo_load import (
    _aggregate_token_usage,
    _condition_episode_metrics,
    _csv_ids,
    _observed_peak_concurrency,
    run_concurrent_agentdojo_load,
)


def test_condition_episode_metrics_aggregate_replicates_and_keep_indeterminate_separate():
    workers = [
        {
            "task_results": [
                {
                    "benign": {
                        "duration_seconds": {"paca_plus_plus": 1.0},
                        "error": {"paca_plus_plus": None},
                    },
                    "attacked_pairs": [
                        {
                            "conditions": {
                                "paca_plus_plus": {
                                    "duration_seconds": 2.0,
                                    "error": None,
                                    "indeterminate_reason": "missing_message_trace",
                                }
                            }
                        }
                    ],
                }
            ]
        },
        {
            "task_results": [
                {
                    "benign": {
                        "duration_seconds": {"paca_plus_plus": 1.5},
                        "error": {"paca_plus_plus": "timeout"},
                    },
                    "attacked_pairs": [],
                }
            ]
        },
    ]

    result = _condition_episode_metrics(workers, "paca_plus_plus")

    assert result["attempted_episodes"] == 3
    assert result["timed_episodes"] == 3
    assert result["error_count"] == 1
    assert result["indeterminate_attack_pairs"] == 1
    assert result["error_free_episode_fraction"] == pytest.approx(2 / 3)
    assert result["episode_latency_seconds"]["p50"] == 1.5
    assert result["episode_latency_seconds"]["p95"] == 2.0


def test_token_usage_aggregation_sums_per_condition_without_calculating_cost():
    workers = [
        {
            "summary": {
                "model_usage_by_condition": {
                    "paca_plus_plus": {
                        "logical_sdk_request_attempts": 4,
                        "successful_responses": 3,
                        "failed_requests": 1,
                        "responses_with_usage": 2,
                        "responses_without_usage": 1,
                        "input_tokens": 100,
                        "output_tokens": 40,
                        "total_tokens": 140,
                        "cached_input_tokens": 10,
                        "reasoning_output_tokens": 5,
                        "models_observed": ["gpt-test"],
                    }
                }
            }
        },
        {
            "summary": {
                "model_usage_by_condition": {
                    "paca_plus_plus": {
                        "logical_sdk_request_attempts": 2,
                        "successful_responses": 2,
                        "failed_requests": 0,
                        "responses_with_usage": 2,
                        "responses_without_usage": 0,
                        "input_tokens": 200,
                        "output_tokens": 80,
                        "total_tokens": 280,
                        "cached_input_tokens": 20,
                        "reasoning_output_tokens": 10,
                        "models_observed": ["gpt-test", "gpt-test-variant"],
                    }
                }
            }
        },
    ]

    result = _aggregate_token_usage(workers)["paca_plus_plus"]

    assert result["logical_sdk_request_attempts"] == 6
    assert result["successful_responses"] == 5
    assert result["failed_requests"] == 1
    assert result["input_tokens"] == 300
    assert result["output_tokens"] == 120
    assert result["total_tokens"] == 420
    assert result["cached_input_tokens"] == 30
    assert result["reasoning_output_tokens"] == 15
    assert result["models_observed"] == ["gpt-test", "gpt-test-variant"]
    assert result["dollar_cost_usd"] is None


def test_observed_peak_concurrency_counts_a_worker_starting_at_zero():
    workers = [
        {"start_offset_seconds": 0.0, "duration_seconds": 2.0},
        {"start_offset_seconds": 0.5, "duration_seconds": 1.5},
        {"start_offset_seconds": 2.0, "duration_seconds": 0.5},
    ]

    assert _observed_peak_concurrency(workers) == 2


def test_observed_peak_concurrency_does_not_count_adjacent_workers_as_overlapping():
    workers = [
        {"start_offset_seconds": 0.0, "duration_seconds": 1.0},
        {"start_offset_seconds": 1.0, "duration_seconds": 1.0},
    ]

    assert _observed_peak_concurrency(workers) == 1


def test_csv_ids_rejects_duplicates_and_empty_values():
    assert _csv_ids("task-a, task-b") == ["task-a", "task-b"]
    with pytest.raises(ValueError, match="duplicate"):
        _csv_ids("task-a,task-a")
    with pytest.raises(ValueError, match="non-empty"):
        _csv_ids(" , ")


def test_live_load_runner_requires_cost_acknowledgement_before_starting(tmp_path):
    output_root = tmp_path / "load-run"

    with pytest.raises(ValueError, match="cost acknowledgement"):
        run_concurrent_agentdojo_load(
            suite="workspace",
            suite_version="v1.2.2",
            user_task_ids=["task-a"],
            injection_task_ids=["injection-a"],
            model="gpt-test",
            model_id=None,
            attack="tool_knowledge",
            max_iters=5,
            repetitions=2,
            concurrency=2,
            timeout_seconds=30,
            output_root=output_root,
            acknowledge_provider_costs=False,
        )

    assert not output_root.exists()


def test_live_load_runner_refuses_to_start_without_protected_openai_credential(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    output_root = tmp_path / "load-run"

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        run_concurrent_agentdojo_load(
            suite="workspace",
            suite_version="v1.2.2",
            user_task_ids=["task-a"],
            injection_task_ids=["injection-a"],
            model="gpt-test",
            model_id=None,
            attack="tool_knowledge",
            max_iters=5,
            repetitions=2,
            concurrency=2,
            timeout_seconds=30,
            output_root=output_root,
            acknowledge_provider_costs=True,
        )

    assert not output_root.exists()
