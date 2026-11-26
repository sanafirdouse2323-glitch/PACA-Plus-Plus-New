"""Opt-in concurrent AgentDojo load runner with isolated worker processes.

This module never starts a live run without an explicit cost acknowledgement
and a configured OpenAI credential. Each replicate receives a unique AgentDojo
log directory and result file. The runner records process/load metrics and
aggregates per-condition episode and token counters without persisting model
prompts, completions, headers or credentials.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CONDITIONS = (
    "agentdojo_no_defense",
    "agentdojo_tool_filter",
    "paca_plus_plus",
)
TOKEN_FIELDS = (
    "logical_sdk_request_attempts",
    "successful_responses",
    "failed_requests",
    "responses_with_usage",
    "responses_without_usage",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
    "reasoning_output_tokens",
)


def _csv_ids(value: str) -> list[str]:
    items = [part.strip() for part in value.split(",") if part.strip()]
    if not items:
        raise ValueError("provide a non-empty comma-separated ID list")
    if len(items) != len(set(items)):
        raise ValueError("duplicate IDs are not allowed")
    return items


def _duration(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) and number > 0 else None


def _nearest_rank(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return round(ordered[index], 6)


def _condition_episode_metrics(
    worker_results: list[dict[str, Any]], condition: str
) -> dict[str, Any]:
    durations: list[float] = []
    attempted = 0
    errors = 0
    indeterminate = 0
    for result in worker_results:
        for task in result.get("task_results", []):
            benign = task.get("benign", {})
            if isinstance(benign, dict):
                attempted += 1
                duration_map = benign.get("duration_seconds", {})
                error_map = benign.get("error", {})
                value = _duration(duration_map.get(condition)) if isinstance(duration_map, dict) else None
                if value is not None:
                    durations.append(value)
                errors += int(
                    isinstance(error_map, dict) and error_map.get(condition) is not None
                )
            for pair in task.get("attacked_pairs", []):
                record = pair.get("conditions", {}).get(condition)
                if not isinstance(record, dict):
                    continue
                attempted += 1
                value = _duration(record.get("duration_seconds"))
                if value is not None:
                    durations.append(value)
                errors += int(record.get("error") is not None)
                indeterminate += int(record.get("indeterminate_reason") is not None)

    return {
        "attempted_episodes": attempted,
        "timed_episodes": len(durations),
        "episodes_without_timing": attempted - len(durations),
        "error_count": errors,
        "indeterminate_attack_pairs": indeterminate,
        "error_free_episode_fraction": (
            round((attempted - errors) / attempted, 6) if attempted else None
        ),
        "episode_latency_seconds": {
            "p50": _nearest_rank(durations, 0.50),
            "p95": _nearest_rank(durations, 0.95),
            "p99": _nearest_rank(durations, 0.99),
        },
        "throughput_qualification": (
            "Episode timings from independent worker results; aggregate throughput "
            "uses attempted episodes divided by outer wall-clock duration. This is "
            "not an SLA or a general production-capacity guarantee."
        ),
    }


def _aggregate_token_usage(worker_results: list[dict[str, Any]]) -> dict[str, Any]:
    aggregates = {
        condition: {field: 0 for field in TOKEN_FIELDS}
        for condition in CONDITIONS
    }
    models: dict[str, set[str]] = {condition: set() for condition in CONDITIONS}
    workers_with_usage = {condition: 0 for condition in CONDITIONS}
    workers_without_usage = {condition: 0 for condition in CONDITIONS}
    for result in worker_results:
        summary = result.get("summary", {})
        by_condition = summary.get("model_usage_by_condition", {})
        if not isinstance(by_condition, dict):
            continue
        for condition in CONDITIONS:
            usage = by_condition.get(condition)
            if not isinstance(usage, dict):
                continue
            for field in TOKEN_FIELDS:
                value = usage.get(field, 0)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    aggregates[condition][field] += value
            seen_models = usage.get("models_observed", [])
            if isinstance(seen_models, list):
                models[condition].update(
                    item for item in seen_models if isinstance(item, str) and item
                )
            if usage.get("responses_with_usage", 0) > 0:
                workers_with_usage[condition] += 1
            if usage.get("responses_without_usage", 0) > 0:
                workers_without_usage[condition] += 1

    return {
        condition: {
            **aggregates[condition],
            "models_observed": sorted(models[condition]),
            "workers_with_usage_fields": workers_with_usage[condition],
            "workers_with_missing_usage_fields": workers_without_usage[condition],
            "dollar_cost_usd": None,
            "cost_qualification": (
                "Token usage is not dollar cost. Join the provider's dated billing "
                "schedule/export, including cached/reasoning token treatment and "
                "account-specific adjustments, before estimating charges."
            ),
        }
        for condition in CONDITIONS
    }


def _observed_peak_concurrency(workers: list[dict[str, Any]]) -> int:
    events: list[tuple[float, int]] = []
    for worker in workers:
        start = _duration(worker.get("start_offset_seconds"))
        duration = _duration(worker.get("duration_seconds"))
        if start is None or duration is None:
            continue
        events.append((start, 1))
        events.append((start + duration, -1))
    active = 0
    peak = 0
    # End events precede start events at identical times; adjacent runs do not
    # count as overlapping.
    for _instant, delta in sorted(events, key=lambda item: (item[0], item[1])):
        active += delta
        peak = max(peak, active)
    return peak


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    temporary.replace(path)


def _benchmark_command(
    *,
    suite: str,
    suite_version: str,
    user_tasks: list[str],
    injection_tasks: list[str],
    model: str,
    model_id: str | None,
    attack: str,
    max_iters: int,
    log_dir: Path | None = None,
    output_path: Path | None = None,
    dry_run: bool = False,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "paca.integrations.agentdojo_benchmark",
        "--suite-version",
        suite_version,
        "--suite",
        suite,
        "--user-tasks",
        ",".join(user_tasks),
        "--injection-tasks",
        ",".join(injection_tasks),
        "--model",
        model,
        "--attack",
        attack,
        "--max-iters",
        str(max_iters),
    ]
    if model_id:
        command.extend(["--model-id", model_id])
    if log_dir is not None:
        command.extend(["--log-dir", str(log_dir)])
    if output_path is not None:
        command.extend(["--output", str(output_path)])
    if dry_run:
        command.append("--dry-run")
    return command


def run_concurrent_agentdojo_load(
    *,
    suite: str,
    suite_version: str,
    user_task_ids: list[str],
    injection_task_ids: list[str],
    model: str,
    model_id: str | None,
    attack: str,
    max_iters: int,
    repetitions: int,
    concurrency: int,
    timeout_seconds: int,
    output_root: Path,
    acknowledge_provider_costs: bool,
) -> dict[str, Any]:
    """Preflight, then run independent, concurrent AgentDojo benchmark processes."""
    if not acknowledge_provider_costs:
        raise ValueError(
            "live load runs require explicit provider-cost acknowledgement"
        )
    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError(
            "OPENAI_API_KEY is not configured; no live load workers were started"
        )
    if not 1 <= repetitions <= 64:
        raise ValueError("repetitions must be between 1 and 64")
    if not 1 <= concurrency <= min(repetitions, 16):
        raise ValueError("concurrency must be between 1 and min(repetitions, 16)")
    if not 1 <= timeout_seconds <= 7200:
        raise ValueError("timeout_seconds must be between 1 and 7200")
    if not 1 <= max_iters <= 100:
        raise ValueError("max_iters must be between 1 and 100")
    if len(set(user_task_ids)) != len(user_task_ids) or not user_task_ids:
        raise ValueError("user task IDs must be non-empty and unique")
    if len(set(injection_task_ids)) != len(injection_task_ids) or not injection_task_ids:
        raise ValueError("injection task IDs must be non-empty and unique")

    root = output_root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=False)
    base_command = _benchmark_command(
        suite=suite,
        suite_version=suite_version,
        user_tasks=user_task_ids,
        injection_tasks=injection_task_ids,
        model=model,
        model_id=model_id,
        attack=attack,
        max_iters=max_iters,
    )

    # Validate suite/task/attack compatibility without a provider request before
    # any concurrent worker is spawned.
    preflight = subprocess.run(
        [*base_command, "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
        timeout=min(timeout_seconds, 300),
    )
    if preflight.returncode != 0:
        raise RuntimeError(
            "AgentDojo dry-run preflight failed; no live workers were started "
            f"(exit code {preflight.returncode})"
        )
    try:
        preflight_data = json.loads(preflight.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "AgentDojo dry-run did not return valid JSON; no live workers were started"
        ) from exc
    if not isinstance(preflight_data, dict) or preflight_data.get("status") != "dry_run":
        raise RuntimeError("AgentDojo dry-run response was invalid; no live workers were started")
    applicable_by_task = preflight_data.get(
        "applicable_injection_task_ids_by_user_task", {}
    )
    if not isinstance(applicable_by_task, dict):
        raise RuntimeError("AgentDojo dry-run omitted the applicable attack matrix")
    applicable_pair_count = sum(
        len(ids) for ids in applicable_by_task.values() if isinstance(ids, list)
    )
    if applicable_pair_count < 1:
        raise RuntimeError("AgentDojo preflight found no applicable attack pairs")

    started_at = datetime.now(timezone.utc).isoformat()
    run_started = time.perf_counter()
    worker_results: list[dict[str, Any]] = []

    def execute_worker(index: int) -> dict[str, Any]:
        worker_dir = root / f"worker-{index:03d}"
        log_dir = worker_dir / "agentdojo-logs"
        output_path = worker_dir / "result.json"
        log_dir.mkdir(parents=True, exist_ok=False)
        command = _benchmark_command(
            suite=suite,
            suite_version=suite_version,
            user_tasks=user_task_ids,
            injection_tasks=injection_task_ids,
            model=model,
            model_id=model_id,
            attack=attack,
            max_iters=max_iters,
            log_dir=log_dir,
            output_path=output_path,
        )
        worker_start = time.perf_counter()
        record: dict[str, Any] = {
            "worker_id": index,
            "start_offset_seconds": round(worker_start - run_started, 6),
            "status": "running",
            "return_code": None,
            "failure_type": None,
            "result_file": str(output_path),
        }
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds,
            )
            record["return_code"] = completed.returncode
            if output_path.exists():
                try:
                    payload = json.loads(output_path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    payload = None
                if isinstance(payload, dict):
                    record["failure_type"] = payload.get("failure_type")
                    record["status"] = (
                        "completed"
                        if completed.returncode == 0 and payload.get("status") == "completed"
                        else "failed"
                    )
            if record["status"] == "running":
                record["status"] = "completed" if completed.returncode == 0 else "failed"
            # Intentionally discard stdout/stderr. Provider exception text and
            # logs may contain user content or sensitive request metadata.
        except subprocess.TimeoutExpired:
            record["status"] = "timed_out"
            record["failure_type"] = "TimeoutExpired"
        except OSError as exc:
            record["status"] = "failed"
            record["failure_type"] = type(exc).__name__
        worker_end = time.perf_counter()
        record["duration_seconds"] = round(worker_end - worker_start, 6)
        return record

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(execute_worker, index) for index in range(1, repetitions + 1)]
        for future in as_completed(futures):
            worker_results.append(future.result())
    worker_results.sort(key=lambda item: item["worker_id"])
    wall_clock = time.perf_counter() - run_started

    completed_payloads: list[dict[str, Any]] = []
    for worker in worker_results:
        result_file = Path(worker["result_file"])
        if result_file.exists():
            try:
                payload = json.loads(result_file.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict) and payload.get("status") == "completed":
                completed_payloads.append(payload)

    condition_metrics = {
        condition: _condition_episode_metrics(completed_payloads, condition)
        for condition in CONDITIONS
    }
    token_metrics = _aggregate_token_usage(completed_payloads)
    attempted_episodes = sum(
        item["attempted_episodes"] for item in condition_metrics.values()
    )
    successful_workers = sum(item["status"] == "completed" for item in worker_results)
    failed_workers = sum(item["status"] == "failed" for item in worker_results)
    timed_out_workers = sum(item["status"] == "timed_out" for item in worker_results)

    result = {
        "schema_version": "1.0.0",
        "status": (
            "completed"
            if successful_workers == repetitions and wall_clock > 0
            else "completed_with_worker_failures"
        ),
        "evidence": {
            "class": "R",
            "experiment_type": "concurrent_model_in_loop_agentdojo_load",
            "model_in_loop": True,
            "live_vendor_security_products_tested": False,
            "execution_status": (
                "completed" if successful_workers == repetitions else "partial_or_failed"
            ),
            "preflight_completed": True,
        },
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "configuration": {
            "suite": suite,
            "suite_version": suite_version,
            "user_task_ids": user_task_ids,
            "injection_task_ids": injection_task_ids,
            "model": model,
            "model_id": model_id,
            "attack": attack,
            "max_iters": max_iters,
            "repetitions": repetitions,
            "requested_concurrency": concurrency,
            "timeout_seconds_per_worker": timeout_seconds,
            "applicable_attack_pairs_per_repetition": applicable_pair_count,
            "conditions": list(CONDITIONS),
        },
        "preflight": {
            "status": "passed",
            "applicable_attack_pairs_per_repetition": applicable_pair_count,
            "skipped_attack_pairs": preflight_data.get("skipped_attack_pairs", []),
        },
        "workers": worker_results,
        "summary": {
            "successful_workers": successful_workers,
            "failed_workers": failed_workers,
            "timed_out_workers": timed_out_workers,
            "worker_completion_fraction": round(
                successful_workers / repetitions, 6
            ),
            "observed_peak_concurrent_workers": _observed_peak_concurrency(
                worker_results
            ),
            "overall_wall_clock_seconds": round(wall_clock, 6),
            "attempted_condition_episodes": attempted_episodes,
            "attempted_condition_episodes_per_wall_clock_second": (
                round(attempted_episodes / wall_clock, 6) if wall_clock > 0 else None
            ),
            "episode_metrics_by_condition": condition_metrics,
            "model_usage_by_condition": token_metrics,
            "provider_cost_usd": None,
            "throughput_qualification": (
                "Short-run measured aggregate across separate worker processes, "
                "three conditions and the selected AgentDojo workspace tasks. It is "
                "not a service SLA or general deployment capacity guarantee."
            ),
            "availability_qualification": (
                "Worker completion fraction for this bounded load run only; it is not "
                "long-term service availability, recovery time or a production SLA."
            ),
        },
    }
    result_path = root / "concurrent-load-results.json"
    _atomic_write(result_path, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run explicitly acknowledged concurrent AgentDojo benchmark replicas."
    )
    parser.add_argument("--suite", default="workspace", choices=["workspace"])
    parser.add_argument("--suite-version", default="v1.2.2")
    parser.add_argument("--user-tasks", required=True)
    parser.add_argument("--injection-tasks", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-id")
    parser.add_argument("--attack", default="tool_knowledge")
    parser.add_argument("--max-iters", type=int, default=15)
    parser.add_argument("--repetitions", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--confirm-provider-costs",
        action="store_true",
        help="Acknowledge that concurrent model replicas may incur provider charges.",
    )
    args = parser.parse_args(argv)
    try:
        result = run_concurrent_agentdojo_load(
            suite=args.suite,
            suite_version=args.suite_version,
            user_task_ids=_csv_ids(args.user_tasks),
            injection_task_ids=_csv_ids(args.injection_tasks),
            model=args.model,
            model_id=args.model_id,
            attack=args.attack,
            max_iters=args.max_iters,
            repetitions=args.repetitions,
            concurrency=args.concurrency,
            timeout_seconds=args.timeout_seconds,
            output_root=args.output_root,
            acknowledge_provider_costs=args.confirm_provider_costs,
        )
    except Exception as exc:  # noqa: BLE001 - surface safe exception type only.
        parser.exit(2, f"load benchmark failed ({type(exc).__name__})\n")
    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    print(f"Raw worker results: {args.output_root.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
