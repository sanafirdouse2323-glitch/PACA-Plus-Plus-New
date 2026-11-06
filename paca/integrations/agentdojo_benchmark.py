"""Reproducible, task-scoped AgentDojo workspace benchmark runner.

This runner compares AgentDojo's stock no-defense pipeline with PACA++ for
explicitly selected workspace user tasks whose trusted ground-truth calls are
entirely within the PACA++ read-scoped workspace mapper.

It uses AgentDojo's own task/attack result checkers and logger. It does not claim
full workspace-suite coverage, and it does not run until an operator explicitly
selects tasks, attack tasks, a model, and a configured provider.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import statistics
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..runtime import ACTIONS, Capability
from ..provenance import Label
from .agentdojo import PacaToolsExecutor
from .agentdojo_workspace import (
    SUPPORTED_WORKSPACE_READ_TOOLS,
    WorkspaceTaskContext,
    make_workspace_request_builder,
)

TENANT = "agentdojo-v1.2.2-workspace"
DEFAULT_SUITE_VERSION = "v1.2.2"
DEFAULT_SUITE_NAME = "workspace"
BOOTSTRAP_ACTIONS = ("read_mail", "mark_mail_read", "read_calendar", "read_drive")


class UnsupportedWorkspaceTask(ValueError):
    """A selected AgentDojo user task is outside the mapped workspace read scope."""


@dataclass(frozen=True)
class TaskPolicy:
    user_task_id: str
    capability: Capability
    context: WorkspaceTaskContext
    manifest: tuple[dict[str, str], ...]


def _agentdojo_imports():
    """Import optional AgentDojo APIs only when the benchmark runner is invoked."""
    try:
        from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
        from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
        from agentdojo.attacks import load_attack
        from agentdojo.benchmark import (
            load_task_results,
            run_task_with_injection_tasks,
            run_task_without_injection_tasks,
        )
        from agentdojo.task_suite.load_suites import get_suite
    except ImportError as exc:
        raise RuntimeError(
            "The AgentDojo runner requires the optional dependency. "
            'Install it with: pip install -e ".[dev,agentdojo]"'
        ) from exc
    return {
        "AgentPipeline": AgentPipeline,
        "PipelineConfig": PipelineConfig,
        "ToolsExecutionLoop": ToolsExecutionLoop,
        "ToolsExecutor": ToolsExecutor,
        "load_attack": load_attack,
        "load_task_results": load_task_results,
        "run_task_with_injection_tasks": run_task_with_injection_tasks,
        "run_task_without_injection_tasks": run_task_without_injection_tasks,
        "get_suite": get_suite,
    }


def _resource_labeler_for_tenant(tenant: str):
    """Label every workspace resource as untrusted and maximum sensitivity.

    AgentDojo's fixture schema does not supply PACA++ confidentiality labels.
    Rather than invent per-record classifications, the benchmark conservatively
    assigns the maximum PACA++ sensitivity (3) to the whole source collection.
    This is a benchmark policy choice, not a claim that AgentDojo metadata contains
    a sensitivity classification.
    """
    if not isinstance(tenant, str) or not tenant.strip():
        raise ValueError("tenant must be a non-empty string")

    def label_resource(source: str, arguments: dict[str, Any], env: Any) -> Label:
        if source not in {"mail", "calendar", "drive"}:
            raise ValueError(f"unknown AgentDojo workspace resource source: {source!r}")
        return Label(
            integrity="untrusted",
            sensitivity=3,
            tenant=tenant,
            origins=frozenset({f"agentdojo_fixture:{source}", "agentdojo_benchmark"}),
        )

    return label_resource


def derive_task_policy(user_task: Any, suite: Any, *, episode_id: str = "task") -> TaskPolicy:
    """Derive exact action/target grants from the suite's trusted user-task ground truth.

    The environment is loaded without attack injections. Only the user task's
    declared ground-truth calls are considered; injection-task ground truth is
    never used to create authority. Every ground-truth function must be in the
    supported mapper and every target must be representable.
    """
    if not hasattr(user_task, "ID") or not isinstance(user_task.ID, str):
        raise UnsupportedWorkspaceTask("AgentDojo user task has no valid ID")

    clean_environment = suite.load_and_inject_default_environment({})
    clean_environment = user_task.init_environment(clean_environment)
    try:
        ground_truth_calls = user_task.ground_truth(clean_environment)
    except Exception as exc:
        raise UnsupportedWorkspaceTask(
            f"{user_task.ID}: could not derive trusted ground-truth calls ({type(exc).__name__})"
        ) from exc

    if not ground_truth_calls:
        raise UnsupportedWorkspaceTask(f"{user_task.ID}: ground truth contains no tool calls")

    labeler = _resource_labeler_for_tenant(TENANT)
    bootstrap_capability = Capability(
        cap_id=f"bootstrap:{user_task.ID}",
        principal="agentdojo-user",
        tenant=TENANT,
        task_id=f"bootstrap:{user_task.ID}",
        role="assistant",
        grants={action: ("*",) for action in BOOTSTRAP_ACTIONS},
        expires=1000,
        max_calls=1000,
    )
    bootstrap_context = WorkspaceTaskContext(
        capability=bootstrap_capability,
        resource_labeler=labeler,
    )
    bootstrap_builder = make_workspace_request_builder(bootstrap_context)

    grants: dict[str, set[str]] = {}
    manifest: list[dict[str, str]] = []
    for call in ground_truth_calls:
        function_name = getattr(call, "function", None)
        arguments = getattr(call, "args", None)
        if function_name not in SUPPORTED_WORKSPACE_READ_TOOLS:
            raise UnsupportedWorkspaceTask(
                f"{user_task.ID}: ground-truth tool {function_name!r} is outside "
                "SUPPORTED_WORKSPACE_READ_TOOLS"
            )
        if not isinstance(arguments, dict):
            try:
                arguments = dict(arguments)
            except Exception as exc:
                raise UnsupportedWorkspaceTask(
                    f"{user_task.ID}: ground-truth arguments for {function_name!r} are not a mapping"
                ) from exc

        try:
            request = bootstrap_builder(
                function_name,
                dict(arguments),
                clean_environment,
                {},
            )
            target_name = ACTIONS[request.action]["target"]
            target_arg = request.args.get(target_name)
            if target_arg is None or not isinstance(target_arg.value, str) or not target_arg.value:
                raise ValueError("mapped target is missing or is not a non-empty string")
        except Exception as exc:
            raise UnsupportedWorkspaceTask(
                f"{user_task.ID}: cannot map ground-truth call {function_name!r} "
                f"({type(exc).__name__})"
            ) from exc

        grants.setdefault(request.action, set()).add(target_arg.value)
        manifest.append(
            {
                "function": function_name,
                "action": request.action,
                "target": target_arg.value,
            }
        )

    if not grants:
        raise UnsupportedWorkspaceTask(f"{user_task.ID}: no PACA++ grants could be derived")

    episode_suffix = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in episode_id)
    capability = Capability(
        cap_id=f"agentdojo:{user_task.ID}:{episode_suffix}",
        principal="agentdojo-user",
        tenant=TENANT,
        task_id=f"agentdojo:{DEFAULT_SUITE_VERSION}:{user_task.ID}:{episode_suffix}",
        role="assistant",
        grants={action: tuple(sorted(targets)) for action, targets in sorted(grants.items())},
        expires=100,
        max_calls=40,
    )
    context = WorkspaceTaskContext(
        capability=capability,
        resource_labeler=labeler,
    )
    return TaskPolicy(
        user_task_id=user_task.ID,
        capability=capability,
        context=context,
        manifest=tuple(manifest),
    )


def list_supported_workspace_tasks(suite: Any) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Return supported tasks and explicit exclusion reasons using task ground truth."""
    supported: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    for task_id, task in suite.user_tasks.items():
        try:
            policy = derive_task_policy(task, suite)
            supported.append(
                {
                    "user_task_id": task_id,
                    "tool_calls": list(policy.manifest),
                    "grants": {
                        action: list(patterns)
                        for action, patterns in policy.capability.grants.items()
                    },
                }
            )
        except UnsupportedWorkspaceTask as exc:
            excluded.append({"user_task_id": task_id, "reason": str(exc)})
    return supported, excluded


def _build_pipeline(
    api: dict[str, Any],
    *,
    model: str,
    model_id: str | None,
    pipeline_name: str,
    max_iters: int,
    task_policy: TaskPolicy | None = None,
) -> tuple[Any, PacaToolsExecutor | None, Any | None]:
    config = api["PipelineConfig"](
        llm=model,
        model_id=model_id,
        defense=None,
        tool_delimiter="tool",
        system_message_name=None,
        system_message=None,
    )
    pipeline = api["AgentPipeline"].from_config(config)
    pipeline.name = pipeline_name

    tools_loops = [
        element
        for element in pipeline.elements
        if isinstance(element, api["ToolsExecutionLoop"])
    ]
    if len(tools_loops) != 1:
        raise RuntimeError(
            f"Expected exactly one AgentDojo ToolsExecutionLoop, found {len(tools_loops)}"
        )
    tools_loop = tools_loops[0]
    tools_loop.max_iters = max_iters

    if task_policy is None:
        return pipeline, None, None

    executor = PacaToolsExecutor(
        monitor=_new_monitor(),
        request_builder=make_workspace_request_builder(task_policy.context),
    )
    executor_indices = [
        index
        for index, element in enumerate(tools_loop.elements)
        if isinstance(element, api["ToolsExecutor"])
    ]
    if len(executor_indices) != 1:
        raise RuntimeError(
            "Expected exactly one stock AgentDojo ToolsExecutor in the unprotected pipeline"
        )
    tools_loop.elements[executor_indices[0]] = executor
    return pipeline, executor, executor.monitor


def _new_monitor():
    from ..monitor import Monitor

    return Monitor()


def _distribution_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _load_saved_result(api: dict[str, Any], pipeline_name: str, suite_name: str,
                       user_task_id: str, attack_name: str, injection_task_id: str,
                       log_dir: Path):
    return api["load_task_results"](
        pipeline_name,
        suite_name,
        user_task_id,
        attack_name,
        injection_task_id,
        log_dir,
    )


def _mean(values: list[bool]) -> float | None:
    if not values:
        return None
    return float(statistics.mean(values))


def _sum_metrics(records: list[dict[str, int]]) -> dict[str, int]:
    keys = (
        "tool_calls_seen",
        "denied_calls",
        "authorized_dispatches",
        "dispatch_attempts",
        "dispatch_errors",
        "dispatch_exceptions",
        "approval_requests",
        "policy_decision_ns",
    )
    return {key: sum(record.get(key, 0) for record in records) for key in keys}


def run_workspace_benchmark(
    *,
    suite: Any,
    user_task_ids: list[str],
    injection_task_ids: list[str],
    model: str,
    model_id: str | None,
    attack_name: str,
    log_dir: Path,
    output_path: Path,
    max_iters: int = 15,
) -> dict[str, Any]:
    """Run paired no-defense and PACA++ conditions for explicitly selected tasks.

    A separate executor, monitor, capability, and task-step counter are created
    for every task episode. The baseline and PACA++ conditions use the same model,
    system message, tool output format, iteration limit, user-task ID, attack, and
    injection-task ID. No API call occurs during dry-run/task-policy derivation.
    """
    api = _agentdojo_imports()
    from agentdojo.models import ModelsEnum

    try:
        ModelsEnum(model)
    except ValueError as exc:
        raise ValueError(f"unsupported AgentDojo model identifier: {model!r}") from exc
    if attack_name.lower().endswith("_dos") or attack_name in {"dos", "manual"}:
        raise ValueError(
            "DoS and interactive manual attacks are not included in this first workspace runner; "
            "choose a non-interactive, non-DoS registered attack such as tool_knowledge."
        )
    if max_iters < 1 or max_iters > 100:
        raise ValueError("max_iters must be between 1 and 100")
    if not user_task_ids or not injection_task_ids:
        raise ValueError("at least one user task and one injection task must be selected")

    available_users = suite.user_tasks
    available_injections = suite.injection_tasks
    missing_users = sorted(set(user_task_ids) - set(available_users))
    missing_injections = sorted(set(injection_task_ids) - set(available_injections))
    if missing_users:
        raise ValueError(f"unknown workspace user task IDs: {missing_users}")
    if missing_injections:
        raise ValueError(f"unknown workspace injection task IDs: {missing_injections}")

    log_dir.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    results: dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "configuration": {
            "agentdojo_package_version": _distribution_version("agentdojo"),
            "paca_package_version": _distribution_version("paca-plus-plus"),
            "benchmark_version": DEFAULT_SUITE_VERSION,
            "suite": suite.name,
            "model": model,
            "model_id": model_id,
            "attack": attack_name,
            "user_task_ids": user_task_ids,
            "injection_task_ids": injection_task_ids,
            "max_iters": max_iters,
            "conditions": ["agentdojo_no_defense", "paca_plus_plus"],
            "workspace_mapper_scope": sorted(SUPPORTED_WORKSPACE_READ_TOOLS),
            "resource_label_policy": "untrusted integrity; sensitivity 3 (maximum); benchmark tenant",
        },
        "task_policies": {},
        "task_results": [],
        "skipped_attack_pairs": [],
    }

    baseline_benign: list[bool] = []
    paca_benign: list[bool] = []
    baseline_attack_success: list[bool] = []
    paca_attack_success: list[bool] = []
    baseline_utility_under_attack: list[bool] = []
    paca_utility_under_attack: list[bool] = []
    paca_benign_metrics: list[dict[str, int]] = []
    paca_attacked_metrics: list[dict[str, int]] = []

    def save_checkpoint() -> None:
        serialized = json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False)
        temporary_path = output_path.with_name(output_path.name + ".tmp")
        temporary_path.write_text(serialized, encoding="utf-8")
        temporary_path.replace(output_path)

    save_checkpoint()
    for user_task_id in user_task_ids:
        user_task = available_users[user_task_id]
        policy = derive_task_policy(user_task, suite)
        results["task_policies"][user_task_id] = {
            "grants": {
                action: list(patterns)
                for action, patterns in policy.capability.grants.items()
            },
            "ground_truth_tool_calls": list(policy.manifest),
        }

        # Benign (no-injection) baseline.
        baseline_name = f"{model}__agentdojo_baseline"
        baseline_pipeline, _, _ = _build_pipeline(
            api,
            model=model,
            model_id=model_id,
            pipeline_name=baseline_name,
            max_iters=max_iters,
        )
        base_utility, _ = api["run_task_without_injection_tasks"](
            suite,
            baseline_pipeline,
            user_task,
            log_dir,
            True,
            benchmark_version=DEFAULT_SUITE_VERSION,
        )
        base_result = _load_saved_result(
            api, baseline_name, suite.name, user_task_id, "none", "none", log_dir
        )

        # Benign (no-injection) PACA++ condition. A fresh capability is used for
        # this episode and is not reused by any injection episode.
        paca_name = f"{model}__paca_plus_plus"
        paca_policy = derive_task_policy(user_task, suite, episode_id="benign")
        paca_pipeline, paca_executor, paca_monitor = _build_pipeline(
            api,
            model=model,
            model_id=model_id,
            pipeline_name=paca_name,
            max_iters=max_iters,
            task_policy=paca_policy,
        )
        paca_utility_value, _ = api["run_task_without_injection_tasks"](
            suite,
            paca_pipeline,
            user_task,
            log_dir,
            True,
            benchmark_version=DEFAULT_SUITE_VERSION,
        )
        paca_result = _load_saved_result(
            api, paca_name, suite.name, user_task_id, "none", "none", log_dir
        )
        base_utility_bool = bool(base_utility)
        paca_utility_bool = bool(paca_utility_value)
        baseline_benign.append(base_utility_bool)
        paca_benign.append(paca_utility_bool)
        task_result: dict[str, Any] = {
            "user_task_id": user_task_id,
            "benign": {
                "baseline_utility": base_utility_bool,
                "paca_utility": paca_utility_bool,
                "baseline_duration_seconds": float(base_result.duration),
                "paca_duration_seconds": float(paca_result.duration),
                "baseline_error": base_result.error,
                "paca_error": paca_result.error,
                "paca_metrics": dict(paca_executor.metrics),
                "paca_audit_entries": list(paca_monitor.audit.entries),
            },
            "attacked_pairs": [],
        }
        results["task_results"].append(task_result)
        paca_benign_metrics.append(dict(paca_executor.metrics))
        save_checkpoint()

        # Check which selected injections are applicable to this user task before
        # starting model calls. Unsupported/non-injectable pairs are recorded, not
        # silently removed from the experiment denominator.
        baseline_preflight_pipeline, _, _ = _build_pipeline(
            api,
            model=model,
            model_id=model_id,
            pipeline_name=baseline_name,
            max_iters=max_iters,
        )
        preflight_attack = api["load_attack"](attack_name, suite, baseline_preflight_pipeline)
        applicable_injections: list[str] = []
        for injection_task_id in injection_task_ids:
            injection_task = available_injections[injection_task_id]
            try:
                preflight_attack.attack(user_task, injection_task)
            except ValueError as exc:
                results["skipped_attack_pairs"].append(
                    {
                        "user_task_id": user_task_id,
                        "injection_task_id": injection_task_id,
                        "reason": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            applicable_injections.append(injection_task_id)

        for injection_task_id in applicable_injections:
            injection_task = available_injections[injection_task_id]
            episode_id = injection_task_id

            # Baseline attacked episode.
            base_pipeline, _, _ = _build_pipeline(
                api,
                model=model,
                model_id=model_id,
                pipeline_name=baseline_name,
                max_iters=max_iters,
            )
            base_attack = api["load_attack"](attack_name, suite, base_pipeline)
            base_utility_results, base_security_results = api["run_task_with_injection_tasks"](
                suite,
                base_pipeline,
                user_task,
                base_attack,
                log_dir,
                True,
                injection_tasks=[injection_task_id],
                benchmark_version=DEFAULT_SUITE_VERSION,
            )
            base_pair = (user_task_id, injection_task_id)
            base_pair_utility = bool(base_utility_results[base_pair])
            base_pair_attack_success = bool(base_security_results[base_pair])
            base_pair_result = _load_saved_result(
                api, baseline_name, suite.name, user_task_id,
                attack_name, injection_task_id, log_dir
            )

            # PACA++ attacked episode with newly derived task-scoped authority.
            paca_pair_policy = derive_task_policy(
                user_task, suite, episode_id=episode_id
            )
            paca_pair_pipeline, paca_pair_executor, paca_pair_monitor = _build_pipeline(
                api,
                model=model,
                model_id=model_id,
                pipeline_name=paca_name,
                max_iters=max_iters,
                task_policy=paca_pair_policy,
            )
            paca_attack = api["load_attack"](attack_name, suite, paca_pair_pipeline)
            paca_utility_results, paca_security_results = api["run_task_with_injection_tasks"](
                suite,
                paca_pair_pipeline,
                user_task,
                paca_attack,
                log_dir,
                True,
                injection_tasks=[injection_task_id],
                benchmark_version=DEFAULT_SUITE_VERSION,
            )
            paca_pair_utility = bool(paca_utility_results[base_pair])
            paca_pair_attack_success = bool(paca_security_results[base_pair])
            paca_pair_result = _load_saved_result(
                api, paca_name, suite.name, user_task_id,
                attack_name, injection_task_id, log_dir
            )

            baseline_utility_under_attack.append(base_pair_utility)
            paca_utility_under_attack.append(paca_pair_utility)
            baseline_attack_success.append(base_pair_attack_success)
            paca_attack_success.append(paca_pair_attack_success)
            paca_attacked_metrics.append(dict(paca_pair_executor.metrics))

            task_result["attacked_pairs"].append(
                {
                    "injection_task_id": injection_task_id,
                    "baseline": {
                        "utility": base_pair_utility,
                        "attack_success": base_pair_attack_success,
                        "duration_seconds": float(base_pair_result.duration),
                        "error": base_pair_result.error,
                    },
                    "paca": {
                        "utility": paca_pair_utility,
                        "attack_success": paca_pair_attack_success,
                        "duration_seconds": float(paca_pair_result.duration),
                        "error": paca_pair_result.error,
                        "metrics": dict(paca_pair_executor.metrics),
                        "audit_entries": list(paca_pair_monitor.audit.entries),
                    },
                }
            )
            save_checkpoint()

        # The complete per-user-task record remains in task_results, including
        # when every selected attack pair was marked inapplicable.

    benign_policy_metrics = _sum_metrics(paca_benign_metrics)
    attacked_policy_metrics = _sum_metrics(paca_attacked_metrics)
    all_policy_metrics = _sum_metrics([*paca_benign_metrics, *paca_attacked_metrics])

    def policy_metric_summary(metrics: dict[str, int]) -> dict[str, Any]:
        calls = metrics["tool_calls_seen"]
        return {
            **metrics,
            "mean_policy_decision_ms_per_tool_call": (
                metrics["policy_decision_ns"] / 1_000_000 / calls if calls else None
            ),
        }

    results["summary"] = {
        "benign_task_count": len(baseline_benign),
        "attack_pair_count": len(baseline_attack_success),
        "skipped_attack_pair_count": len(results["skipped_attack_pairs"]),
        "benign_utility": {
            "agentdojo_no_defense": _mean(baseline_benign),
            "paca_plus_plus": _mean(paca_benign),
        },
        "utility_under_attack": {
            "agentdojo_no_defense": _mean(baseline_utility_under_attack),
            "paca_plus_plus": _mean(paca_utility_under_attack),
        },
        "attack_success_rate": {
            "agentdojo_no_defense": _mean(baseline_attack_success),
            "paca_plus_plus": _mean(paca_attack_success),
        },
        "paca_tool_metrics": {
            "benign": policy_metric_summary(benign_policy_metrics),
            "attacked": policy_metric_summary(attacked_policy_metrics),
            "combined": policy_metric_summary(all_policy_metrics),
        },
        "denied_tool_calls_during_benign_tasks": benign_policy_metrics["denied_calls"],
        "denied_tool_calls_during_attacked_tasks": attacked_policy_metrics["denied_calls"],
        "benign_utility_regression_count": sum(
            base and not defended for base, defended in zip(baseline_benign, paca_benign)
        ),
        "error_sample_counts": {
            "baseline_benign": sum(
                bool(item["benign"]["baseline_error"])
                for item in results["task_results"]
            ),
            "paca_benign": sum(
                bool(item["benign"]["paca_error"])
                for item in results["task_results"]
            ),
            "baseline_attacked": sum(
                bool(pair["baseline"]["error"])
                for item in results["task_results"]
                for pair in item["attacked_pairs"]
            ),
            "paca_attacked": sum(
                bool(pair["paca"]["error"])
                for item in results["task_results"]
                for pair in item["attacked_pairs"]
            ),
        },
        "attack_success_semantics": (
            "AgentDojo BaseInjectionTask.security returns True when the injection goal "
            "was achieved; lower attack_success_rate is better."
        ),
    }
    results["status"] = "completed"
    results["finished_at"] = datetime.now(timezone.utc).isoformat()
    save_checkpoint()
    return results


def _csv_ids(value: str) -> list[str]:
    values = [item.strip() for item in value.split(",") if item.strip()]
    if not values:
        raise argparse.ArgumentTypeError("provide a comma-separated list of IDs")
    if len(values) != len(set(values)):
        raise argparse.ArgumentTypeError("duplicate IDs are not allowed")
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run matched AgentDojo workspace baseline and PACA++ benchmark episodes."
    )
    parser.add_argument("--suite-version", default=DEFAULT_SUITE_VERSION)
    parser.add_argument("--suite", default=DEFAULT_SUITE_NAME, choices=[DEFAULT_SUITE_NAME])
    parser.add_argument("--list-supported-tasks", action="store_true")
    parser.add_argument("--list-injection-tasks", action="store_true")
    parser.add_argument("--user-tasks", type=_csv_ids)
    parser.add_argument("--injection-tasks", type=_csv_ids)
    parser.add_argument("--model")
    parser.add_argument("--model-id")
    parser.add_argument("--attack", default="tool_knowledge")
    parser.add_argument("--log-dir", type=Path, default=Path("runs/agentdojo"))
    parser.add_argument("--output", type=Path, default=Path("runs/agentdojo/paca-comparison.json"))
    parser.add_argument("--max-iters", type=int, default=15)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if args.suite_version != DEFAULT_SUITE_VERSION:
        parser.error(
            f"this mapper is pinned to suite data {DEFAULT_SUITE_VERSION}; "
            "other suite versions require a separately reviewed mapping"
        )

    api = _agentdojo_imports()
    suite = api["get_suite"](args.suite_version, args.suite)

    if args.list_injection_tasks:
        print(json.dumps({"injection_task_ids": list(suite.injection_tasks)}, indent=2))
        return 0

    if args.list_supported_tasks:
        supported, excluded = list_supported_workspace_tasks(suite)
        print(json.dumps({"supported_tasks": supported, "excluded_tasks": excluded}, indent=2))
        return 0

    if not args.user_tasks:
        parser.error("--user-tasks is required unless --list-supported-tasks is used")
    if not args.injection_tasks:
        parser.error("--injection-tasks is required so the attack denominator is explicit")
    if not args.model:
        parser.error("--model is required for an actual or dry-run experiment")

    selected_tasks = []
    for task_id in args.user_tasks:
        if task_id not in suite.user_tasks:
            parser.error(f"unknown user task ID: {task_id}")
        task = suite.user_tasks[task_id]
        try:
            policy = derive_task_policy(task, suite)
        except UnsupportedWorkspaceTask as exc:
            parser.error(str(exc))
        selected_tasks.append((task_id, task, policy))

    missing_injections = sorted(set(args.injection_tasks) - set(suite.injection_tasks))
    if missing_injections:
        parser.error(f"unknown injection task IDs: {missing_injections}")

    if args.dry_run:
        print(json.dumps(
            {
                "status": "dry_run",
                "suite": args.suite,
                "suite_version": args.suite_version,
                "model": args.model,
                "attack": args.attack,
                "injection_task_ids": args.injection_tasks,
                "task_policies": {
                    task_id: {
                        "ground_truth_tool_calls": list(policy.manifest),
                        "grants": {
                            action: list(patterns)
                            for action, patterns in policy.capability.grants.items()
                        },
                    }
                    for task_id, _, policy in selected_tasks
                },
            },
            indent=2,
        ))
        return 0

    try:
        result = run_workspace_benchmark(
            suite=suite,
            user_task_ids=args.user_tasks,
            injection_task_ids=args.injection_tasks,
            model=args.model,
            model_id=args.model_id,
            attack_name=args.attack,
            log_dir=args.log_dir,
            output_path=args.output,
            max_iters=args.max_iters,
        )
    except Exception as exc:
        if args.output.exists():
            try:
                partial = json.loads(args.output.read_text(encoding="utf-8"))
                partial["status"] = "failed"
                partial["finished_at"] = datetime.now(timezone.utc).isoformat()
                # Do not copy arbitrary provider exception text into a result file:
                # it may contain request details or credentials.
                partial["failure_type"] = type(exc).__name__
                temporary_path = args.output.with_name(args.output.name + ".tmp")
                temporary_path.write_text(
                    json.dumps(partial, indent=2, sort_keys=True, ensure_ascii=False),
                    encoding="utf-8",
                )
                temporary_path.replace(args.output)
            except Exception:
                pass
        parser.exit(2, f"benchmark failed ({type(exc).__name__}): {exc}\n")

    print(json.dumps(result["summary"], indent=2))
    print(f"Raw task-level results: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
