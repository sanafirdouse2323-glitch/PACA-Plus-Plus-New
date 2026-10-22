from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from .ast import EvaluationResult, Policy, PolicySet
from .engine import PolicyEngine as _PolicyEngine
from .evaluator_asp import evaluate_policy as _evaluate_policy


def evaluate_policy(policy: Policy | str, context: Dict[str, Any], provenance: Iterable[Any] | None = None) -> EvaluationResult:
    return _evaluate_policy(policy, context, provenance)


def evaluate_policy_set(
    policy_set: PolicySet | Sequence[Policy | str] | Policy | str,
    context: Dict[str, Any],
    provenance: Iterable[Any] | None = None,
) -> List[EvaluationResult]:
    if isinstance(policy_set, PolicySet):
        policies = list(policy_set.policies)
    elif isinstance(policy_set, Policy):
        policies = [policy_set]
    elif isinstance(policy_set, str):
        policies = [policy_set]
    elif isinstance(policy_set, (list, tuple)):
        policies = list(policy_set)
    else:
        raise TypeError(f"Unsupported policy set type: {type(policy_set)!r}")

    return [evaluate_policy(policy, context, provenance) for policy in policies]


__all__ = ["PolicyEngine", "evaluate_policy", "evaluate_policy_set"]


PolicyEngine = _PolicyEngine
