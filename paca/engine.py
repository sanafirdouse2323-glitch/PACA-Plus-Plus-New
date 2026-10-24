from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from .ast import Policy, PolicySet
from .compiler import compile_policy
from .evaluator_asp import evaluate_policy as _evaluate_policy


def evaluate_policy(policy: Policy | str, context: Dict[str, Any], provenance: Iterable[Any] | None = None):
    return _evaluate_policy(policy, context, provenance)


def evaluate_policy_set(
    policy_set: PolicySet | Sequence[Policy | str] | Policy | str,
    context: Dict[str, Any],
    provenance: Iterable[Any] | None = None,
) -> List[Any]:
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


def compile_cedar(policy: Policy | str) -> Dict[str, Any]:
    compiled = compile_policy(policy)
    compiled["backend"] = "cedar"
    return compiled


class PolicyEngine:
    """Production-style policy engine for evaluating policy sets."""

    def __init__(self, strategy: str = "deny_overrides", default_decision: str = "deny") -> None:
        self.strategy = strategy
        self.default_decision = default_decision

    def evaluate(self, policy: Policy | str, context: Dict[str, Any]) -> Any:
        return evaluate_policy(policy, context)

    def evaluate_set(self, policy_set: PolicySet | Sequence[Policy | str] | Policy | str, context: Dict[str, Any]) -> Any:
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

        results = [evaluate_policy(policy, context) for policy in policies]
        if not results:
            return results

        matched = [result.policy_id or "unknown" for result in results if result.decision == "permit"]
        denies = [result.policy_id or "unknown" for result in results if result.decision == "deny"]

        if self.strategy == "deny_overrides":
            final_decision = "deny" if denies else "permit" if matched else self.default_decision
        elif self.strategy == "permit_overrides":
            final_decision = "permit" if matched else "deny" if denies else self.default_decision
        elif self.strategy == "first_match":
            final_decision = results[0].decision
        else:
            raise ValueError(f"Unsupported policy strategy: {self.strategy!r}")

        all_details: List[str] = []
        all_provenance: List[Any] = []
        for result in results:
            all_details.extend(result.details)
            all_provenance.extend(result.provenance)

        return {
            "decision": final_decision,
            "passed": final_decision == "permit",
            "matched_conditions": sum(r.matched_conditions for r in results),
            "total_conditions": sum(r.total_conditions for r in results),
            "details": all_details,
            "provenance": all_provenance,
            "matched_policies": matched,
        }


__all__ = [
    "PolicyEngine",
    "compile_cedar",
    "evaluate_policy",
    "evaluate_policy_set",
]
