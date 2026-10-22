from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from .ast import EvaluationResult, Policy, PolicySet, ProvenanceRecord
from .compiler import compile_policy
from .evaluator_asp import evaluate_policy as _evaluate_policy


def evaluate_policy(policy: Policy | str, context: Dict[str, Any], provenance: Iterable[Any] | None = None) -> EvaluationResult:
    return _evaluate_policy(policy, context, provenance)


def evaluate_policy_set(policy_set: PolicySet | Sequence[Policy | str] | Policy | str, context: Dict[str, Any], provenance: Iterable[Any] | None = None) -> List[EvaluationResult]:
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


class PolicyEngine:
    """A policy engine for evaluating PACA++ rules."""

    def __init__(self, strategy: str = "deny_overrides", default_decision: str = "deny") -> None:
        self.strategy = strategy
        self.default_decision = default_decision

    def evaluate(self, policy: Policy | str, context: Dict[str, Any]) -> EvaluationResult:
        return evaluate_policy(policy, context)

    def evaluate_set(self, policy_set: PolicySet, context: Dict[str, Any]) -> EvaluationResult:
        if not isinstance(policy_set, PolicySet):
            raise TypeError("Expected a PolicySet instance.")

        results = [evaluate_policy(policy, context) for policy in policy_set.policies]
        if not results:
            return EvaluationResult(
                decision=self.default_decision,
                passed=(self.default_decision == "permit"),
                matched_conditions=0,
                total_conditions=0,
                details=["No policies matched; using default decision."],
                provenance=[],
            )

        if self.strategy == "deny_overrides":
            final_decision = "deny" if any(result.decision == "deny" for result in results) else "permit"
        elif self.strategy == "permit_overrides":
            final_decision = "permit" if any(result.decision == "permit" for result in results) else "deny"
        elif self.strategy == "first_match":
            final_decision = results[0].decision
        else:
            raise ValueError(f"Unsupported policy strategy: {self.strategy!r}")

        all_details: List[str] = []
        provenance: List[ProvenanceRecord] = []
        for result in results:
            all_details.extend(result.details)
            provenance.extend(result.provenance)

        return EvaluationResult(
            decision=final_decision,
            passed=(final_decision == "permit"),
            matched_conditions=sum(result.matched_conditions for result in results),
            total_conditions=sum(result.total_conditions for result in results),
            details=all_details,
            provenance=provenance,
        )


__all__ = ["PolicyEngine", "evaluate_policy", "evaluate_policy_set"]
