from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from .ast import EvaluationResult, Policy, PolicySet
from .compiler import compile_policy
from .evaluator_asp import evaluate_policy as _evaluate_policy


class PolicyEngine:
    """A small runtime engine for registering and evaluating PACA++ policies."""

    def __init__(
        self,
        policies: Sequence[Policy | str] | None = None,
        *,
        name: str = "default",
        strategy: str = "deny_overrides",
        default_decision: str = "deny",
    ):
        self.name = name
        self.strategy = strategy
        self.default_decision = default_decision
        self._policies: List[Policy] = []
        if policies:
            self.add_policies(policies)

    @property
    def policies(self) -> List[Policy]:
        return list(self._policies)

    def add_policy(self, policy: Policy | str) -> Policy:
        parsed = policy if isinstance(policy, Policy) else __import__("paca.parser", fromlist=["parse_policy"]).parse_policy(policy)
        self._policies.append(parsed)
        return parsed

    def add_policies(self, policies: Iterable[Policy | str]) -> None:
        for policy in policies:
            self.add_policy(policy)

    def evaluate(self, policy: Policy | str, context: Dict[str, Any]) -> EvaluationResult:
        return _evaluate_policy(policy, context)

    def evaluate_set(self, policy_set: PolicySet, context: Dict[str, Any]) -> EvaluationResult:
        if not isinstance(policy_set, PolicySet):
            raise TypeError("Expected a PolicySet instance.")

        results = [_evaluate_policy(policy, context) for policy in policy_set.policies]
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
        provenance: List[Any] = []
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

    def compile(self) -> List[Dict[str, Any]]:
        return [compile_policy(policy) for policy in self._policies]

    def to_policy_set(self) -> PolicySet:
        return PolicySet(name=self.name, policies=list(self._policies), strategy=self.strategy, default_decision=self.default_decision)


__all__ = ["PolicyEngine"]
