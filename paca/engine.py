"""Policy engine: combines rule results with a conflict-resolution strategy."""
from __future__ import annotations

from typing import Any, Dict, Sequence

from .ast import EvaluationResult, Policy, PolicySet
from .evaluator import evaluate_policy


class PolicyEngine:
    STRATEGIES = ("deny_overrides", "permit_overrides", "first_applicable")

    def __init__(self, strategy: str = "deny_overrides", default_decision: str = "deny") -> None:
        if strategy not in self.STRATEGIES:
            raise ValueError(f"Unsupported policy strategy: {strategy!r}")
        if default_decision not in ("permit", "deny"):
            raise ValueError(f"Unsupported default decision: {default_decision!r}")
        self.strategy, self.default_decision = strategy, default_decision

    def evaluate(self, policy: Policy | str, context: Dict[str, Any]) -> EvaluationResult:
        return evaluate_policy(policy, context)

    def evaluate_set(self, policy_set: PolicySet | Sequence[Policy | str], context: Dict[str, Any],
                     action: str | None = None) -> EvaluationResult:
        if isinstance(policy_set, PolicySet):
            pols = list(policy_set.policies)
            strategy = policy_set.strategy
            default_decision = policy_set.default_decision
        else:
            pols = list(policy_set)
            strategy = self.strategy
            default_decision = self.default_decision
        if strategy not in self.STRATEGIES:
            raise ValueError(f"Unsupported policy strategy: {strategy!r}")
        if default_decision not in ("permit", "deny"):
            raise ValueError(f"Unsupported default decision: {default_decision!r}")
        from .parser import parse_policy
        normalized = [parse_policy(policy) if isinstance(policy, str) else policy for policy in pols]
        results = []
        for policy in normalized:
            if action is not None and policy.action not in (action, "any"):
                continue
            results.append(evaluate_policy(policy, context))
        all_fired = [item for result in results for item in result.fired]
        permits = [result for result in results if any(effect == "permit" for effect, _ in result.fired)]
        denies = [result for result in results if any(effect == "deny" for effect, _ in result.fired)]

        if strategy == "deny_overrides":
            effective = denies or permits
        elif strategy == "permit_overrides":
            effective = permits or denies
        else:  # first_applicable: retain only the first policy that matched
            effective = next(( [result] for result in results if result.fired), [])

        fired = [item for result in effective for item in result.fired]
        final = fired[0][0] if fired else default_decision
        # Keep diagnostics for all matched rules, but only effective rules may
        # trigger enforcement or contribute obligations to the final decision.
        obl_map: Dict[str, list] = {}
        for result in effective:
            obl_map.update(result.obligation_map)
        return EvaluationResult(
            decision=final, passed=final == "permit",
            matched_conditions=sum(r.matched_conditions for r in results),
            total_conditions=sum(r.total_conditions for r in results),
            details=[d for r in results for d in r.details],
            provenance=[x for r in results for x in r.provenance],
            matched_policies=[name for _, name in all_fired], fired=fired, obligation_map=obl_map,
            obligations=sorted({obligation for values in obl_map.values() for obligation in values}),
        )


__all__ = ["PolicyEngine"]
