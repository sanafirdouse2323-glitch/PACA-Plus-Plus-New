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
        self.strategy, self.default_decision = strategy, default_decision

    def evaluate(self, policy: Policy | str, context: Dict[str, Any]) -> EvaluationResult:
        return evaluate_policy(policy, context)

    def evaluate_set(self, policy_set: PolicySet | Sequence[Policy | str], context: Dict[str, Any],
                     action: str | None = None) -> EvaluationResult:
        pols = list(policy_set.policies) if isinstance(policy_set, PolicySet) else list(policy_set)
        results = []
        for p in pols:
            if action is not None and isinstance(p, Policy) and p.action not in (action, "any"):
                continue
            results.append(evaluate_policy(p, context))
        fired = [f for r in results for f in r.fired]
        permits = [n for e, n in fired if e == "permit"]
        denies = [n for e, n in fired if e == "deny"]
        if self.strategy == "deny_overrides":
            final = "deny" if denies else "permit" if permits else self.default_decision
        elif self.strategy == "permit_overrides":
            final = "permit" if permits else "deny" if denies else self.default_decision
        else:
            final = fired[0][0] if fired else self.default_decision
        obl_map: Dict[str, list] = {}
        for r in results:
            obl_map.update(r.obligation_map)
        return EvaluationResult(
            decision=final, passed=final == "permit",
            matched_conditions=sum(r.matched_conditions for r in results),
            total_conditions=sum(r.total_conditions for r in results),
            details=[d for r in results for d in r.details],
            provenance=[x for r in results for x in r.provenance],
            matched_policies=[n for _, n in fired], fired=fired, obligation_map=obl_map,
            obligations=sorted({o for n, os in obl_map.items() for o in os}),
        )


__all__ = ["PolicyEngine"]
