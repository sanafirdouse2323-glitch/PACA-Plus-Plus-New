from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from .ast import Policy, PolicySet
from .compiler import compile_policy
from .evaluator import evaluate_policy


class PolicyEngine:
    """A small runtime engine for registering and evaluating PACA++ policies."""

    def __init__(self, policies: Sequence[Policy | str] | None = None, *, name: str = "default"):
        self.name = name
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

    def evaluate(self, context: Dict[str, Any], *, action: str | None = None, policy_name: str | None = None):
        matches = self._policies
        if action is not None:
            matches = [p for p in matches if p.action == action]
        if policy_name is not None:
            matches = [p for p in matches if p.name == policy_name]

        if not matches:
            return []
        if len(matches) == 1 and action is None and policy_name is None:
            return evaluate_policy(matches[0], context)
        return [evaluate_policy(policy, context) for policy in matches]

    def compile(self) -> List[Dict[str, Any]]:
        return [compile_policy(policy) for policy in self._policies]

    def to_policy_set(self) -> PolicySet:
        return PolicySet(name=self.name, policies=list(self._policies))


__all__ = ["PolicyEngine"]
