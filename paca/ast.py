from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Expression:
    """Represents a single policy condition."""

    entity: str
    attribute: str
    operator: str
    value: Any
    source: str = "context"


@dataclass(frozen=True)
class Obligation:
    """Represents an obligation attached to a policy decision."""

    name: str
    parameter: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProvenanceRecord:
    """A single fact used while evaluating a policy."""

    source: str
    entity: str
    attribute: str
    value: Any
    explanation: str = ""


@dataclass
class EvaluationResult:
    """The result of evaluating one policy or a policy set."""

    decision: str
    passed: bool
    matched_conditions: int
    total_conditions: int
    details: list[str] = field(default_factory=list)
    provenance: list[ProvenanceRecord] = field(default_factory=list)
    policy_id: str | None = None
    obligations: list[str] = field(default_factory=list)
    matched_policies: list[str] = field(
        default_factory=list
    )  # all applicable rule names
    fired: list[tuple] = field(
        default_factory=list
    )  # effective (effect, policy_name) rules after conflict resolution
    obligation_map: dict[str, list[str]] = field(
        default_factory=dict
    )  # effective policy_name -> obligation names


@dataclass(frozen=True)
class Policy:
    """Represents a complete authorization policy.

    The API intentionally preserves the original lightweight style while supporting
    the richer metadata fields used by the production-style engine API.
    """

    name: str
    action: str
    expressions: list[Expression] = field(default_factory=list)
    obligation: Obligation | None = None
    obligations: list[Obligation] = field(default_factory=list)
    effect: str = "deny"
    description: str = ""
    priority: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    connectors: list[str] = field(default_factory=list)


@dataclass
class PolicySet:
    """A named collection of policies evaluated together."""

    name: str = "default"
    policies: list[Policy] = field(default_factory=list)
    strategy: str = "deny_overrides"
    default_decision: str = "deny"
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_policy(self, policy: Policy) -> None:
        self.policies.append(policy)

    def add_policies(self, policies: Iterable[Policy]) -> None:
        for policy in policies:
            self.add_policy(policy)

    def __iter__(self):
        return iter(self.policies)


__all__ = [
    "EvaluationResult",
    "Expression",
    "Obligation",
    "Policy",
    "PolicySet",
    "ProvenanceRecord",
]
