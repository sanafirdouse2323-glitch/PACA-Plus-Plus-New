from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class Expression:
    """Represents a single policy condition."""

    entity: str
    attribute: str
    operator: str
    value: Any
    source: str = ""


@dataclass(frozen=True)
class Obligation:
    """Represents an obligation attached to a policy decision."""

    name: str
    parameter: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    """Represents a complete authorization policy."""

    name: str
    action: str
    expressions: List[Expression] = field(default_factory=list)
    obligation: Optional[Obligation] = None
    obligations: List[Obligation] = field(default_factory=list)
    effect: str = "deny"
    description: str = ""
    priority: int = 0
    connectors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicySet:
    """A named collection of policies evaluated together."""

    name: str = "default"
    policies: List[Policy] = field(default_factory=list)
    strategy: str = "deny_overrides"
    default_decision: str = "deny"

    def add_policy(self, policy: Policy) -> None:
        self.policies.append(policy)

    def add_policies(self, policies: Iterable[Policy]) -> None:
        for policy in policies:
            self.add_policy(policy)

    def __iter__(self):
        return iter(self.policies)


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
    """The result of evaluating a policy against a runtime context."""

    decision: str
    passed: bool
    matched_conditions: int
    total_conditions: int
    details: List[str] = field(default_factory=list)
    provenance: List[ProvenanceRecord] = field(default_factory=list)


__all__ = [
    "EvaluationResult",
    "Expression",
    "Obligation",
    "Policy",
    "PolicySet",
    "ProvenanceRecord",
]
