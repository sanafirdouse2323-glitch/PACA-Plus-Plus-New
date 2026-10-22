"""Abstract syntax tree and policy data model for PACA++.

The object model stays deliberately small so that the parser, compiler, and
runtime evaluator can remain easy to reason about and test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass(frozen=True)
class Expression:
    """Represents one authorization condition."""

    entity: str
    attribute: str
    operator: str
    value: Any


@dataclass(frozen=True)
class Obligation:
    """Represents an obligation attached to a policy decision."""

    name: str
    parameter: str = ""


@dataclass(frozen=True)
class Policy:
    """Represents a complete authorization policy."""

    name: str
    action: str
    expressions: List[Expression] = field(default_factory=list)
    obligation: Optional[Obligation] = None
    effect: str = "deny"


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
