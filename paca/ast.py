"""
PACA++ Abstract Syntax Tree (AST)

Defines the internal representation of PACA++ policies.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Expression:
    """Represents a single policy condition."""

    entity: str
    attribute: str
    operator: str
    value: str


@dataclass(frozen=True)
class Obligation:
    """Represents an obligation that must hold."""

    name: str
    parameter: str


@dataclass(frozen=True)
class Policy:
    """Represents a complete PACA++ policy."""

    name: str
    action: str
    expressions: List[Expression] = field(default_factory=list)
    obligation: Optional[Obligation] = None
    effect: str = "deny"