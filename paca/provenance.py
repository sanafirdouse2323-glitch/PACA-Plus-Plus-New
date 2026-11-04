"""Provenance labels and taint propagation.

Labels are assigned by trusted runtime adapters, never by the model. Combining values
preserves the least-trusted integrity, greatest sensitivity, all contributing origins,
and every contributing tenant.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional

from .ast import ProvenanceRecord

SENSITIVITY = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


@dataclass(frozen=True)
class Label:
    integrity: str = "trusted"
    sensitivity: int = 0
    tenant: Optional[str] = None
    origins: FrozenSet[str] = frozenset()
    tenants: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        if self.integrity not in {"trusted", "untrusted"}:
            raise ValueError("integrity must be 'trusted' or 'untrusted'")
        if isinstance(self.sensitivity, bool) or not isinstance(self.sensitivity, int) or not 0 <= self.sensitivity <= 3:
            raise ValueError("sensitivity must be an integer from 0 to 3")
        tenant_set = set(self.tenants)
        if any(not isinstance(value, str) or not value for value in tenant_set):
            raise ValueError("tenant identifiers must be non-empty strings")
        if self.tenant is not None:
            if not isinstance(self.tenant, str) or not self.tenant:
                raise ValueError("tenant must be a non-empty string or None")
            tenant_set.add(self.tenant)
        normalized = frozenset(tenant_set)
        object.__setattr__(self, "tenants", normalized)
        object.__setattr__(self, "tenant", next(iter(normalized)) if len(normalized) == 1 else None)
        object.__setattr__(self, "origins", frozenset(self.origins))

    @staticmethod
    def join(*labels: "Label") -> "Label":
        ls = [label for label in labels if label is not None]
        if not ls:
            return Label()
        return Label(
            integrity="untrusted" if any(label.integrity == "untrusted" for label in ls) else "trusted",
            sensitivity=max(label.sensitivity for label in ls),
            origins=frozenset().union(*(label.origins for label in ls)),
            tenants=frozenset().union(*(label.tenants for label in ls)),
        )

    def short(self) -> str:
        s = ("U" if self.integrity == "untrusted" else "T") + f"/S{self.sensitivity}"
        if len(self.tenants) == 1:
            s += "/" + next(iter(self.tenants))
        elif len(self.tenants) > 1:
            s += "/mixed-tenants"
        return s


@dataclass(frozen=True)
class Arg:
    """A value plus its provenance label."""
    value: Any
    label: Label = field(default_factory=Label)


def derive(value: Any, *inputs: Arg) -> Arg:
    """Value computed from other values: labels are joined, never improved."""
    return Arg(value, Label.join(*(arg.label for arg in inputs if isinstance(arg, Arg))))


@dataclass
class ProvenanceGraph:
    """Flat record store used to explain policy decisions."""
    records: List[ProvenanceRecord] = field(default_factory=list)

    def add(self, source: str, entity: str, attribute: str, value: Any, explanation: str = "") -> ProvenanceRecord:
        rec = ProvenanceRecord(source, entity, attribute, value, explanation)
        self.records.append(rec)
        return rec

    def from_context(self, context: Dict[str, Any], source: str = "context") -> None:
        for key, value in (context or {}).items():
            if isinstance(value, dict):
                for attribute, item in value.items():
                    self.add(source, str(key), str(attribute), item, f"context value for {key}.{attribute}")
            else:
                self.add(source, str(key), "value", value, f"context value for {key}")

    def __iter__(self):
        return iter(self.records)


__all__ = ["Label", "Arg", "derive", "ProvenanceGraph", "SENSITIVITY"]
