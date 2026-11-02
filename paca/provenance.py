"""Provenance labels and taint propagation.

Every value an agent handles carries a Label assigned by the *runtime* (connectors,
memory store) - never by the model. Labels only ever get worse when data is combined:
integrity drops to the weakest input, sensitivity rises to the strongest, tenants and
origins accumulate. That is what stops summarising/rephrasing from laundering a source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional

from .ast import ProvenanceRecord

SENSITIVITY = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


@dataclass(frozen=True)
class Label:
    integrity: str = "trusted"                 # trusted | untrusted
    sensitivity: int = 0                       # 0 public .. 3 restricted
    tenant: Optional[str] = None
    origins: FrozenSet[str] = frozenset()

    @staticmethod
    def join(*labels: "Label") -> "Label":
        ls = [l for l in labels if l is not None]
        if not ls:
            return Label()
        return Label(
            integrity="untrusted" if any(l.integrity == "untrusted" for l in ls) else "trusted",
            sensitivity=max(l.sensitivity for l in ls),
            tenant=next((l.tenant for l in ls if l.tenant), None),
            origins=frozenset().union(*(l.origins for l in ls)),
        )

    def short(self) -> str:
        s = ("U" if self.integrity == "untrusted" else "T") + f"/S{self.sensitivity}"
        return s + (f"/{self.tenant}" if self.tenant else "")


@dataclass(frozen=True)
class Arg:
    """A value plus its provenance label."""
    value: Any
    label: Label = field(default_factory=Label)


def derive(value: Any, *inputs: Arg) -> Arg:
    """Value computed from other values (summary, rewrite, concatenation...): labels join."""
    return Arg(value, Label.join(*(a.label for a in inputs if isinstance(a, Arg))))


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
                for a, v in value.items():
                    self.add(source, str(key), str(a), v, f"context value for {key}.{a}")
            else:
                self.add(source, str(key), "value", value, f"context value for {key}")

    def __iter__(self):
        return iter(self.records)


__all__ = ["Label", "Arg", "derive", "ProvenanceGraph", "SENSITIVITY"]
