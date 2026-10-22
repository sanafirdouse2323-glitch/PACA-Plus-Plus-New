"""Simple provenance tracking utilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .ast import ProvenanceRecord


@dataclass
class ProvenanceGraph:
    """Stores provenance records for a policy evaluation."""

    records: List[ProvenanceRecord] = field(default_factory=list)

    def add(self, source: str, entity: str, attribute: str, value: Any, explanation: str = "") -> ProvenanceRecord:
        record = ProvenanceRecord(
            source=source,
            entity=entity,
            attribute=attribute,
            value=value,
            explanation=explanation,
        )
        self.records.append(record)
        return record

    def from_context(self, context: Dict[str, Any], source: str = "context") -> None:
        if not isinstance(context, dict):
            return

        for key, value in context.items():
            if isinstance(value, dict):
                for attr_name, attr_value in value.items():
                    self.add(source, str(key), str(attr_name), attr_value, f"context value for {key}.{attr_name}")
            else:
                self.add(source, str(key), "value", value, f"context value for {key}")

    def __iter__(self):
        return iter(self.records)


__all__ = ["ProvenanceGraph"]
