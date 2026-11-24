"""Provenance labels and typed information-lineage tracking.

Labels are assigned by trusted runtime adapters, never by the model. Combining values
preserves the least-trusted integrity, greatest sensitivity, all contributing origins,
and every contributing tenant. The optional lineage graph records stable object/version
identifiers and parent transformations without storing the underlying content.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from typing import Any

from .ast import ProvenanceRecord

SENSITIVITY = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Label:
    integrity: str = "trusted"
    sensitivity: int = 0
    tenant: str | None = None
    origins: frozenset[str] = frozenset()
    tenants: frozenset[str] = frozenset()
    tenant_unknown: bool = False

    def __post_init__(self) -> None:
        if self.integrity not in {"trusted", "untrusted"}:
            raise ValueError("integrity must be 'trusted' or 'untrusted'")
        if (
            isinstance(self.sensitivity, bool)
            or not isinstance(self.sensitivity, int)
            or not 0 <= self.sensitivity <= 3
        ):
            raise ValueError("sensitivity must be an integer from 0 to 3")
        tenant_set = set(self.tenants)
        if any(not isinstance(value, str) for value in tenant_set):
            raise TypeError("tenant identifiers must be strings")
        if any(not value for value in tenant_set):
            raise ValueError("tenant identifiers must be non-empty")
        if self.tenant is not None:
            if not isinstance(self.tenant, str):
                raise TypeError("tenant must be a string or None")
            if not self.tenant:
                raise ValueError("tenant must be non-empty")
            tenant_set.add(self.tenant)
        normalized = frozenset(tenant_set)
        object.__setattr__(self, "tenants", normalized)
        if not isinstance(self.tenant_unknown, bool):
            raise TypeError("tenant_unknown must be a boolean")
        if self.sensitivity > 0 and not normalized:
            object.__setattr__(self, "tenant_unknown", True)
        object.__setattr__(
            self,
            "tenant",
            next(iter(normalized))
            if len(normalized) == 1 and not self.tenant_unknown
            else None,
        )
        origins = frozenset(self.origins)
        if any(not isinstance(origin, str) or not origin for origin in origins):
            raise ValueError("provenance origins must be non-empty strings")
        object.__setattr__(self, "origins", origins)

    @staticmethod
    def join(*labels: Label) -> Label:
        ls = [label for label in labels if label is not None]
        if not ls:
            return Label(integrity="untrusted")
        return Label(
            integrity="untrusted"
            if any(label.integrity == "untrusted" for label in ls)
            else "trusted",
            sensitivity=max(label.sensitivity for label in ls),
            origins=frozenset().union(*(label.origins for label in ls)),
            tenants=frozenset().union(*(label.tenants for label in ls)),
            tenant_unknown=any(label.tenant_unknown for label in ls),
        )

    def short(self) -> str:
        s = ("U" if self.integrity == "untrusted" else "T") + f"/S{self.sensitivity}"
        if self.tenant_unknown:
            s += "/unknown-tenant"
        if len(self.tenants) == 1:
            s += "/" + next(iter(self.tenants))
        elif len(self.tenants) > 1:
            s += "/mixed-tenants"
        return s


@dataclass(frozen=True)
class Arg:
    """A value plus its conservative label and optional trusted lineage references."""

    value: Any
    # Unknown values are tainted by default; trusted adapters must explicitly label them.
    label: Label = field(default_factory=lambda: Label(integrity="untrusted"))
    lineage_refs: frozenset[str] = frozenset()
    # True when an unrecorded dependency entered a derived value.
    lineage_incomplete: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.label, Label):
            raise TypeError("Arg.label must be a Label assigned by a trusted adapter")
        if isinstance(self.lineage_refs, (str, bytes)):
            raise TypeError("lineage_refs must be a collection of node identifiers")
        refs = frozenset(self.lineage_refs)
        if any(not isinstance(ref, str) or not ref for ref in refs):
            raise ValueError("lineage references must be non-empty strings")
        if not isinstance(self.lineage_incomplete, bool):
            raise TypeError("lineage_incomplete must be a boolean")
        object.__setattr__(self, "lineage_refs", refs)


def derive(value: Any, *inputs: Arg) -> Arg:
    """Propagate labels and all lineage references through an unrecorded transformation.

    This lightweight helper preserves existing callers. Use ProvenanceGraph.derive()
    when the transformation itself must become an explicit, versioned lineage node.
    """
    if any(not isinstance(arg, Arg) for arg in inputs):
        raise TypeError(
            "derive() accepts only Arg inputs; label every source before deriving"
        )
    joined = Label.join(*(arg.label for arg in inputs))
    refs = (
        frozenset().union(*(arg.lineage_refs for arg in inputs))
        if inputs
        else frozenset()
    )
    incomplete = not inputs or any(
        not arg.lineage_refs or arg.lineage_incomplete for arg in inputs
    )
    return Arg(value, joined, refs, incomplete)


@dataclass(frozen=True)
class LineageNode:
    """Immutable metadata for one version of an information object.

    content_digest is SHA-256 over the content bytes as produced by the trusted
    adapter. The graph stores this digest, never the content itself.
    """

    object_id: str
    version_id: str
    source: str
    source_class: str
    content_digest: str
    label: Label
    parent_ids: tuple[str, ...] = ()
    transformation: str = "source"
    purpose: str | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "object_id",
            "version_id",
            "source",
            "source_class",
            "transformation",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} must be a non-empty string")
        if not isinstance(self.content_digest, str) or not _SHA256_RE.fullmatch(
            self.content_digest
        ):
            raise ValueError("content_digest must be a lowercase SHA-256 hex digest")
        if not isinstance(self.label, Label):
            raise TypeError("lineage label must be a Label from a trusted adapter")
        if self.purpose is not None and (
            not isinstance(self.purpose, str) or not self.purpose
        ):
            raise ValueError("purpose must be a non-empty string or None")
        if isinstance(self.parent_ids, (str, bytes)):
            raise TypeError("parent_ids must be a collection of node identifiers")
        raw_parents = tuple(self.parent_ids)
        if any(not isinstance(parent, str) or not parent for parent in raw_parents):
            raise ValueError("parent identifiers must be non-empty strings")
        parents = tuple(sorted(set(raw_parents)))
        object.__setattr__(self, "parent_ids", parents)

    def as_dict(self) -> dict[str, object]:
        return {
            "object_id": self.object_id,
            "version_id": self.version_id,
            "source": self.source,
            "source_class": self.source_class,
            "content_digest": self.content_digest,
            "label": {
                "integrity": self.label.integrity,
                "sensitivity": self.label.sensitivity,
                "tenants": sorted(self.label.tenants),
                "tenant_unknown": self.label.tenant_unknown,
                "origins": sorted(self.label.origins),
            },
            "parent_ids": list(self.parent_ids),
            "transformation": self.transformation,
            "purpose": self.purpose,
        }

    @property
    def node_id(self) -> str:
        blob = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class ProvenanceGraph:
    """Policy facts plus an append-only, in-memory information-lineage DAG.

    A node can refer only to parents already inserted into this graph. This makes
    cycles impossible through the public API. Object/version pairs are immutable:
    a different record for an existing pair is rejected instead of silently
    replacing its lineage. Persistence and connector-level enforcement are separate
    integration work and are not provided by this class.
    """

    records: list[ProvenanceRecord] = field(default_factory=list)
    _lineage_nodes: dict[str, LineageNode] = field(
        default_factory=dict, init=False, repr=False
    )
    _version_index: dict[tuple[str, str], str] = field(
        default_factory=dict, init=False, repr=False
    )

    @property
    def lineage_nodes(self) -> dict[str, LineageNode]:
        """Return a snapshot so callers cannot mutate the graph's internal index."""
        return dict(self._lineage_nodes)

    def get_node(self, node_id: str) -> LineageNode | None:
        return self._lineage_nodes.get(node_id)

    def ancestors(self, node_id: str) -> tuple[LineageNode, ...]:
        """Return the root-to-node lineage chain, deduplicating shared parents."""
        if node_id not in self._lineage_nodes:
            raise KeyError(node_id)
        ordered: list[LineageNode] = []
        visited = set()
        visiting = set()

        def visit(current_id: str) -> None:
            if current_id in visiting:
                raise RuntimeError("cycle detected in information-lineage graph")
            if current_id in visited:
                return
            node = self._lineage_nodes.get(current_id)
            if node is None:
                raise ValueError("lineage graph contains a missing parent reference")
            visiting.add(current_id)
            for parent_id in node.parent_ids:
                visit(parent_id)
            visiting.remove(current_id)
            visited.add(current_id)
            ordered.append(node)

        visit(node_id)
        return tuple(ordered)

    def add_lineage_node(self, node: LineageNode) -> LineageNode:
        if not isinstance(node, LineageNode):
            raise TypeError("node must be a LineageNode")
        if not node.parent_ids and node.transformation != "source":
            raise ValueError("a parentless lineage node must be an explicit source")
        if not node.parent_ids and node.source not in node.label.origins:
            raise ValueError(
                "a source node must retain its source identifier in label origins"
            )
        if node.parent_ids and node.transformation == "source":
            raise ValueError("a derived lineage node must name its transformation")

        parents: list[LineageNode] = []
        for parent_id in node.parent_ids:
            parent = self._lineage_nodes.get(parent_id)
            if parent is None:
                raise ValueError(
                    "all lineage parents must exist before the child is added"
                )
            parents.append(parent)

        # Transformations may become more restrictive, but may never erase a
        # parent's untrusted status, sensitivity, origins, tenant or unknown-tenant flag.
        for parent in parents:
            if (
                parent.label.integrity == "untrusted"
                and node.label.integrity != "untrusted"
            ):
                raise ValueError("a transformation cannot upgrade untrusted integrity")
            if node.label.sensitivity < parent.label.sensitivity:
                raise ValueError("a transformation cannot lower sensitivity")
            if not parent.label.origins.issubset(node.label.origins):
                raise ValueError("a transformation cannot erase provenance origins")
            if not parent.label.tenants.issubset(node.label.tenants):
                raise ValueError("a transformation cannot erase tenant lineage")
            if parent.label.tenant_unknown and not node.label.tenant_unknown:
                raise ValueError(
                    "a transformation cannot erase unknown-tenant provenance"
                )

        version_key = (node.object_id, node.version_id)
        existing_id = self._version_index.get(version_key)
        if existing_id is not None:
            existing = self._lineage_nodes[existing_id]
            if existing != node:
                raise ValueError(
                    "object/version identifiers are immutable and already have different lineage"
                )
            return existing

        node_id = node.node_id
        existing_node = self._lineage_nodes.get(node_id)
        if existing_node is not None:
            if existing_node != node:
                raise ValueError(
                    "lineage node digest collision with different contents"
                )
            return existing_node
        self._lineage_nodes[node_id] = node
        self._version_index[version_key] = node_id
        return node

    def add_source(
        self,
        value: Any,
        *,
        object_id: str,
        version_id: str,
        source: str,
        source_class: str,
        content_digest: str,
        label: Label,
        purpose: str | None = None,
    ) -> Arg:
        """Record a trusted-adapter source version and return a lineage-bound Arg."""
        if not isinstance(label, Label):
            raise TypeError("source label must be assigned by a trusted adapter")
        if not isinstance(source, str) or not source:
            raise ValueError("source must be a non-empty trusted source identifier")
        source_label = replace(label, origins=label.origins | frozenset({source}))
        node = LineageNode(
            object_id=object_id,
            version_id=version_id,
            source=source,
            source_class=source_class,
            content_digest=content_digest,
            label=source_label,
            transformation="source",
            purpose=purpose,
        )
        stored = self.add_lineage_node(node)
        return Arg(value, stored.label, frozenset({stored.node_id}))

    def derive(
        self,
        value: Any,
        *inputs: Arg,
        object_id: str,
        version_id: str,
        content_digest: str,
        transformation: str,
        purpose: str | None = None,
        source: str = "model_generated",
    ) -> Arg:
        """Record a transformed object with explicit, existing parent lineage."""
        if not inputs or any(not isinstance(arg, Arg) for arg in inputs):
            raise TypeError("lineage derive requires one or more Arg inputs")
        if any(not arg.lineage_refs or arg.lineage_incomplete for arg in inputs):
            raise ValueError(
                "every derived input requires complete explicit source lineage references"
            )
        parent_ids = frozenset().union(*(arg.lineage_refs for arg in inputs))
        if any(ref not in self._lineage_nodes for ref in parent_ids):
            raise ValueError(
                "derived value references lineage not present in this graph"
            )
        label = Label.join(*(arg.label for arg in inputs))
        node = LineageNode(
            object_id=object_id,
            version_id=version_id,
            source=source,
            source_class="model_generated",
            content_digest=content_digest,
            label=label,
            parent_ids=tuple(parent_ids),
            transformation=transformation,
            purpose=purpose,
        )
        stored = self.add_lineage_node(node)
        return Arg(value, stored.label, frozenset({stored.node_id}))

    def add(
        self,
        source: str,
        entity: str,
        attribute: str,
        value: Any,
        explanation: str = "",
    ) -> ProvenanceRecord:
        rec = ProvenanceRecord(source, entity, attribute, value, explanation)
        self.records.append(rec)
        return rec

    def from_context(self, context: dict[str, Any], source: str = "context") -> None:
        for key, value in (context or {}).items():
            if isinstance(value, dict):
                for attribute, item in value.items():
                    self.add(
                        source,
                        str(key),
                        str(attribute),
                        item,
                        f"context value for {key}.{attribute}",
                    )
            else:
                self.add(source, str(key), "value", value, f"context value for {key}")

    def __iter__(self):
        return iter(self.records)


__all__ = [
    "SENSITIVITY",
    "Arg",
    "Label",
    "LineageNode",
    "ProvenanceGraph",
    "derive",
]
