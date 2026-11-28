"""Trusted memory, connector and inter-agent adapters for PACA++ New.

The SQLite value table is separate from lineage metadata. Inter-agent message
handling lives in :mod:`paca.messages`; this module owns memory storage and policy.
Reads consult metadata,
authorization, revocation and authority state before fetching the value bytes. Python
object boundaries are not host-security boundaries: deployments must keep the value
database and adapter credentials inaccessible to agent-controlled code.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import sqlite3
import time
from collections.abc import Callable, Iterable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .authority import grant_pattern_is_subset
from .authority_runtime import (
    AuthorityRegistryError,
    HMACCapabilityAuthority,
)
from .durable import SQLiteProvenanceRepository
from .provenance import Arg, Label, LineageNode

if TYPE_CHECKING:
    from .agent_runtime import PACAAgentRuntime
    from .messages import HMACAgentMessageCodec


class MemoryAccessDenied(PermissionError):
    """Metadata policy or active authority denied a memory operation."""


class MemoryIntegrityError(RuntimeError):
    """Stored value bytes do not match the immutable lineage digest."""


def canonical_value_bytes(value: Any) -> bytes:
    """Canonical JSON encoding for the reference value backend.

    Only JSON values are accepted. Non-finite floats, non-string mapping keys and
    arbitrary Python objects fail closed rather than being pickled or executed.
    """
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TypeError("memory values must be finite, JSON-serialisable data") from exc


class SQLiteMemoryValueStore:
    """Immutable, file-backed memory values kept apart from lineage metadata."""

    def __init__(
        self,
        database: str | os.PathLike[str],
        *,
        timeout: float = 10.0,
    ) -> None:
        raw = os.fspath(database)
        if raw == ":memory:" or not raw:
            raise ValueError("durable memory requires a file-backed SQLite database")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.database = Path(raw).expanduser().resolve()
        self.timeout = float(timeout)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS memory_store_meta "
                "(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
            )
            row = connection.execute(
                "SELECT value FROM memory_store_meta WHERE key='schema_version'"
            ).fetchone()
            version = int(row["value"]) if row else 0
            if version > 1:
                raise MemoryIntegrityError(
                    "memory value-store schema is newer than this package"
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS memory_values ("
                "object_id TEXT NOT NULL,"
                "version_id TEXT NOT NULL,"
                "payload_json TEXT NOT NULL,"
                "content_digest TEXT NOT NULL,"
                "PRIMARY KEY(object_id,version_id))"
            )
            if version < 1:
                connection.execute(
                    "INSERT INTO memory_store_meta(key,value) VALUES('schema_version','1')"
                )
        with contextlib.suppress(OSError):
            os.chmod(self.database, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database),
            timeout=self.timeout,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={int(self.timeout * 1000)}")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def put_if_absent(
        self,
        object_id: str,
        version_id: str,
        value: Any,
        content_digest: str,
    ) -> None:
        encoded = canonical_value_bytes(value).decode("utf-8")
        calculated = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(calculated, content_digest):
            raise MemoryIntegrityError(
                "caller-supplied content digest does not match the value"
            )
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT payload_json,content_digest FROM memory_values "
                    "WHERE object_id=? AND version_id=?",
                    (object_id, version_id),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["payload_json"] != encoded
                        or existing["content_digest"] != content_digest
                    ):
                        raise MemoryIntegrityError(
                            "memory object/version is immutable and already has different bytes"
                        )
                    connection.commit()
                    return
                connection.execute(
                    "INSERT INTO memory_values(object_id,version_id,payload_json,content_digest) "
                    "VALUES(?,?,?,?)",
                    (object_id, version_id, encoded, content_digest),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def get(self, object_id: str, version_id: str) -> tuple[Any, str] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload_json,content_digest FROM memory_values "
                "WHERE object_id=? AND version_id=?",
                (object_id, version_id),
            ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row["payload_json"])
            if canonical_value_bytes(value).decode("utf-8") != row["payload_json"]:
                raise MemoryIntegrityError("stored memory payload is not canonical")
            return value, row["content_digest"]
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise MemoryIntegrityError(
                "stored memory payload is not valid canonical JSON"
            ) from exc


@dataclass(frozen=True)
class MemoryAccessContext:
    principal: str
    tenant: str
    purpose: str
    authority_id: str
    max_calls: int


@dataclass(frozen=True)
class _AuthorizedMemoryReference:
    context: MemoryAccessContext
    node: LineageNode
    ancestry: tuple[LineageNode, ...]
    authority_ids: tuple[str, ...]


class TrustedMemoryAdapter:
    """Memory API that enforces metadata and authority checks before value release."""

    def __init__(
        self,
        repository: SQLiteProvenanceRepository,
        values: SQLiteMemoryValueStore,
        authority: HMACCapabilityAuthority,
        *,
        authorize: Callable[[MemoryAccessContext, LineageNode], bool] | None = None,
        clock=time.time,
    ) -> None:
        self.repository = repository
        self._values = values
        self.authority = authority
        self.registry = authority.registry
        # Missing policy is deny, never allow.
        self._authorize = authorize or (lambda _context, _node: False)
        self.clock = clock

    def _verified_context(
        self,
        capability_token: str,
        action: str,
        object_id: str,
        purpose: str,
    ) -> MemoryAccessContext:
        try:
            signed = self.authority.verify(capability_token)
            record = signed.capability.authority_lineage
            if record is None:
                raise MemoryAccessDenied("memory capability has no authority lineage")
            grants = dict(record.grants).get(action, ())
            if not any(
                grant_pattern_is_subset(object_id, pattern) for pattern in grants
            ):
                raise MemoryAccessDenied(
                    "memory object is outside the signed capability scope"
                )
            if record.purpose != purpose:
                raise MemoryAccessDenied(
                    "memory purpose does not match the signed capability"
                )
            self.registry.assert_active(record.authority_id)
            return MemoryAccessContext(
                record.principal,
                record.tenant,
                purpose,
                record.authority_id,
                signed.capability.max_calls,
            )
        except MemoryAccessDenied:
            raise
        except Exception as exc:
            raise MemoryAccessDenied(
                "memory capability authentication or active-state check failed"
            ) from exc

    @staticmethod
    def _check_label_for_tenant(label: Label, tenant: str) -> None:
        if label.tenant_unknown:
            raise MemoryAccessDenied("memory lineage has unknown tenant ownership")
        if any(value != tenant for value in label.tenants):
            raise MemoryAccessDenied(
                "memory lineage crosses the caller tenant boundary"
            )

    def _consume_budget(self, context: MemoryAccessContext) -> None:
        try:
            self.registry.consume_effect(
                context.authority_id,
                max_calls=context.max_calls,
            )
            self.registry.assert_active(context.authority_id)
        except AuthorityRegistryError as exc:
            raise MemoryAccessDenied(
                "memory operation budget exhausted or authority revoked"
            ) from exc

    def _authorised_node(
        self,
        object_id: str,
        version_id: str,
        *,
        purpose: str,
        capability_token: str,
    ) -> tuple[
        MemoryAccessContext, LineageNode, tuple[LineageNode, ...], tuple[str, ...]
    ]:
        """Apply the complete read policy to lineage metadata without fetching values."""
        context = self._verified_context(
            capability_token,
            "mem_read",
            object_id,
            purpose,
        )
        node = self.repository.get_version(object_id, version_id)
        if node is None:
            raise MemoryAccessDenied("memory object/version is unknown")
        if node.purpose != purpose:
            raise MemoryAccessDenied("memory purpose mismatch")
        ancestry = self.repository.ancestors(node.node_id)
        if self.repository.revoked_nodes(ancestor.node_id for ancestor in ancestry):
            raise MemoryAccessDenied("memory depends on revoked information lineage")
        for ancestor in ancestry:
            self._check_label_for_tenant(ancestor.label, context.tenant)
            if ancestor.purpose is not None and ancestor.purpose != purpose:
                raise MemoryAccessDenied(
                    "memory ancestry is bound to a different purpose"
                )

        authority_ids = self.repository.authority_ids_for_node(node.node_id)
        for inherited_authority_id in authority_ids:
            try:
                self.registry.assert_active(inherited_authority_id)
            except AuthorityRegistryError as exc:
                raise MemoryAccessDenied(
                    "memory depends on an expired, revoked or stale authority"
                ) from exc
        try:
            authorised = all(
                bool(self._authorize(context, ancestor)) for ancestor in ancestry
            )
        except Exception as exc:
            raise MemoryAccessDenied("memory policy evaluation failed closed") from exc
        if not authorised:
            raise MemoryAccessDenied("memory read denied by metadata policy")
        return context, node, ancestry, authority_ids

    def _recheck_read_authority(
        self,
        context: MemoryAccessContext,
        ancestry: tuple[LineageNode, ...],
        authority_ids: tuple[str, ...],
    ) -> None:
        """Recheck authority and information revocation after a mediated operation."""
        try:
            self.registry.assert_active(context.authority_id)
            for inherited_authority_id in authority_ids:
                self.registry.assert_active(inherited_authority_id)
            if self.repository.revoked_nodes(ancestor.node_id for ancestor in ancestry):
                raise MemoryAccessDenied("memory lineage was revoked during retrieval")
            if not all(
                bool(self._authorize(context, ancestor)) for ancestor in ancestry
            ):
                raise MemoryAccessDenied(
                    "memory application policy changed during retrieval"
                )
        except MemoryAccessDenied:
            raise
        except AuthorityRegistryError as exc:
            raise MemoryAccessDenied(
                "memory authority was revoked during retrieval"
            ) from exc
        except Exception as exc:
            raise MemoryAccessDenied(
                "memory application policy revalidation failed closed"
            ) from exc

    @staticmethod
    def _assert_label_covers_lineage(
        label: Label,
        ancestry: tuple[LineageNode, ...],
    ) -> None:
        """Reject request labels that hide any restriction in durable ancestry."""
        if not isinstance(label, Label):
            raise MemoryAccessDenied("lineage-bound request label is invalid")
        for ancestor in ancestry:
            source = ancestor.label
            if source.integrity == "untrusted" and label.integrity != "untrusted":
                raise MemoryAccessDenied(
                    "request label upgrades untrusted lineage integrity"
                )
            if label.sensitivity < source.sensitivity:
                raise MemoryAccessDenied("request label lowers lineage sensitivity")
            if not source.origins.issubset(label.origins):
                raise MemoryAccessDenied("request label omits lineage origins")
            if not source.tenants.issubset(label.tenants):
                raise MemoryAccessDenied("request label omits lineage tenant ownership")
            if source.tenant_unknown and not label.tenant_unknown:
                raise MemoryAccessDenied("request label hides unknown-tenant lineage")

    def authorize_argument(
        self,
        argument: Arg,
        *,
        purpose: str,
        capability_token: str,
    ) -> tuple[_AuthorizedMemoryReference, ...]:
        """Validate request argument bytes against the exact durable lineage node.

        Every protected effect argument must be captured by a trusted ingress
        adapter and bound to one immutable persisted value/version. A caller-created
        Arg, including one labelled "trusted", is not evidence of source identity.
        Persisted combined derivations must be committed as one new lineage node.
        """
        if not isinstance(argument, Arg):
            raise MemoryAccessDenied("effect argument is not a typed PACA Arg")
        if argument.lineage_incomplete:
            raise MemoryAccessDenied(
                "effect argument has incomplete information lineage"
            )
        if not argument.lineage_refs:
            raise MemoryAccessDenied(
                "protected effect argument is untracked; capture it through trusted ingress "
                "and persist its value before use"
            )
        refs = tuple(argument.lineage_refs)
        if len(refs) != 1:
            raise MemoryAccessDenied(
                "effect argument must bind to one persisted value/version; "
                "persist combined derivations before use"
            )
        node = self.repository.get_node(refs[0])
        if node is None:
            raise MemoryAccessDenied(
                "effect argument references unknown information lineage"
            )
        context, verified, ancestry, authority_ids = self._authorised_node(
            node.object_id,
            node.version_id,
            purpose=purpose,
            capability_token=capability_token,
        )
        if verified.node_id != refs[0]:
            raise MemoryAccessDenied(
                "effect argument lineage identity does not match the stored node"
            )
        try:
            digest = hashlib.sha256(canonical_value_bytes(argument.value)).hexdigest()
        except TypeError as exc:
            raise MemoryAccessDenied(
                "effect argument is not canonical JSON bound to its lineage"
            ) from exc
        if not hmac.compare_digest(digest, verified.content_digest):
            raise MemoryAccessDenied(
                "effect argument bytes do not match their immutable lineage digest"
            )
        self._assert_label_covers_lineage(argument.label, ancestry)
        self._consume_budget(context)
        access = _AuthorizedMemoryReference(
            context,
            verified,
            ancestry,
            authority_ids,
        )
        self._recheck_read_authority(context, ancestry, authority_ids)
        return (access,)

    def authorize_reference(
        self,
        node_id: str,
        *,
        label: Label,
        purpose: str,
        capability_token: str,
    ) -> _AuthorizedMemoryReference:
        """Authorize a resource-lineage reference and its externally supplied label."""
        if not isinstance(node_id, str) or not node_id:
            raise MemoryAccessDenied("resource lineage reference is invalid")
        node = self.repository.get_node(node_id)
        if node is None:
            raise MemoryAccessDenied("resource references unknown information lineage")
        context, verified, ancestry, authority_ids = self._authorised_node(
            node.object_id,
            node.version_id,
            purpose=purpose,
            capability_token=capability_token,
        )
        if verified.node_id != node_id:
            raise MemoryAccessDenied(
                "resource lineage identity does not match the stored node"
            )
        self._assert_label_covers_lineage(label, ancestry)
        self._consume_budget(context)
        access = _AuthorizedMemoryReference(
            context,
            verified,
            ancestry,
            authority_ids,
        )
        self._recheck_read_authority(context, ancestry, authority_ids)
        return access

    def revalidate_authorized_references(
        self,
        accesses: Iterable[_AuthorizedMemoryReference],
        *,
        capability_token: str,
        purpose: str,
    ) -> None:
        """Re-run policy, authority and revocation checks immediately before an effect."""
        for access in accesses:
            context, node, ancestry, authority_ids = self._authorised_node(
                access.node.object_id,
                access.node.version_id,
                purpose=purpose,
                capability_token=capability_token,
            )
            if (
                node.node_id != access.node.node_id
                or context.authority_id != access.context.authority_id
            ):
                raise MemoryAccessDenied(
                    "effect lineage authorization changed before execution"
                )
            self._recheck_read_authority(context, ancestry, authority_ids)

    def revalidate_read_access(
        self,
        object_id: str,
        version_id: str,
        *,
        purpose: str,
        capability_token: str,
    ) -> LineageNode:
        """Recheck current read policy and revocation without charging a second read.

        Use after a mediated external/provider operation and before returning its
        result, so authority or metadata-policy changes during that operation
        fail closed. The caller must already have completed the corresponding
        budgeted read or authorization.
        """
        context, node, ancestry, authority_ids = self._authorised_node(
            object_id,
            version_id,
            purpose=purpose,
            capability_token=capability_token,
        )
        self._recheck_read_authority(context, ancestry, authority_ids)
        return node

    def authorize_metadata(
        self,
        object_id: str,
        version_id: str,
        *,
        purpose: str,
        capability_token: str,
    ) -> LineageNode:
        """Authorize metadata disclosure without fetching protected value bytes.

        Namespace listings and similar metadata-only APIs must enforce the same
        ancestry, tenant, authority and application policy checks as value reads.
        One durable memory-read budget unit is consumed for each disclosed object.
        """
        context, node, ancestry, authority_ids = self._authorised_node(
            object_id,
            version_id,
            purpose=purpose,
            capability_token=capability_token,
        )
        self._consume_budget(context)
        self._recheck_read_authority(context, ancestry, authority_ids)
        return node

    def _write(self, node: LineageNode, value: Any, capability_token: str) -> Arg:
        context = self._verified_context(
            capability_token,
            "mem_write",
            node.object_id,
            node.purpose or "",
        )
        authority = self.registry.assert_active(context.authority_id)
        self._check_label_for_tenant(node.label, authority.tenant)
        if node.purpose != authority.purpose:
            raise MemoryAccessDenied(
                "memory purpose does not match the writing authority"
            )
        encoded = canonical_value_bytes(value)
        digest = hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(digest, node.content_digest):
            raise MemoryIntegrityError(
                "lineage content digest was not computed from the exact stored value"
            )
        # Memory writes consume the same durable operation budget as tool effects.
        self._consume_budget(context)
        # Metadata is committed first. A crash before value insertion leaves an
        # unreadable orphan, not an untracked value that can be released.
        stored = self.repository.add(node)
        self.repository.bind_authority(stored.node_id, context.authority_id)
        self._values.put_if_absent(
            stored.object_id,
            stored.version_id,
            value,
            stored.content_digest,
        )
        try:
            self.registry.assert_active(context.authority_id)
        except AuthorityRegistryError as exc:
            raise MemoryAccessDenied(
                "memory write authority was revoked during persistence"
            ) from exc
        return Arg(value, stored.label, frozenset({stored.node_id}), False)

    def write_derived(
        self,
        value: Any,
        *inputs: Arg,
        object_id: str,
        version_id: str,
        transformation: str,
        purpose: str,
        capability_token: str,
    ) -> Arg:
        if not inputs or any(not isinstance(item, Arg) for item in inputs):
            raise TypeError("derived memory requires one or more Arg inputs")
        if any(not item.lineage_refs or item.lineage_incomplete for item in inputs):
            raise MemoryAccessDenied(
                "cannot persist a derived memory with incomplete lineage"
            )
        # Validate the exact value digest, current read authority, revocation,
        # tenant/purpose ancestry and application metadata policy for every input.
        # Persisted intermediates are required for multi-step transformations.
        input_accesses = []
        for item in inputs:
            input_accesses.extend(
                self.authorize_argument(
                    item,
                    purpose=purpose,
                    capability_token=capability_token,
                )
            )
        parent_ids = tuple(sorted(set().union(*(item.lineage_refs for item in inputs))))
        label = Label.join(*(item.label for item in inputs)).as_model_output()
        encoded = canonical_value_bytes(value)
        node = LineageNode(
            object_id=object_id,
            version_id=version_id,
            source="paca-model-runtime",
            source_class="model_generated",
            content_digest=hashlib.sha256(encoded).hexdigest(),
            label=label,
            parent_ids=parent_ids,
            transformation=transformation,
            purpose=purpose,
        )
        written = self._write(node, value, capability_token)
        # Re-run the configured application policy, authority and revocation
        # checks after persistence. The derived node remains unreadable if a
        # dependency changes state during the write.
        self.revalidate_authorized_references(
            input_accesses,
            capability_token=capability_token,
            purpose=purpose,
        )
        return written

    def summarise(
        self,
        summary: Any,
        *inputs: Arg,
        object_id: str,
        version_id: str,
        purpose: str,
        capability_token: str,
    ) -> Arg:
        return self.write_derived(
            summary,
            *inputs,
            object_id=object_id,
            version_id=version_id,
            transformation="summarise",
            purpose=purpose,
            capability_token=capability_token,
        )

    def compact(
        self,
        compacted_value: Any,
        *inputs: Arg,
        object_id: str,
        version_id: str,
        purpose: str,
        capability_token: str,
    ) -> Arg:
        return self.write_derived(
            compacted_value,
            *inputs,
            object_id=object_id,
            version_id=version_id,
            transformation="compact",
            purpose=purpose,
            capability_token=capability_token,
        )

    def read(
        self,
        object_id: str,
        version_id: str,
        *,
        purpose: str,
        capability_token: str,
    ) -> Arg:
        # Authenticate the complete lineage and policy before fetching any value bytes.
        context, node, ancestry, authority_ids = self._authorised_node(
            object_id,
            version_id,
            purpose=purpose,
            capability_token=capability_token,
        )
        self._consume_budget(context)
        stored = self._values.get(object_id, version_id)
        if stored is None:
            raise MemoryIntegrityError(
                "lineage metadata exists but the memory value is missing"
            )
        value, stored_digest = stored
        actual_digest = hashlib.sha256(canonical_value_bytes(value)).hexdigest()
        if not hmac.compare_digest(
            actual_digest, node.content_digest
        ) or not hmac.compare_digest(stored_digest, node.content_digest):
            self.repository.revoke_lineage(
                node.node_id,
                "memory content digest mismatch",
                revoked_at=int(self.clock()),
            )
            raise MemoryIntegrityError(
                "memory bytes do not match their immutable lineage digest"
            )
        # Re-check after fetching and validating bytes to narrow the concurrent
        # revocation window. Remote sinks still need commit-time authorization.
        self._recheck_read_authority(context, ancestry, authority_ids)
        return Arg(value, node.label, frozenset({node.node_id}), False)


class TrustedConnectorAdapter:
    """Fixed-identity ingress adapter; the model cannot choose its source label."""

    def __init__(
        self,
        memory: TrustedMemoryAdapter,
        *,
        connector_id: str,
        source_class: str,
        tenant: str,
        sensitivity: int = 1,
        integrity: str = "untrusted",
    ) -> None:
        for name, value in (
            ("connector_id", connector_id),
            ("source_class", source_class),
            ("tenant", tenant),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(name + " must be a non-empty string")
        if integrity not in {"trusted", "untrusted"}:
            raise ValueError("integrity must be trusted or untrusted")
        if (
            isinstance(sensitivity, bool)
            or not isinstance(sensitivity, int)
            or not 0 <= sensitivity <= 3
        ):
            raise ValueError("sensitivity must be between 0 and 3")
        self.memory = memory
        self.connector_id = connector_id
        self.source_class = source_class
        self.tenant = tenant
        self.sensitivity = sensitivity
        self.integrity = integrity

    def ingest(
        self,
        value: Any,
        *,
        object_id: str,
        version_id: str,
        purpose: str,
        capability_token: str,
    ) -> Arg:
        encoded = canonical_value_bytes(value)
        node = LineageNode(
            object_id=object_id,
            version_id=version_id,
            source=self.connector_id,
            source_class=self.source_class,
            content_digest=hashlib.sha256(encoded).hexdigest(),
            label=Label(
                integrity=self.integrity,
                sensitivity=self.sensitivity,
                tenant=self.tenant if self.sensitivity > 0 else None,
                origins=frozenset({self.connector_id}),
            ),
            transformation="source",
            purpose=purpose,
        )
        return self.memory._write(node, value, capability_token)



def __getattr__(name: str) -> Any:
    """Load compatibility exports lazily to keep module dependencies acyclic."""
    if name == "PACAAgentRuntime":
        from .agent_runtime import PACAAgentRuntime

        return PACAAgentRuntime
    if name == "HMACAgentMessageCodec":
        from .messages import HMACAgentMessageCodec

        globals()[name] = HMACAgentMessageCodec
        return HMACAgentMessageCodec
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "HMACAgentMessageCodec",
    "MemoryAccessContext",
    "MemoryAccessDenied",
    "MemoryIntegrityError",
    "PACAAgentRuntime",
    "SQLiteMemoryValueStore",
    "TrustedConnectorAdapter",
    "TrustedMemoryAdapter",
    "canonical_value_bytes",
]
