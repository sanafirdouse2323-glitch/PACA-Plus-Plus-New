"""Trusted memory, connector and inter-agent adapters for PACA++ New.

The SQLite value table is separate from lineage metadata. Reads consult metadata,
authorization, revocation and authority state before fetching the value bytes. Python
object boundaries are not host-security boundaries: deployments must keep the value
database and adapter credentials inaccessible to agent-controlled code.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import inspect
import json
import os
import sqlite3
import secrets
from contextlib import closing
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Tuple

from .authority import grant_pattern_is_subset
from .authority_runtime import (
    AuthorityRegistryError,
    HMACCapabilityAuthority,
)
from .durable import LineageIntegrityError, SQLiteProvenanceRepository
from .provenance import Arg, Label, LineageNode
from .runtime import Decision, Request, Tool


def _b64encode(value: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    import base64
    return base64.b64decode(
        value + ("=" * (-len(value) % 4)), altchars=b"-_", validate=True,
    )


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
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
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
                raise MemoryIntegrityError("memory value-store schema is newer than this package")
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
        try:
            os.chmod(self.database, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database), timeout=self.timeout, isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=%d" % int(self.timeout * 1000))
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
            raise MemoryIntegrityError("caller-supplied content digest does not match the value")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT payload_json,content_digest FROM memory_values "
                    "WHERE object_id=? AND version_id=?",
                    (object_id, version_id),
                ).fetchone()
                if existing is not None:
                    if existing["payload_json"] != encoded or existing["content_digest"] != content_digest:
                        raise MemoryIntegrityError("memory object/version is immutable and already has different bytes")
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

    def get(self, object_id: str, version_id: str) -> Optional[Tuple[Any, str]]:
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
            raise MemoryIntegrityError("stored memory payload is not valid canonical JSON") from exc


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
    ancestry: Tuple[LineageNode, ...]
    authority_ids: Tuple[str, ...]


class TrustedMemoryAdapter:
    """Memory API that enforces metadata and authority checks before value release."""

    def __init__(
        self,
        repository: SQLiteProvenanceRepository,
        values: SQLiteMemoryValueStore,
        authority: HMACCapabilityAuthority,
        *,
        authorize: Optional[Callable[[MemoryAccessContext, LineageNode], bool]] = None,
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
        self, capability_token: str, action: str, object_id: str, purpose: str,
    ) -> MemoryAccessContext:
        try:
            signed = self.authority.verify(capability_token)
            record = signed.capability.authority_lineage
            if record is None:
                raise MemoryAccessDenied("memory capability has no authority lineage")
            grants = dict(record.grants).get(action, ())
            if not any(grant_pattern_is_subset(object_id, pattern) for pattern in grants):
                raise MemoryAccessDenied("memory object is outside the signed capability scope")
            if record.purpose != purpose:
                raise MemoryAccessDenied("memory purpose does not match the signed capability")
            self.registry.assert_active(record.authority_id)
            return MemoryAccessContext(
                record.principal, record.tenant, purpose,
                record.authority_id, signed.capability.max_calls,
            )
        except MemoryAccessDenied:
            raise
        except Exception as exc:
            raise MemoryAccessDenied("memory capability authentication or active-state check failed") from exc

    @staticmethod
    def _check_label_for_tenant(label: Label, tenant: str) -> None:
        if label.tenant_unknown:
            raise MemoryAccessDenied("memory lineage has unknown tenant ownership")
        if any(value != tenant for value in label.tenants):
            raise MemoryAccessDenied("memory lineage crosses the caller tenant boundary")

    def _consume_budget(self, context: MemoryAccessContext) -> None:
        try:
            self.registry.consume_effect(
                context.authority_id, max_calls=context.max_calls,
            )
            self.registry.assert_active(context.authority_id)
        except AuthorityRegistryError as exc:
            raise MemoryAccessDenied("memory operation budget exhausted or authority revoked") from exc

    def _authorised_node(
        self,
        object_id: str,
        version_id: str,
        *,
        purpose: str,
        capability_token: str,
    ) -> Tuple[MemoryAccessContext, LineageNode, Tuple[LineageNode, ...], Tuple[str, ...]]:
        """Apply the complete read policy to lineage metadata without fetching values."""
        context = self._verified_context(
            capability_token, "mem_read", object_id, purpose,
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
                raise MemoryAccessDenied("memory ancestry is bound to a different purpose")

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
        ancestry: Tuple[LineageNode, ...],
        authority_ids: Tuple[str, ...],
    ) -> None:
        """Recheck authority and information revocation after a mediated operation."""
        try:
            self.registry.assert_active(context.authority_id)
            for inherited_authority_id in authority_ids:
                self.registry.assert_active(inherited_authority_id)
            if self.repository.revoked_nodes(
                ancestor.node_id for ancestor in ancestry
            ):
                raise MemoryAccessDenied("memory lineage was revoked during retrieval")
            if not all(bool(self._authorize(context, ancestor)) for ancestor in ancestry):
                raise MemoryAccessDenied("memory application policy changed during retrieval")
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
        ancestry: Tuple[LineageNode, ...],
    ) -> None:
        """Reject request labels that hide any restriction in durable ancestry."""
        if not isinstance(label, Label):
            raise MemoryAccessDenied("lineage-bound request label is invalid")
        for ancestor in ancestry:
            source = ancestor.label
            if source.integrity == "untrusted" and label.integrity != "untrusted":
                raise MemoryAccessDenied("request label upgrades untrusted lineage integrity")
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
    ) -> Tuple[_AuthorizedMemoryReference, ...]:
        """Validate request argument bytes against the exact durable lineage node.

        Every protected effect argument must be captured by a trusted ingress
        adapter and bound to one immutable persisted value/version. A caller-created
        Arg, including one labelled "trusted", is not evidence of source identity.
        Persisted combined derivations must be committed as one new lineage node.
        """
        if not isinstance(argument, Arg):
            raise MemoryAccessDenied("effect argument is not a typed PACA Arg")
        if argument.lineage_incomplete:
            raise MemoryAccessDenied("effect argument has incomplete information lineage")
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
            raise MemoryAccessDenied("effect argument references unknown information lineage")
        context, verified, ancestry, authority_ids = self._authorised_node(
            node.object_id,
            node.version_id,
            purpose=purpose,
            capability_token=capability_token,
        )
        if verified.node_id != refs[0]:
            raise MemoryAccessDenied("effect argument lineage identity does not match the stored node")
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
            context, verified, ancestry, authority_ids,
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
            raise MemoryAccessDenied("resource lineage identity does not match the stored node")
        self._assert_label_covers_lineage(label, ancestry)
        self._consume_budget(context)
        access = _AuthorizedMemoryReference(
            context, verified, ancestry, authority_ids,
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
                raise MemoryAccessDenied("effect lineage authorization changed before execution")
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
            object_id, version_id, purpose=purpose,
            capability_token=capability_token,
        )
        self._consume_budget(context)
        self._recheck_read_authority(context, ancestry, authority_ids)
        return node

    def _write(self, node: LineageNode, value: Any, capability_token: str) -> Arg:
        context = self._verified_context(
            capability_token, "mem_write", node.object_id, node.purpose or "",
        )
        authority = self.registry.assert_active(context.authority_id)
        self._check_label_for_tenant(node.label, authority.tenant)
        if node.purpose != authority.purpose:
            raise MemoryAccessDenied("memory purpose does not match the writing authority")
        encoded = canonical_value_bytes(value)
        digest = hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(digest, node.content_digest):
            raise MemoryIntegrityError("lineage content digest was not computed from the exact stored value")
        # Memory writes consume the same durable operation budget as tool effects.
        self._consume_budget(context)
        # Metadata is committed first. A crash before value insertion leaves an
        # unreadable orphan, not an untracked value that can be released.
        stored = self.repository.add(node)
        self.repository.bind_authority(stored.node_id, context.authority_id)
        self._values.put_if_absent(
            stored.object_id, stored.version_id, value, stored.content_digest,
        )
        try:
            self.registry.assert_active(context.authority_id)
        except AuthorityRegistryError as exc:
            raise MemoryAccessDenied("memory write authority was revoked during persistence") from exc
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
            raise MemoryAccessDenied("cannot persist a derived memory with incomplete lineage")
        # Validate the exact value digest, current read authority, revocation,
        # tenant/purpose ancestry and application metadata policy for every input.
        # Persisted intermediates are required for multi-step transformations.
        input_accesses = []
        for item in inputs:
            input_accesses.extend(self.authorize_argument(
                item,
                purpose=purpose,
                capability_token=capability_token,
            ))
        parent_ids = tuple(sorted(set().union(*(item.lineage_refs for item in inputs))))
        label = Label.join(*(item.label for item in inputs))
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
            summary, *inputs, object_id=object_id, version_id=version_id,
            transformation="summarise", purpose=purpose, capability_token=capability_token,
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
            compacted_value, *inputs, object_id=object_id, version_id=version_id,
            transformation="compact", purpose=purpose, capability_token=capability_token,
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
            object_id, version_id, purpose=purpose,
            capability_token=capability_token,
        )
        self._consume_budget(context)
        stored = self._values.get(object_id, version_id)
        if stored is None:
            raise MemoryIntegrityError("lineage metadata exists but the memory value is missing")
        value, stored_digest = stored
        actual_digest = hashlib.sha256(canonical_value_bytes(value)).hexdigest()
        if (
            not hmac.compare_digest(actual_digest, node.content_digest)
            or not hmac.compare_digest(stored_digest, node.content_digest)
        ):
            self.repository.revoke_lineage(
                node.node_id, "memory content digest mismatch", revoked_at=int(self.clock()),
            )
            raise MemoryIntegrityError("memory bytes do not match their immutable lineage digest")
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
            ("connector_id", connector_id), ("source_class", source_class), ("tenant", tenant),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(name + " must be a non-empty string")
        if integrity not in {"trusted", "untrusted"}:
            raise ValueError("integrity must be trusted or untrusted")
        if isinstance(sensitivity, bool) or not isinstance(sensitivity, int) or not 0 <= sensitivity <= 3:
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


class HMACAgentMessageCodec:
    """Sign inter-agent message envelopes while preserving Arg labels and lineage."""

    def __init__(
        self,
        key: bytes,
        authority: HMACCapabilityAuthority,
        repository: SQLiteProvenanceRepository,
        *,
        memory: TrustedMemoryAdapter,
        clock=time.time,
    ) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("message HMAC key must contain at least 32 bytes")
        if (
            not isinstance(memory, TrustedMemoryAdapter)
            or memory.repository is not repository
            or memory.authority is not authority
        ):
            raise ValueError(
                "message codec, memory adapter and authority must share the same trusted state"
            )
        self._key = bytes(key)
        self.authority = authority
        self.registry = authority.registry
        self.repository = repository
        self.memory = memory
        self.clock = clock

    def _assert_payload_matches_lineage(
        self, value: Any, lineage_refs: Iterable[str],
    ) -> None:
        """Require the exact message value to match one immutable lineage node.

        A set of source references alone does not prove that a caller-supplied
        value was derived from those sources. Requiring one persisted leaf node
        binds the transmitted bytes to its content digest and parent DAG. Callers
        must persist transformed values through TrustedMemoryAdapter first.
        """
        refs = tuple(lineage_refs)
        if len(refs) != 1 or not isinstance(refs[0], str) or not refs[0]:
            raise MemoryAccessDenied(
                "inter-agent payload must reference one versioned value bound to its exact digest"
            )
        node = self.repository.get_node(refs[0])
        if node is None:
            raise MemoryAccessDenied("inter-agent payload references missing lineage")
        try:
            digest = hashlib.sha256(canonical_value_bytes(value)).hexdigest()
        except (TypeError, ValueError) as exc:
            raise MemoryAccessDenied(
                "inter-agent payload is not canonical JSON bound to its lineage"
            ) from exc
        if not hmac.compare_digest(digest, node.content_digest):
            raise MemoryAccessDenied(
                "inter-agent payload bytes do not match their immutable lineage digest"
            )

    def seal(
        self,
        payload: Arg,
        *,
        sender: str,
        recipient: str,
        capability_token: str,
    ) -> str:
        if not isinstance(payload, Arg) or not payload.lineage_refs or payload.lineage_incomplete:
            raise MemoryAccessDenied("inter-agent messages require complete explicit provenance")
        signed = self.authority.verify(capability_token)
        authority = signed.capability.authority_lineage
        if authority is None:
            raise MemoryAccessDenied("message sender capability has no authority lineage")
        authority_id = authority.authority_id
        if sender != authority.principal or not recipient:
            raise MemoryAccessDenied("message sender does not match authenticated authority")
        if payload.label.tenant_unknown or any(t != authority.tenant for t in payload.label.tenants):
            raise MemoryAccessDenied("message provenance crosses or obscures the sender tenant")
        if payload.label.sensitivity > 0 and not payload.label.tenants:
            raise MemoryAccessDenied("sensitive message has no tenant provenance")
        send_targets = dict(authority.grants).get("send_agent_message", ())
        if not any(grant_pattern_is_subset(recipient, pattern) for pattern in send_targets):
            raise MemoryAccessDenied("sender capability does not authorise this recipient")
        # A valid message-send grant does not imply a right to read the data.
        # Re-run the same current memory authority and application policy used
        # for ordinary reads before transferring the persisted value.
        self.memory.authorize_argument(
            payload,
            purpose=authority.purpose,
            capability_token=capability_token,
        )
        for node_id in payload.lineage_refs:
            node = self.repository.get_node(node_id)
            if node is None:
                raise MemoryAccessDenied("message references missing lineage")
            ancestry = self.repository.ancestors(node_id)
            if self.repository.revoked_nodes(item.node_id for item in ancestry):
                raise MemoryAccessDenied("message references revoked lineage")
            for item in ancestry:
                if item.purpose is not None and item.purpose != authority.purpose:
                    raise MemoryAccessDenied("message source purpose does not match sender authority")
                if item.label.tenant_unknown or any(
                    tenant != authority.tenant for tenant in item.label.tenants
                ):
                    raise MemoryAccessDenied("message source lineage crosses or obscures sender tenant")
                if item.label.integrity == "untrusted" and payload.label.integrity != "untrusted":
                    raise MemoryAccessDenied("message attempts to upgrade source integrity")
                if payload.label.sensitivity < item.label.sensitivity:
                    raise MemoryAccessDenied("message attempts to lower sensitivity")
                if not item.label.origins.issubset(payload.label.origins):
                    raise MemoryAccessDenied("message attempts to erase source origins")
                if not item.label.tenants.issubset(payload.label.tenants):
                    raise MemoryAccessDenied("message attempts to erase source tenant lineage")
                for bound_authority in self.repository.authority_ids_for_node(item.node_id):
                    self.registry.assert_active(bound_authority)
        try:
            self.registry.consume_effect(
                authority_id, max_calls=signed.capability.max_calls,
            )
            self.registry.assert_active(authority_id)
        except AuthorityRegistryError as exc:
            raise MemoryAccessDenied("message send budget exhausted or authority revoked") from exc
        label = {
            "integrity": payload.label.integrity,
            "sensitivity": payload.label.sensitivity,
            "tenants": sorted(payload.label.tenants),
            "tenant_unknown": payload.label.tenant_unknown,
            "origins": sorted(payload.label.origins),
        }
        body = {
            "version": 1,
            "message_id": secrets.token_urlsafe(18),
            "sender": sender,
            "recipient": recipient,
            "task_id": authority.task_id,
            "purpose": authority.purpose,
            "authority_id": authority_id,
            "issued_at": int(self.clock()),
            "value": payload.value,
            "label": label,
            "lineage_refs": sorted(payload.lineage_refs),
        }
        encoded = canonical_value_bytes(body)
        signature = hmac.new(self._key, encoded, hashlib.sha256).digest()
        return _b64encode(encoded) + "." + _b64encode(signature)

    def open(self, token: str, *, recipient_token: str) -> Arg:
        try:
            recipient_capability = self.authority.verify(recipient_token).capability
            recipient_record = recipient_capability.authority_lineage
            recipient = recipient_capability.principal
            if recipient_record is None:
                raise ValueError("recipient capability has no authority lineage")
            if not isinstance(token, str) or len(token) > 1_000_000:
                raise ValueError("invalid message size")
            body_part, signature_part = token.split(".")
            encoded = _b64decode(body_part)
            supplied = _b64decode(signature_part)
            expected = hmac.new(self._key, encoded, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, supplied):
                raise ValueError("message signature mismatch")
            body = json.loads(encoded)
            if not isinstance(body, dict) or body.get("version") != 1:
                raise ValueError("unsupported message envelope")
            message_id = body.get("message_id")
            if not isinstance(message_id, str) or not message_id or len(message_id) > 256:
                raise ValueError("message identifier is missing or exceeds the supported length")
            if body.get("recipient") != recipient:
                raise ValueError("message recipient mismatch")
            # The envelope MAC and recipient capability have both been verified.
            # Short-circuit a sequential replay using the composite receipt index
            # before sender-authority lookup and provenance-DAG traversal. This
            # check is not the concurrency boundary: consume_message() below still
            # performs the unique receipt insert and quota charge atomically.
            if self.registry.has_message_receipt(
                recipient_record.principal,
                recipient_record.tenant,
                recipient_record.task_id,
                message_id,
            ):
                # Preserve the explicit denial reason; the outer parser-error
                # handler intentionally normalizes malformed-envelope failures.
                raise MemoryAccessDenied("inter-agent message replay was rejected")
            if int(body.get("issued_at", -1)) > int(self.clock()) + 30:
                raise ValueError("message issuance time is invalid")
            authority_id = body.get("authority_id")
            authority = self.registry.assert_active(str(authority_id))
            if (
                body.get("sender") != authority.principal
                or body.get("task_id") != authority.task_id
                or body.get("purpose") != authority.purpose
                or recipient_record.tenant != authority.tenant
                or recipient_record.task_id != authority.task_id
                or recipient_record.purpose != authority.purpose
            ):
                raise ValueError("message sender, recipient or task authority mismatch")
            send_targets = dict(authority.grants).get("send_agent_message", ())
            if not any(
                grant_pattern_is_subset(recipient, pattern)
                for pattern in send_targets
            ):
                raise ValueError("sender capability does not authorise this recipient")
            receive_targets = dict(recipient_record.grants).get("receive_agent_message", ())
            if not any(
                grant_pattern_is_subset(authority.principal, pattern)
                for pattern in receive_targets
            ):
                raise ValueError("recipient capability does not authorise this sender")
            label_data = body.get("label")
            refs = body.get("lineage_refs")
            if (
                not isinstance(label_data, dict)
                or not isinstance(refs, list)
                or not refs
                or any(not isinstance(ref, str) or not ref for ref in refs)
            ):
                raise ValueError("message provenance is missing")
            self._assert_payload_matches_lineage(body["value"], refs)
            label = Label(
                integrity=label_data["integrity"],
                sensitivity=label_data["sensitivity"],
                tenant=None,
                tenants=frozenset(label_data["tenants"]),
                tenant_unknown=label_data["tenant_unknown"],
                origins=frozenset(label_data["origins"]),
            )
            if label.tenant_unknown or any(t != authority.tenant for t in label.tenants):
                raise ValueError("message provenance crosses or obscures the recipient authority tenant")
            if label.sensitivity > 0 and not label.tenants:
                raise ValueError("sensitive message has no tenant provenance")
            received = Arg(body["value"], label, frozenset(refs), False)
            for node_id in refs:
                node = self.repository.get_node(node_id)
                if node is None:
                    raise ValueError("message lineage is missing")
                ancestry = self.repository.ancestors(node_id)
                if self.repository.revoked_nodes(item.node_id for item in ancestry):
                    raise ValueError("message lineage is revoked")
                for item in ancestry:
                    if item.purpose is not None and item.purpose != authority.purpose:
                        raise ValueError("message lineage purpose mismatch")
                    if item.label.tenant_unknown or any(
                        tenant != authority.tenant for tenant in item.label.tenants
                    ):
                        raise ValueError("message source lineage tenant mismatch")
                    for bound_authority in self.repository.authority_ids_for_node(item.node_id):
                        self.registry.assert_active(bound_authority)
                    if item.label.integrity == "untrusted" and label.integrity != "untrusted":
                        raise ValueError("message integrity exceeds its source lineage")
                    if (
                        label.sensitivity < item.label.sensitivity
                        or not item.label.origins.issubset(label.origins)
                        or not item.label.tenants.issubset(label.tenants)
                    ):
                        raise ValueError("message label is less restrictive than source lineage")
            try:
                # Consume the replay receipt before charging a memory read. A
                # duplicate delivery must not drain the recipient's memory-read
                # budget on every rejected replay attempt.
                self.registry.consume_message(
                    recipient_capability.cap_id,
                    message_id,
                    max_calls=recipient_capability.max_calls,
                )
            except AuthorityRegistryError as exc:
                raise MemoryAccessDenied(
                    "message replay, receive budget exhaustion or revoked authority was rejected"
                ) from exc
            # A valid receipt does not confer memory access. The recipient must
            # independently pass current mem_read scope and application policy.
            self.memory.authorize_argument(
                received,
                purpose=recipient_record.purpose,
                capability_token=recipient_token,
            )
            return received
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, AuthorityRegistryError) as exc:
            raise MemoryAccessDenied("inter-agent message authentication or provenance validation failed") from exc


class PACAAgentRuntime:
    """Small reference orchestrator joining signed authority, monitor and message/memory APIs.

    This wrapper covers calls made through its methods only. Direct tool clients,
    framework callbacks, subprocesses and remote resource servers must be integrated
    separately; a final local registry check cannot make a remote effect atomic with
    revocation.
    """

    def __init__(
        self,
        authority: HMACCapabilityAuthority,
        memory: TrustedMemoryAdapter,
        monitor: Any,
        messages: HMACAgentMessageCodec,
    ) -> None:
        if (
            memory.authority is not authority
            or messages.authority is not authority
            or messages.memory is not memory
        ):
            raise ValueError(
                "runtime, memory and message adapters must share the same trusted issuer and memory store"
            )
        # C13 is the single-use effect-token binding. It may be disabled in
        # isolated benchmark ablations, but never in a runtime that can invoke
        # consequential executors.
        if "C13" in getattr(monitor, "disable", ()):
            raise ValueError("PACAAgentRuntime requires C13 effect-token verification")
        self.authority = authority
        self.memory = memory
        self.monitor = monitor
        self.messages = messages

    @staticmethod
    def _assert_tool_binding(capability: Any, request: Request) -> None:
        if request.action in {"mem_read", "mem_write", "delegate"}:
            return
        tool = request.tool
        if not isinstance(tool, Tool):
            raise MemoryAccessDenied("protected agent effect requires an explicit typed tool manifest")
        pinned = capability.tool_pins.get(tool.name)
        if pinned is None or not hmac.compare_digest(pinned, tool.hash):
            raise MemoryAccessDenied("tool manifest is not pinned by the authenticated capability")

    def delegate(
        self,
        parent_token: str,
        *,
        principal: str,
        grants: Mapping[str, Iterable[str]],
        expires_at: int,
        role: str = "assistant",
        max_calls: int = 40,
        max_fanout: int = 5,
        max_task_calls: Optional[int] = None,
    ):
        return self.authority.issue(
            parent_token=parent_token,
            principal=principal,
            grants=grants,
            expires_at=expires_at,
            role=role,
            max_calls=max_calls,
            max_fanout=max_fanout,
            max_task_calls=max_task_calls,
        )

    def send_message(
        self, payload: Arg, *, sender: str, recipient: str, capability_token: str,
    ) -> str:
        return self.messages.seal(
            payload, sender=sender, recipient=recipient,
            capability_token=capability_token,
        )

    def receive_message(self, token: str, *, recipient_token: str) -> Arg:
        return self.messages.open(token, recipient_token=recipient_token)

    def revoke_authority(self, authority_id: str, reason: str) -> Tuple[str, ...]:
        return self.authority.registry.revoke(authority_id, reason)

    def revoke_information(self, node_id: str, reason: str) -> None:
        self.memory.repository.revoke_lineage(node_id, reason, revoked_at=int(self.memory.clock()))


    def _prepare_effect(
        self,
        capability_token: str,
        request: Request,
    ) -> Tuple[Any, Request, str, Tuple[_AuthorizedMemoryReference, ...]]:
        """Authenticate and snapshot an effect before authorizing any consequence."""
        if not isinstance(request, Request):
            raise MemoryAccessDenied("effect request must be a typed PACA Request")
        signed = self.authority.verify(capability_token)
        issued = signed.capability

        try:
            original_digest = request.digest
            snapshot = copy.deepcopy(request)
            snapshot_digest = snapshot.digest
        except Exception as exc:
            raise MemoryAccessDenied("effect request could not be safely snapshotted") from exc
        if snapshot_digest != original_digest:
            raise MemoryAccessDenied("effect request changed while being snapshotted")

        supplied = snapshot.cap
        try:
            supplied.validate_authority_lineage()
        except Exception as exc:
            raise MemoryAccessDenied("request capability lineage is invalid") from exc
        if (
            supplied.cap_id != issued.cap_id
            or supplied.authority_lineage != issued.authority_lineage
            or supplied.principal != issued.principal
            or supplied.tenant != issued.tenant
            or supplied.task_id != issued.task_id
            or supplied.grants != issued.grants
            or supplied.expires != issued.expires
            or supplied.parent != issued.parent
            or supplied.role != issued.role
            or supplied.max_calls != issued.max_calls
            or supplied.max_fanout != issued.max_fanout
            or supplied.tool_pins != issued.tool_pins
        ):
            raise MemoryAccessDenied("request capability does not match the authenticated token")
        self._assert_tool_binding(issued, snapshot)
        self.authority.registry.assert_active(issued.cap_id)

        authority_record = issued.authority_lineage
        if authority_record is None:
            raise MemoryAccessDenied("effect capability has no immutable authority lineage")
        purpose = authority_record.purpose
        accesses = []
        for argument in snapshot.args.values():
            accesses.extend(self.memory.authorize_argument(
                argument,
                purpose=purpose,
                capability_token=capability_token,
            ))

        if snapshot.resource_lineage_refs:
            if snapshot.resource is None:
                raise MemoryAccessDenied(
                    "resource lineage references require an explicit resource label"
                )
            for node_id in sorted(snapshot.resource_lineage_refs):
                accesses.append(self.memory.authorize_reference(
                    node_id,
                    label=snapshot.resource,
                    purpose=purpose,
                    capability_token=capability_token,
                ))

        if snapshot.digest != original_digest:
            raise MemoryAccessDenied("effect request changed during provenance authorization")
        return issued, snapshot, original_digest, tuple(accesses)

    def _authorize_effect(
        self,
        capability_token: str,
        request: Request,
    ) -> Tuple[Optional[Decision], Optional[Request], Optional[Any], Tuple[_AuthorizedMemoryReference, ...]]:
        """Run policy and consume a single-use decision for a frozen request snapshot."""
        if "C13" in getattr(self.monitor, "disable", ()):
            raise MemoryAccessDenied(
                "PACAAgentRuntime requires C13 effect-token verification"
            )
        issued, snapshot, request_digest, accesses = self._prepare_effect(
            capability_token, request,
        )
        decision = self.monitor.decide(snapshot)
        if decision.verdict != "allow":
            return decision, None, issued, accesses
        if decision.digest != request_digest or snapshot.digest != request_digest:
            raise MemoryAccessDenied("monitor decision is not bound to the unchanged effect request")
        if not self.monitor.verify(snapshot, decision):
            return Decision("deny", digest=request_digest), None, issued, accesses

        self.authority.registry.consume_effect(
            issued.cap_id, max_calls=issued.max_calls,
        )
        self.authority.registry.assert_active(issued.cap_id)
        authority_record = issued.authority_lineage
        if authority_record is None:
            raise MemoryAccessDenied("effect capability lost its authority lineage")
        if snapshot.digest != request_digest or decision.digest != request_digest:
            raise MemoryAccessDenied("effect request changed before executor entry")
        return decision, snapshot, issued, accesses

    def _revalidate_effect_snapshot(
        self,
        capability_token: str,
        decision: Decision,
        snapshot: Request,
        issued: Any,
        accesses: Tuple[_AuthorizedMemoryReference, ...],
    ) -> None:
        """Check active authority, dynamic lineage policy and request immutability."""
        self.authority.registry.assert_active(issued.cap_id)
        authority_record = issued.authority_lineage
        if authority_record is None:
            raise MemoryAccessDenied("effect capability lost its authority lineage")
        self.memory.revalidate_authorized_references(
            accesses,
            capability_token=capability_token,
            purpose=authority_record.purpose,
        )
        if snapshot.digest != decision.digest:
            raise MemoryAccessDenied("effect request changed before executor entry")

    async def aexecute_effect(
        self,
        capability_token: str,
        request: Request,
        executor: Callable[[Request], Any],
    ) -> Tuple[Decision, Optional[Any]]:
        """Async effect path with provenance, authority and revocation rechecks."""
        decision, snapshot, issued, accesses = self._authorize_effect(
            capability_token, request,
        )
        if decision is None or issued is None:
            return Decision("deny"), None
        if decision.verdict != "allow":
            return decision, None
        if snapshot is None:
            return Decision("deny", digest=decision.digest), None

        self._revalidate_effect_snapshot(
            capability_token, decision, snapshot, issued, accesses,
        )
        result = executor(snapshot)
        if inspect.isawaitable(result):
            # Only a newly-created native coroutine has a guaranteed lazy body.
            # An asyncio.Task/Future or arbitrary Awaitable may already be running
            # before this runtime can revalidate its authority and source policy.
            if (
                not inspect.iscoroutine(result)
                or inspect.getcoroutinestate(result) != inspect.CORO_CREATED
            ):
                cancel = getattr(result, "cancel", None)
                if callable(cancel):
                    cancel()
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise MemoryAccessDenied(
                    "async executor must return an unstarted native coroutine, not a Task/Future or started awaitable"
                )
            # The coroutine body does not run until awaited. Revalidate again
            # after constructing it and immediately before entering that body.
            try:
                self._revalidate_effect_snapshot(
                    capability_token, decision, snapshot, issued, accesses,
                )
            except Exception:
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise
            result = await result

        # Do not return nested deferred or lazy values to a caller that could
        # execute them after PACA's authorization boundary has ended.
        if inspect.isawaitable(result):
            cancel = getattr(result, "cancel", None)
            if callable(cancel):
                cancel()
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise MemoryAccessDenied(
                "async executor returned a nested deferred result outside PACA authorization"
            )
        if inspect.isgenerator(result):
            result.close()
            raise MemoryAccessDenied(
                "async executor returned a lazy generator outside PACA authorization"
            )
        if inspect.isasyncgen(result):
            await result.aclose()
            raise MemoryAccessDenied(
                "async executor returned a lazy async generator outside PACA authorization"
            )
        return decision, result

    def execute_effect(
        self,
        capability_token: str,
        request: Request,
        executor: Callable[[Request], Any],
    ) -> Tuple[Decision, Optional[Any]]:
        """Check signed authority and exact request provenance immediately before effect."""
        decision, snapshot, issued, accesses = self._authorize_effect(
            capability_token, request,
        )
        if decision is None or issued is None:
            return Decision("deny"), None
        if decision.verdict != "allow":
            return decision, None
        if snapshot is None:
            return Decision("deny", digest=decision.digest), None
        self._revalidate_effect_snapshot(
            capability_token, decision, snapshot, issued, accesses,
        )
        result = executor(snapshot)
        if inspect.isawaitable(result):
            # The synchronous entry point cannot perform the post-construction
            # async authority check. Reject and cancel anything awaitable rather
            # than returning a Task/Future that may already be executing.
            cancel = getattr(result, "cancel", None)
            if callable(cancel):
                cancel()
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise MemoryAccessDenied(
                "synchronous effect executor must not return an awaitable; "
                "use the async runtime with an unstarted native coroutine"
            )
        if inspect.isgenerator(result):
            result.close()
            raise MemoryAccessDenied(
                "synchronous effect executor must not return a lazy generator"
            )
        if inspect.isasyncgen(result):
            raise MemoryAccessDenied(
                "synchronous effect executor must not return a lazy async generator"
            )
        return decision, result


__all__ = [
    "HMACAgentMessageCodec",
    "MemoryAccessDenied",
    "MemoryAccessContext",
    "MemoryIntegrityError",
    "PACAAgentRuntime",
    "SQLiteMemoryValueStore",
    "TrustedConnectorAdapter",
    "TrustedMemoryAdapter",
    "canonical_value_bytes",
]
