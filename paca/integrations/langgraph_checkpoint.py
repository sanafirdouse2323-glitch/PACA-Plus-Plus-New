"""PACA mediation for the official LangGraph PostgreSQL checkpointer.

This adapter covers the BaseCheckpointSaver checkpoint and pending-write methods.
It records immutable PACA provenance/value evidence before persisting to PostgreSQL,
and validates that evidence before returning PostgreSQL state to the graph runtime.

Install the langgraph-postgres extra. The raw PostgresSaver, its connection and
database credentials must remain inside a trusted process. Python wrappers are not
a sandbox: direct access to the raw saver or SQL connection bypasses this adapter.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any, Callable, Optional, Tuple

try:
    from langgraph.checkpoint.base import (
        BaseCheckpointSaver,
        CheckpointTuple,
        get_serializable_checkpoint_metadata,
    )
    from langgraph.checkpoint.postgres import PostgresSaver
except ImportError as exc:  # pragma: no cover - optional dependency
    raise ImportError(
        "PostgreSQL checkpoint integration requires "
        "paca-plus-plus[langgraph-postgres]"
    ) from exc

from ..durable import SQLiteProvenanceRepository
from ..memory import MemoryAccessDenied, MemoryIntegrityError, TrustedMemoryAdapter
from ..provenance import Arg


def _digest(*parts: str) -> str:
    payload = "\0".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _provider_thread_id(tenant: str, thread_id: str) -> str:
    """Namespace provider thread IDs by authenticated tenant identity."""
    return "paca-" + _digest(tenant, thread_id)


def _checkpoint_object_id(tenant: str, thread_id: str, checkpoint_ns: str) -> str:
    return (
        "mem/checkpoints/" + _digest(tenant) + "/"
        + _digest(thread_id) + "/" + _digest(checkpoint_ns)
    )


def _thread_prefix(tenant: str, thread_id: str) -> str:
    return "mem/checkpoints/" + _digest(tenant) + "/" + _digest(thread_id) + "/"


def _writes_prefix(
    tenant: str, thread_id: str, checkpoint_ns: str, checkpoint_id: str,
) -> str:
    return (
        "mem/checkpoint-writes/" + _digest(tenant) + "/"
        + _digest(thread_id) + "/" + _digest(checkpoint_ns) + "/"
        + _digest(checkpoint_id) + "/"
    )


def _write_object_id(
    tenant: str,
    thread_id: str,
    checkpoint_ns: str,
    checkpoint_id: str,
    task_id: str,
    task_path: str,
) -> str:
    return _writes_prefix(
        tenant, thread_id, checkpoint_ns, checkpoint_id,
    ) + _digest(task_id, task_path)


class PACAProvenancePostgresSaver(BaseCheckpointSaver):
    """PACA-gated wrapper for LangGraph's PostgresSaver.

    The provenance callback must return every trusted data dependency of a
    checkpoint. The pending-writes callback must return every trusted dependency
    of each task-write batch. The previous checkpoint is added automatically.
    The application is responsible for supplying trusted, complete callbacks.
    """

    def __init__(
        self,
        delegate: PostgresSaver,
        memory: TrustedMemoryAdapter,
        *,
        capability_token_provider: Callable[[], str],
        provenance_provider: Callable[
            [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]], Iterable[Arg]
        ],
        writes_provenance_provider: Callable[
            [Mapping[str, Any], Sequence[Tuple[str, Any]], str, str], Iterable[Arg]
        ],
        purpose: str,
    ) -> None:
        if not isinstance(delegate, PostgresSaver):
            raise TypeError("delegate must be an official LangGraph PostgresSaver")
        if not callable(capability_token_provider):
            raise TypeError("capability_token_provider must be callable")
        if not callable(provenance_provider) or not callable(writes_provenance_provider):
            raise TypeError("checkpoint and pending-write provenance providers are required")
        if not isinstance(purpose, str) or not purpose:
            raise ValueError("purpose must be a non-empty string")
        super().__init__(serde=delegate.serde)
        self.__delegate = delegate
        self.memory = memory
        self.repository: SQLiteProvenanceRepository = memory.repository
        self._token_provider = capability_token_provider
        self._provenance_provider = provenance_provider
        self._writes_provenance_provider = writes_provenance_provider
        self.purpose = purpose

    def setup(self) -> None:
        """Run the official PostgreSQL checkpointer migrations."""
        self.__delegate.setup()

    def _normalized_config(
        self, config: Optional[Mapping[str, Any]], *, action: str,
    ) -> Tuple[str, str, str, str, str, dict[str, Any]]:
        if not isinstance(config, Mapping):
            raise MemoryAccessDenied("checkpoint access requires an explicit thread scope")
        configurable = config.get("configurable")
        if not isinstance(configurable, Mapping):
            raise MemoryAccessDenied("checkpoint config has no configurable scope")
        thread_id = configurable.get("thread_id")
        checkpoint_ns = configurable.get("checkpoint_ns", "")
        if (
            not isinstance(thread_id, str) or not thread_id
            or not isinstance(checkpoint_ns, str)
        ):
            raise MemoryAccessDenied("checkpoint thread or namespace identity is invalid")
        token = self._token_provider()
        try:
            signed = self.memory.authority.verify(token)
            authority = signed.capability.authority_lineage
            if authority is None:
                raise MemoryAccessDenied("checkpoint capability has no authority lineage")
            tenant = authority.tenant
        except MemoryAccessDenied:
            raise
        except Exception as exc:
            raise MemoryAccessDenied("checkpoint capability authentication failed") from exc

        object_id = _checkpoint_object_id(tenant, thread_id, checkpoint_ns)
        self.memory._verified_context(token, action, object_id, self.purpose)

        provider_config = dict(config)
        provider_configurable = dict(configurable)
        provider_configurable["thread_id"] = _provider_thread_id(tenant, thread_id)
        provider_configurable["checkpoint_ns"] = checkpoint_ns
        provider_config["configurable"] = provider_configurable
        return token, tenant, thread_id, checkpoint_ns, object_id, provider_config

    def _typed_payload(self, value: Any) -> dict[str, str]:
        kind, payload = self.serde.dumps_typed(value)
        return {
            "serializer": str(kind),
            "payload_b64": base64.b64encode(payload).decode("ascii"),
        }

    def _decode_payload(self, envelope: Mapping[str, str]) -> Any:
        try:
            raw = base64.b64decode(envelope["payload_b64"], validate=True)
            return self.serde.loads_typed((envelope["serializer"], raw))
        except Exception as exc:
            raise MemoryIntegrityError("checkpoint evidence payload is malformed") from exc

    def _node_arg(self, node: Any, capability_token: str) -> Arg:
        """Return the actual stored checkpoint evidence, not a placeholder value.

        Lineage references alone do not bind a supplied Arg's bytes. Parent
        checkpoint dependencies must therefore be obtained through the active
        PACA memory-read path so their value digest and source policy are checked.
        """
        return self.memory.read(
            node.object_id,
            node.version_id,
            purpose=self.purpose,
            capability_token=capability_token,
        )

    def _checkpoint_node(self, object_id: str, checkpoint_id: Optional[str]) -> Any:
        if checkpoint_id:
            return self.repository.get_version(object_id, checkpoint_id)
        return self.repository.latest_node(object_id)

    @staticmethod
    def _provider_configurable(
        config: Any,
        *,
        expected_thread_id: str,
        expected_namespace: str,
        expected_checkpoint_id: Optional[str] = None,
    ) -> Mapping[str, Any]:
        if not isinstance(config, Mapping):
            raise MemoryIntegrityError("PostgreSQL returned a checkpoint config with an invalid shape")
        configurable = config.get("configurable")
        if not isinstance(configurable, Mapping):
            raise MemoryIntegrityError("PostgreSQL returned a checkpoint config without configurable identity")
        if (
            configurable.get("thread_id") != expected_thread_id
            or configurable.get("checkpoint_ns", "") != expected_namespace
        ):
            raise MemoryIntegrityError("PostgreSQL checkpoint config escaped its authenticated thread namespace")
        if expected_checkpoint_id is not None and (
            configurable.get("checkpoint_id") != expected_checkpoint_id
        ):
            raise MemoryIntegrityError("PostgreSQL checkpoint ID differs from authorized PACA evidence")
        checkpoint_id = configurable.get("checkpoint_id")
        if checkpoint_id is not None and (
            not isinstance(checkpoint_id, str) or not checkpoint_id
        ):
            raise MemoryIntegrityError("PostgreSQL returned an invalid checkpoint identifier")
        return configurable

    def _assert_provider_tuple(
        self,
        result: CheckpointTuple,
        *,
        tenant: str,
        thread_id: str,
        namespace: str,
        node: Any,
    ) -> None:
        provider_thread_id = _provider_thread_id(tenant, thread_id)
        self._provider_configurable(
            result.config,
            expected_thread_id=provider_thread_id,
            expected_namespace=namespace,
            expected_checkpoint_id=node.version_id,
        )
        expected_parent_ids = {
            parent.version_id
            for parent_id in node.parent_ids
            if (parent := self.repository.get_node(parent_id)) is not None
            and parent.object_id == node.object_id
        }
        if result.parent_config is None:
            if expected_parent_ids:
                raise MemoryIntegrityError(
                    "PostgreSQL omitted the parent checkpoint recorded in PACA lineage"
                )
            return
        parent_configurable = self._provider_configurable(
            result.parent_config,
            expected_thread_id=provider_thread_id,
            expected_namespace=namespace,
        )
        parent_id = parent_configurable.get("checkpoint_id")
        if not isinstance(parent_id, str) or parent_id not in expected_parent_ids:
            raise MemoryIntegrityError(
                "PostgreSQL parent checkpoint does not match the immutable PACA parent lineage"
            )

    def _translate_config(self, config: Mapping[str, Any], original_thread_id: str) -> dict[str, Any]:
        value = dict(config)
        configurable = dict(value.get("configurable", {}))
        configurable["thread_id"] = original_thread_id
        value["configurable"] = configurable
        return value

    def _translate_tuple(self, result: CheckpointTuple, original_thread_id: str) -> CheckpointTuple:
        config = self._translate_config(result.config, original_thread_id)
        parent = (
            self._translate_config(result.parent_config, original_thread_id)
            if result.parent_config is not None else None
        )
        return result._replace(config=config, parent_config=parent)

    def put(
        self,
        config: Mapping[str, Any],
        checkpoint: Mapping[str, Any],
        metadata: Mapping[str, Any],
        new_versions: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        token, tenant, thread_id, namespace, object_id, provider_config = self._normalized_config(
            config, action="mem_write",
        )
        checkpoint_id = checkpoint.get("id")
        if not isinstance(checkpoint_id, str) or not checkpoint_id:
            raise MemoryAccessDenied("checkpoint has no immutable checkpoint id")

        dependencies = tuple(self._provenance_provider(config, checkpoint, metadata))
        parent_id = config.get("configurable", {}).get("checkpoint_id")
        if parent_id is not None and (
            not isinstance(parent_id, str) or not parent_id
        ):
            raise MemoryAccessDenied("parent checkpoint identifier is invalid")
        if parent_id:
            parent = self.repository.get_version(object_id, parent_id)
            if parent is None:
                raise MemoryAccessDenied("parent checkpoint is missing from PACA provenance")
            dependencies += (self._node_arg(parent, token),)
        if not dependencies or any(
            not isinstance(item, Arg) or not item.lineage_refs or item.lineage_incomplete
            for item in dependencies
        ):
            raise MemoryAccessDenied("checkpoint write requires complete trusted provenance")

        persisted_metadata = get_serializable_checkpoint_metadata(provider_config, metadata)
        # Store only the checkpoint saver serializer envelope in the JSON value
        # store. Checkpoint channel values may include MessagePack/JsonPlus objects
        # that are not JSON serialisable on their own.
        evidence = self._typed_payload({
            "checkpoint": dict(checkpoint),
            "metadata": persisted_metadata,
        })
        self.memory.write_derived(
            evidence,
            *dependencies,
            object_id=object_id,
            version_id=checkpoint_id,
            transformation="langgraph_postgres_checkpoint",
            purpose=self.purpose,
            capability_token=token,
        )
        # The provider write is deliberately after evidence persistence. If it
        # fails, the PACA record is an orphan and reads fail closed.
        provider_config["configurable"]["checkpoint_ns"] = namespace
        saved = self.__delegate.put(provider_config, checkpoint, metadata, new_versions)
        self._provider_configurable(
            saved,
            expected_thread_id=provider_config["configurable"]["thread_id"],
            expected_namespace=namespace,
            expected_checkpoint_id=checkpoint_id,
        )
        self.memory._verified_context(
            token, "mem_write", object_id, self.purpose,
        )
        signed_after_write = self.memory.authority.verify(token)
        self.memory.registry.assert_active(signed_after_write.capability.cap_id)
        self.memory.revalidate_read_access(
            object_id,
            checkpoint_id,
            purpose=self.purpose,
            capability_token=token,
        )
        for dependency in dependencies:
            for node_id in dependency.lineage_refs:
                source_node = self.repository.get_node(node_id)
                if source_node is None:
                    raise MemoryAccessDenied("checkpoint source lineage disappeared after provider persistence")
                self.memory.revalidate_read_access(
                    source_node.object_id,
                    source_node.version_id,
                    purpose=self.purpose,
                    capability_token=token,
                )
        return self._translate_config(saved, thread_id)

    def _checkpoint_for_write(
        self, token: str, object_id: str, checkpoint_id: str,
    ) -> Any:
        node = self.repository.get_version(object_id, checkpoint_id)
        if node is None:
            raise MemoryAccessDenied("pending writes refer to an unknown checkpoint")
        if self.repository.is_revoked(node.node_id):
            raise MemoryAccessDenied("pending writes refer to a revoked checkpoint")
        try:
            ancestry = self.repository.ancestors(node.node_id)
            if self.repository.revoked_nodes(item.node_id for item in ancestry):
                raise MemoryAccessDenied("checkpoint ancestry is revoked")
            for ancestor in ancestry:
                if ancestor.purpose is not None and ancestor.purpose != self.purpose:
                    raise MemoryAccessDenied("checkpoint ancestry has a different purpose")
                for authority_id in self.repository.authority_ids_for_node(ancestor.node_id):
                    self.memory.registry.assert_active(authority_id)
            self.memory.registry.assert_active(
                self.memory.authority.verify(token).capability.authority_lineage.authority_id
            )
        except MemoryAccessDenied:
            raise
        except Exception as exc:
            raise MemoryAccessDenied("checkpoint authority or lineage is no longer active") from exc
        return node

    def _pending_write_payload(
        self, task_id: str, task_path: str, writes: Sequence[Tuple[str, Any]],
    ) -> dict[str, Any]:
        return {
            "task_id": task_id,
            "task_path": task_path,
            "writes": tuple((channel, value) for channel, value in writes),
        }

    def _pending_write_args(
        self, pending: Iterable[Any],
    ) -> list[Tuple[str, str, Any]]:
        output = []
        for item in pending or ():
            if not isinstance(item, (tuple, list)) or len(item) != 3:
                raise MemoryIntegrityError("PostgreSQL returned an unsupported pending-write tuple")
            task_id, channel, value = item
            if (
                not isinstance(task_id, str) or not task_id
                or not isinstance(channel, str) or not channel
            ):
                raise MemoryIntegrityError("PostgreSQL returned an invalid pending-write identity")
            output.append((task_id, channel, value))
        return output

    def _expected_pending_writes(
        self,
        token: str,
        tenant: str,
        thread_id: str,
        namespace: str,
        checkpoint_id: str,
    ) -> list[Tuple[str, str, Any]]:
        prefix = _writes_prefix(tenant, thread_id, namespace, checkpoint_id)
        nodes = self.repository.list_nodes(object_id_prefix=prefix)
        records: dict[str, Tuple[str, list[Tuple[str, Any]]]] = {}
        seen_tasks: set[Tuple[str, str]] = set()
        for node in nodes:
            envelope = self.memory.read(
                node.object_id,
                node.version_id,
                purpose=self.purpose,
                capability_token=token,
            ).value
            if not isinstance(envelope, Mapping):
                raise MemoryIntegrityError("pending-write provenance envelope is not a mapping")
            value = self._decode_payload(envelope)
            if not isinstance(value, Mapping):
                raise MemoryIntegrityError("pending-write provenance record is not a mapping")
            task_id = value.get("task_id")
            task_path = value.get("task_path")
            writes = value.get("writes")
            if (
                not isinstance(task_id, str) or not task_id
                or not isinstance(task_path, str)
                or not isinstance(writes, (tuple, list))
            ):
                raise MemoryIntegrityError("pending-write provenance record has invalid fields")
            identity = (task_id, task_path)
            if identity in seen_tasks:
                raise MemoryIntegrityError("duplicate pending-write provenance identity")
            seen_tasks.add(identity)
            if any(
                previous_task == task_id and previous_path != task_path
                for previous_task, previous_path in seen_tasks
            ):
                raise MemoryIntegrityError(
                    "provider pending-write return type cannot disambiguate one task ID across paths"
                )
            normalized_writes: list[Tuple[str, Any]] = []
            for write in writes:
                if (
                    not isinstance(write, (tuple, list)) or len(write) != 2
                    or not isinstance(write[0], str) or not write[0]
                ):
                    raise MemoryIntegrityError("pending-write provenance contains an invalid channel")
                normalized_writes.append((write[0], write[1]))
            records[task_id] = (task_path, normalized_writes)
        # The PostgreSQL saver exposes pending writes as (task_id, channel, value)
        # tuples without task_path. Sort task IDs, retaining channel order within
        # each task, to produce a stable contract-comparable sequence.
        ordered = sorted(records.items(), key=lambda item: (item[1][0], item[0]))
        return [
            (task_id, channel, value)
            for task_id, (_task_path, writes) in ordered
            for channel, value in writes
        ]

    def _assert_pending_writes_match(
        self,
        token: str,
        tenant: str,
        thread_id: str,
        namespace: str,
        checkpoint_id: str,
        provider_pending: Iterable[Any],
    ) -> None:
        expected = self._expected_pending_writes(
            token, tenant, thread_id, namespace, checkpoint_id,
        )
        actual = self._pending_write_args(provider_pending)
        if self._typed_payload(expected) != self._typed_payload(actual):
            raise MemoryIntegrityError(
                "PostgreSQL pending writes differ from authorized PACA evidence"
            )

    def put_writes(
        self,
        config: Mapping[str, Any],
        writes: Sequence[Tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        token, tenant, thread_id, namespace, object_id, provider_config = self._normalized_config(
            config, action="mem_write",
        )
        checkpoint_id = config.get("configurable", {}).get("checkpoint_id")
        if not isinstance(checkpoint_id, str) or not checkpoint_id:
            raise MemoryAccessDenied("pending writes require an explicit checkpoint id")
        checkpoint_node = self._checkpoint_for_write(token, object_id, checkpoint_id)
        if not isinstance(task_id, str) or not task_id or not isinstance(task_path, str):
            raise MemoryAccessDenied("pending-write task identity is invalid")
        clean_writes = tuple((channel, value) for channel, value in writes)
        if not clean_writes or any(
            not isinstance(channel, str) or not channel for channel, _ in clean_writes
        ):
            raise MemoryAccessDenied("pending-write batch must contain valid channels")
        write_object = _write_object_id(
            tenant, thread_id, namespace, checkpoint_id, task_id, task_path,
        )
        # Read through the full PACA boundary before using provider state.
        current = self.get_tuple(config)
        if current is None:
            raise MemoryAccessDenied("provider checkpoint is absent while writing pending state")

        existing = self.repository.latest_node(write_object)
        if existing is not None:
            existing_record = self.memory.read(
                write_object, existing.version_id, purpose=self.purpose,
                capability_token=token,
            ).value
            expected_record = self._typed_payload(
                self._pending_write_payload(task_id, task_path, clean_writes)
            )
            if existing_record != expected_record:
                raise MemoryAccessDenied("pending-write task identity is immutable within a checkpoint")
            actual_for_task = [
                item for item in self._pending_write_args(current.pending_writes)
                if item[0] == task_id
            ]
            expected_for_task = [(task_id, channel, value) for channel, value in clean_writes]
            if self._typed_payload(actual_for_task) == self._typed_payload(expected_for_task):
                return
            if actual_for_task:
                raise MemoryIntegrityError("provider has conflicting pending writes for an existing task")
            # Evidence may have committed before a provider failure. A retry can
            # safely complete the missing provider write.
            self.__delegate.put_writes(provider_config, clean_writes, task_id, task_path)
        else:
            if any(item[0] == task_id for item in self._pending_write_args(current.pending_writes)):
                raise MemoryIntegrityError("provider contains pending writes with no PACA evidence")
            dependencies = (self._node_arg(checkpoint_node, token),) + tuple(
                self._writes_provenance_provider(config, clean_writes, task_id, task_path)
            )
            if any(
                not isinstance(item, Arg) or not item.lineage_refs or item.lineage_incomplete
                for item in dependencies
            ):
                raise MemoryAccessDenied("pending-write provenance is incomplete")
            self.memory.write_derived(
                self._typed_payload(
                    self._pending_write_payload(task_id, task_path, clean_writes)
                ),
                *dependencies,
                object_id=write_object,
                version_id=hashlib.sha256(
                    self._typed_payload(clean_writes)["payload_b64"].encode("ascii")
                ).hexdigest(),
                transformation="langgraph_postgres_pending_writes",
                purpose=self.purpose,
                capability_token=token,
            )
            self.__delegate.put_writes(provider_config, clean_writes, task_id, task_path)

        # Re-enter the full mediated read path after the provider mutation:
        # this validates the returned tuple identity/body/pending writes and
        # rechecks current authority, lineage and application policy.
        persisted = self.get_tuple(config)
        if persisted is None:
            raise MemoryIntegrityError("provider checkpoint disappeared after pending-write persistence")

    def get_tuple(self, config: Mapping[str, Any]) -> Optional[CheckpointTuple]:
        token, tenant, thread_id, namespace, object_id, provider_config = self._normalized_config(
            config, action="mem_read",
        )
        requested_id = config.get("configurable", {}).get("checkpoint_id")
        node = self._checkpoint_node(object_id, requested_id)
        if node is None:
            if requested_id:
                raise MemoryAccessDenied("requested checkpoint is absent from PACA provenance")
            return None

        expected = self.memory.read(
            object_id, node.version_id, purpose=self.purpose,
            capability_token=token,
        ).value
        provider_config["configurable"]["checkpoint_id"] = node.version_id
        result = self.__delegate.get_tuple(provider_config)
        if result is None:
            raise MemoryIntegrityError("PACA checkpoint evidence exists but PostgreSQL has no matching row")
        self._assert_provider_tuple(
            result,
            tenant=tenant,
            thread_id=thread_id,
            namespace=namespace,
            node=node,
        )
        if not isinstance(expected, Mapping):
            raise MemoryIntegrityError("PACA checkpoint evidence envelope is invalid")
        stored = self._decode_payload(expected)
        if not isinstance(stored, Mapping) or "checkpoint" not in stored or "metadata" not in stored:
            raise MemoryIntegrityError("PACA checkpoint evidence has an invalid structure")
        # Compare decoded structures rather than their serialized byte form.
        # Checkpoint savers may normalize mapping order or reconstruct blob-backed
        # channel values while preserving the logical checkpoint content.
        if result.checkpoint != stored["checkpoint"]:
            raise MemoryIntegrityError("PostgreSQL checkpoint body differs from authorized PACA evidence")
        if result.metadata != stored["metadata"]:
            raise MemoryIntegrityError("PostgreSQL checkpoint metadata differs from authorized PACA evidence")
        self._assert_pending_writes_match(
            token, tenant, thread_id, namespace, node.version_id, result.pending_writes,
        )
        self.memory.revalidate_read_access(
            object_id,
            node.version_id,
            purpose=self.purpose,
            capability_token=token,
        )
        return self._translate_tuple(result, thread_id)

    def list(
        self,
        config: Optional[Mapping[str, Any]],
        *,
        filter: Optional[Mapping[str, Any]] = None,
        before: Optional[Mapping[str, Any]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[CheckpointTuple]:
        if config is None:
            raise MemoryAccessDenied("global checkpoint listing is not available without explicit tenant and thread scope")
        _token, _tenant, _thread_id, _namespace, object_id, _provider = self._normalized_config(
            config, action="mem_read",
        )
        before_id = None
        if before is not None:
            if not isinstance(before, Mapping):
                raise MemoryAccessDenied("checkpoint list cursor is invalid")
            before_configurable = before.get("configurable")
            if not isinstance(before_configurable, Mapping):
                raise MemoryAccessDenied("checkpoint list cursor has no configurable scope")
            if (
                before_configurable.get("thread_id") != _thread_id
                or before_configurable.get("checkpoint_ns", "") != _namespace
            ):
                raise MemoryAccessDenied("checkpoint list cursor belongs to another thread or namespace")
            before_id = before_configurable.get("checkpoint_id")
            if not isinstance(before_id, str) or not before_id:
                raise MemoryAccessDenied("checkpoint list cursor is invalid")
        # list_nodes preserves durable insertion order (SQLite seq), whereas
        # checkpoint IDs are opaque identifiers and are not lexically ordered.
        nodes = [
            node for node in self.repository.list_nodes(object_id_prefix=object_id)
            if node.object_id == object_id and not self.repository.is_revoked(node.node_id)
        ]
        nodes.reverse()
        if before_id:
            before_index = next(
                (index for index, item in enumerate(nodes) if item.version_id == before_id),
                None,
            )
            if before_index is None:
                raise MemoryAccessDenied("checkpoint list cursor is outside the authorized evidence history")
            nodes = nodes[before_index + 1:]
        if limit is not None and limit <= 0:
            return
        emitted = 0
        for node in nodes:
            result = self.get_tuple({
                **dict(config),
                "configurable": {
                    **dict(config.get("configurable", {})),
                    "checkpoint_id": node.version_id,
                },
            })
            if result is None:
                continue
            if filter and any(result.metadata.get(key) != value for key, value in filter.items()):
                continue
            yield result
            emitted += 1
            if limit is not None and emitted >= limit:
                break

    def delete_thread(self, thread_id: str) -> None:
        if not isinstance(thread_id, str) or not thread_id:
            raise ValueError("thread_id must be a non-empty string")
        token = self._token_provider()
        try:
            signed = self.memory.authority.verify(token)
            authority = signed.capability.authority_lineage
            if authority is None:
                raise MemoryAccessDenied("checkpoint capability has no authority lineage")
            checkpoint_prefix = _thread_prefix(authority.tenant, thread_id)
            writes_prefix = (
                "mem/checkpoint-writes/" + _digest(authority.tenant) + "/"
                + _digest(thread_id) + "/"
            )
            scope = self.memory._verified_context(
                token, "mem_delete", checkpoint_prefix, self.purpose,
            )
            # Pending-write evidence lives under a separate object namespace and
            # must have its own explicit deletion grant as well.
            self.memory._verified_context(
                token, "mem_delete", writes_prefix, self.purpose,
            )
            self.memory._consume_budget(scope)
            for prefix in (checkpoint_prefix, writes_prefix):
                for node in self.repository.list_nodes(object_id_prefix=prefix):
                    if not self.repository.is_revoked(node.node_id):
                        self.repository.revoke_lineage(
                            node.node_id, "LangGraph checkpoint thread deleted",
                        )
            self.memory.registry.assert_active(authority.authority_id)
        except MemoryAccessDenied:
            raise
        except Exception as exc:
            raise MemoryAccessDenied("checkpoint deletion authority validation failed") from exc
        self.__delegate.delete_thread(_provider_thread_id(authority.tenant, thread_id))

    def get_next_version(self, current: Optional[str], channel: Optional[str]) -> str:
        return self.__delegate.get_next_version(current, channel)

    async def aput(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]:
        return await asyncio.to_thread(self.put, *args, **kwargs)

    async def aput_writes(self, *args: Any, **kwargs: Any) -> None:
        await asyncio.to_thread(self.put_writes, *args, **kwargs)

    async def aget_tuple(self, config: Mapping[str, Any]) -> Optional[CheckpointTuple]:
        return await asyncio.to_thread(self.get_tuple, config)

    async def alist(
        self,
        config: Optional[Mapping[str, Any]],
        *,
        filter: Optional[Mapping[str, Any]] = None,
        before: Optional[Mapping[str, Any]] = None,
        limit: Optional[int] = None,
    ):
        results = await asyncio.to_thread(
            lambda: list(self.list(config, filter=filter, before=before, limit=limit))
        )
        for result in results:
            yield result

    async def adelete_thread(self, thread_id: str) -> None:
        await asyncio.to_thread(self.delete_thread, thread_id)
