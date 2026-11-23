"""Optional LangGraph/LangChain integration for provenance-aware agent execution.

Install the langgraph extra to use these adapters. The store implements the
LangGraph BaseStore contract; the middleware wraps every LangChain agent tool call.
Application callbacks are mandatory trust boundaries: a capability provider must
return the authenticated run credential, and a provenance provider must return the
complete trusted dependencies of a stored value.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple

try:
    from langgraph.store.base import (
        BaseStore, GetOp, Item, ListNamespacesOp, MatchCondition,
        NOT_PROVIDED, PutOp, SearchItem, SearchOp, validate_op_namespace,
    )
except ImportError as exc:  # pragma: no cover - covered by optional-dependency test
    raise ImportError(
        "PACA LangGraph integration requires the optional dependency "
        "paca-plus-plus[langgraph]"
    ) from exc

try:
    from langchain.agents.middleware import AgentMiddleware
except ImportError as exc:  # pragma: no cover - covered by optional-dependency test
    raise ImportError(
        "PACA tool middleware requires the optional dependency "
        "paca-plus-plus[langgraph]"
    ) from exc

from ..durable import SQLiteProvenanceRepository
from ..memory import MemoryAccessDenied, TrustedMemoryAdapter
from ..provenance import Arg
from ..runtime import Request, Tool


def _tenant_digest(tenant: str) -> str:
    if not isinstance(tenant, str) or not tenant:
        raise ValueError("tenant must be a non-empty string")
    return hashlib.sha256(tenant.encode("utf-8")).hexdigest()


def _object_prefix(tenant: str) -> str:
    return "mem/langgraph/" + _tenant_digest(tenant) + "/"


def _object_id(namespace: Tuple[str, ...], key: str, tenant: str) -> str:
    encoded = json.dumps(
        [list(namespace), key], separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return _object_prefix(tenant) + base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _decode_object_id(value: str) -> Tuple[str, Tuple[str, ...], str]:
    prefix = "mem/langgraph/"
    if not value.startswith(prefix):
        raise ValueError("not a PACA LangGraph memory object")
    remainder = value[len(prefix):]
    tenant_digest, separator, token = remainder.partition("/")
    if (
        not separator
        or len(tenant_digest) != 64
        or any(character not in "0123456789abcdef" for character in tenant_digest)
        or not token
    ):
        raise ValueError("invalid PACA LangGraph tenant scope")
    decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    parsed = json.loads(decoded)
    if (
        not isinstance(parsed, list)
        or len(parsed) != 2
        or not isinstance(parsed[0], list)
        or not all(isinstance(part, str) and part for part in parsed[0])
        or not isinstance(parsed[1], str)
        or not parsed[1]
    ):
        raise ValueError("invalid PACA LangGraph memory object identity")
    return tenant_digest, tuple(parsed[0]), parsed[1]


def _snapshot_tool_call_request(
    request: Any,
    tool_call: Mapping[str, Any],
    expected_digest: str,
) -> Any:
    """Create a framework request whose tool payload cannot follow caller mutation."""
    try:
        copied_call = copy.deepcopy(dict(tool_call))
        if _tool_call_digest(copied_call) != expected_digest:
            raise MemoryAccessDenied("LangChain tool call changed while being snapshotted")
        original_tool = getattr(request, "tool", None)
        if original_tool is None:
            raise MemoryAccessDenied("LangChain tool implementation is missing")
        copied_tool = copy.copy(original_tool)
        override = getattr(request, "override", None)
        if callable(override):
            snapshot = override(tool_call=copied_call, tool=copied_tool)
        else:
            snapshot = copy.copy(request)
            setattr(snapshot, "tool_call", copied_call)
            setattr(snapshot, "tool", copied_tool)
        if (
            _tool_call_digest(getattr(snapshot, "tool_call", {})) != expected_digest
            or getattr(getattr(snapshot, "tool", None), "name", None)
            != getattr(original_tool, "name", None)
        ):
            raise MemoryAccessDenied("LangChain request snapshot does not preserve the authorized call")
        return snapshot
    except MemoryAccessDenied:
        raise
    except Exception as exc:
        raise MemoryAccessDenied(
            "LangChain request cannot be safely snapshotted for tool execution"
        ) from exc


def _tool_call_digest(tool_call: Mapping[str, Any]) -> str:
    """Fingerprint the exact JSON tool call handed to LangChain's handler."""
    try:
        encoded = json.dumps(
            dict(tool_call),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MemoryAccessDenied(
            "LangChain tool arguments must be canonical JSON before mediation"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _matches_filter(value: Mapping[str, Any], filters: Optional[Mapping[str, Any]]) -> bool:
    if not filters:
        return True
    operators = {"$eq", "$ne", "$gt", "$gte", "$lt", "$lte"}
    for path, expected in filters.items():
        if not isinstance(path, str) or not path:
            return False
        current: Any = value
        for part in path.split("."):
            if not isinstance(current, Mapping) or part not in current:
                current = None
                break
            current = current[part]
        if isinstance(expected, Mapping) and expected and any(
            key in operators for key in expected
        ):
            if not set(expected).issubset(operators):
                return False
            for operator, target in expected.items():
                try:
                    if operator == "$eq" and current != target:
                        return False
                    if operator == "$ne" and current == target:
                        return False
                    if operator == "$gt" and not current > target:
                        return False
                    if operator == "$gte" and not current >= target:
                        return False
                    if operator == "$lt" and not current < target:
                        return False
                    if operator == "$lte" and not current <= target:
                        return False
                except (TypeError, ValueError):
                    return False
        elif current != expected:
            return False
    return True

class PACAProvenanceLangGraphStore(BaseStore):
    """LangGraph BaseStore backed by PACA's mediated, lineage-aware memory API.

    provenance_provider must return one or more complete Arg dependencies for
    each put. There is intentionally no automatic trust-the-model-summary path.
    Semantic/vector queries and TTL are not implemented; unsupported requests fail
    explicitly. Delete is an irreversible lineage revocation, not physical erasure.
    """

    supports_ttl = False

    def __init__(
        self,
        memory: TrustedMemoryAdapter,
        *,
        capability_token_provider: Callable[[], str],
        provenance_provider: Callable[
            [Tuple[str, ...], str, Mapping[str, Any]], Iterable[Arg]
        ],
        purpose: str,
    ) -> None:
        if not callable(capability_token_provider) or not callable(provenance_provider):
            raise TypeError("trusted capability and provenance providers are required")
        if not isinstance(purpose, str) or not purpose:
            raise ValueError("purpose must be a non-empty string")
        super().__init__()
        self.memory = memory
        self.repository: SQLiteProvenanceRepository = memory.repository
        self._token_provider = capability_token_provider
        self._provenance_provider = provenance_provider
        self.purpose = purpose

    def _tenant_for_token(self, token: str) -> str:
        try:
            signed = self.memory.authority.verify(token)
            authority = signed.capability.authority_lineage
            if authority is None:
                raise MemoryAccessDenied("LangGraph store capability has no authority lineage")
            return authority.tenant
        except MemoryAccessDenied:
            raise
        except Exception as exc:
            raise MemoryAccessDenied("LangGraph store capability authentication failed") from exc

    def _authorize_object(
        self,
        namespace: Tuple[str, ...],
        key: str,
        action: str,
    ) -> Tuple[str, str, str, Any]:
        token = self._token_provider()
        tenant = self._tenant_for_token(token)
        object_id = _object_id(namespace, key, tenant)
        context = self.memory._verified_context(
            token, action, object_id, self.purpose,
        )
        return token, tenant, object_id, context

    @staticmethod
    def _validate_namespace(namespace: Tuple[str, ...], key: str) -> Tuple[str, ...]:
        if (
            not isinstance(namespace, tuple)
            or not namespace
            or namespace[0] == "langgraph"
            or not all(
                isinstance(part, str) and part and "." not in part
                for part in namespace
            )
            or not isinstance(key, str)
            or not key
        ):
            raise ValueError("namespace must be a non-empty tuple of strings and key must be non-empty")
        return namespace

    def put(
        self,
        namespace: Tuple[str, ...],
        key: str,
        value: Mapping[str, Any],
        index: Any = None,
        *,
        ttl: Any = NOT_PROVIDED,
    ) -> None:
        namespace = self._validate_namespace(namespace, key)
        if ttl is not NOT_PROVIDED and ttl is not None:
            raise NotImplementedError("PACA LangGraph store does not implement TTL")
        if index is not None:
            raise NotImplementedError(
                "PACA LangGraph store does not implement vector/index configuration"
            )
        if not isinstance(value, Mapping) or any(not isinstance(k, str) for k in value):
            raise TypeError("LangGraph memory values must be string-keyed mappings")
        token, _tenant, object_id, _context = self._authorize_object(
            namespace, key, "mem_write",
        )
        dependencies = tuple(self._provenance_provider(namespace, key, value))
        previous = self.repository.latest_node(object_id)
        dependency_refs = set().union(
            *(item.lineage_refs for item in dependencies if isinstance(item, Arg))
        ) if dependencies else set()
        if previous is not None:
            if self.repository.is_revoked(previous.node_id):
                raise MemoryAccessDenied("a logically deleted or revoked LangGraph item cannot be overwritten")
            if previous.node_id not in dependency_refs:
                raise MemoryAccessDenied(
                    "LangGraph memory updates must include the previous version as a provenance dependency"
                )
        if not dependencies or any(
            not isinstance(item, Arg) or not item.lineage_refs or item.lineage_incomplete
            for item in dependencies
        ):
            raise MemoryAccessDenied(
                "LangGraph memory write requires complete trusted provenance dependencies"
            )
        self.memory.write_derived(
            dict(value),
            *dependencies,
            object_id=object_id,
            version_id=uuid.uuid4().hex,
            transformation="langgraph_store_put",
            purpose=self.purpose,
            capability_token=token,
        )

    def batch(self, ops: Iterable[Any]) -> list[Any]:
        """Dispatch the complete LangGraph synchronous batch operation contract.

        Operations are executed in input order. Each underlying SQLite mutation is
        transactional, but this sequence is not one cross-operation transaction.
        """
        results = []
        for op in ops:
            # BaseStore validates namespaces before its own batching helpers; direct
            # batch calls must apply the same checks explicitly.
            validate_op_namespace(op)
            if isinstance(op, GetOp):
                results.append(self.get(
                    op.namespace, op.key, refresh_ttl=op.refresh_ttl,
                ))
            elif isinstance(op, PutOp):
                if op.value is None:
                    self.delete(op.namespace, op.key)
                    results.append(None)
                else:
                    self.put(
                        op.namespace, op.key, op.value, index=op.index,
                        ttl=op.ttl,
                    )
                    results.append(None)
            elif isinstance(op, SearchOp):
                results.append(self.search(
                    op.namespace_prefix,
                    query=op.query,
                    filter=op.filter,
                    limit=op.limit,
                    offset=op.offset,
                    refresh_ttl=op.refresh_ttl,
                ))
            elif isinstance(op, ListNamespacesOp):
                namespaces = self.list_namespaces(
                    limit=2**31 - 1,
                    offset=0,
                    max_depth=op.max_depth,
                )
                for condition in op.match_conditions or ():
                    if not isinstance(condition, MatchCondition):
                        raise TypeError("namespace match condition has an unsupported type")
                    path = condition.path
                    if condition.match_type == "prefix":
                        namespaces = [
                            ns for ns in namespaces
                            if len(ns) >= len(path) and all(
                                expected == "*" or ns[index] == expected
                                for index, expected in enumerate(path)
                            )
                        ]
                    elif condition.match_type == "suffix":
                        namespaces = [
                            ns for ns in namespaces
                            if len(ns) >= len(path) and all(
                                expected == "*" or ns[len(ns) - len(path) + index] == expected
                                for index, expected in enumerate(path)
                            )
                        ]
                    else:
                        raise ValueError("unsupported namespace match type")
                results.append(namespaces[op.offset:op.offset + op.limit])
            else:
                raise TypeError("unsupported LangGraph store operation: " + type(op).__name__)
        return results

    async def abatch(self, ops: Iterable[Any]) -> list[Any]:
        """Async batch contract; preserve order while isolating blocking SQLite I/O."""
        return await asyncio.to_thread(self.batch, tuple(ops))

    def get(
        self,
        namespace: Tuple[str, ...],
        key: str,
        *,
        refresh_ttl: Optional[bool] = None,
    ) -> Optional[Item]:
        namespace = self._validate_namespace(namespace, key)
        token, _tenant, object_id, _context = self._authorize_object(
            namespace, key, "mem_read",
        )
        node = self.repository.latest_node(object_id)
        if node is None or self.repository.is_revoked(node.node_id):
            return None
        arg = self.memory.read(
            object_id,
            node.version_id,
            purpose=self.purpose,
            capability_token=token,
        )
        created_at = datetime.fromtimestamp(
            self.repository.node_created_at(node.node_id), tz=timezone.utc,
        )
        return Item(
            value=dict(arg.value),
            key=key,
            namespace=namespace,
            created_at=created_at,
            updated_at=created_at,
        )

    def delete(self, namespace: Tuple[str, ...], key: str) -> None:
        namespace = self._validate_namespace(namespace, key)
        # Resolve tenant identity before looking up object metadata. Identical
        # LangGraph namespace/key pairs in different tenants have distinct IDs.
        _token, _tenant, object_id, context = self._authorize_object(
            namespace, key, "mem_delete",
        )
        # Logical delete is an irreversible lineage revocation, not physical erasure.
        self.memory._consume_budget(context)
        nodes = self.repository.list_nodes(object_id_prefix=object_id)
        matched = [node for node in nodes if node.object_id == object_id]
        if not matched:
            return
        for node in matched:
            if not self.repository.is_revoked(node.node_id):
                self.repository.revoke_lineage(
                    node.node_id, "LangGraph memory item logically deleted",
                )

    def search(
        self,
        namespace_prefix: Tuple[str, ...],
        *,
        query: Optional[str] = None,
        filter: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        offset: int = 0,
        refresh_ttl: Optional[bool] = None,
    ) -> list[SearchItem]:
        if query is not None:
            raise NotImplementedError("semantic/vector search is not configured for PACA LangGraph memory")
        if (
            not isinstance(namespace_prefix, tuple)
            or not all(
                isinstance(part, str) and part and "." not in part
                for part in namespace_prefix
            )
        ):
            raise ValueError("namespace_prefix must be a tuple of non-empty strings")
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")

        token = self._token_provider()
        tenant = self._tenant_for_token(token)
        tenant_prefix = _object_prefix(tenant)
        latest: Dict[str, Any] = {}
        for node in self.repository.list_nodes(object_id_prefix=tenant_prefix):
            latest[node.object_id] = node
        selected = []
        for object_id, node in latest.items():
            if self.repository.is_revoked(node.node_id):
                continue
            try:
                decoded_tenant, namespace, key = _decode_object_id(object_id)
            except ValueError:
                continue
            if decoded_tenant != _tenant_digest(tenant):
                continue
            if namespace[:len(namespace_prefix)] != namespace_prefix:
                continue
            arg = self.memory.read(
                object_id,
                node.version_id,
                purpose=self.purpose,
                capability_token=token,
            )
            value = dict(arg.value)
            if not _matches_filter(value, filter):
                continue
            created_at = datetime.fromtimestamp(
                self.repository.node_created_at(node.node_id), tz=timezone.utc,
            )
            selected.append(SearchItem(
                namespace=namespace,
                key=key,
                value=value,
                created_at=created_at,
                updated_at=created_at,
                score=None,
            ))
        selected.sort(key=lambda item: (item.namespace, item.key))
        return selected[offset:offset + limit]

    def list_namespaces(
        self,
        *,
        prefix: Optional[Tuple[str, ...]] = None,
        suffix: Optional[Tuple[str, ...]] = None,
        max_depth: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Tuple[str, ...]]:
        if limit < 0 or offset < 0 or (max_depth is not None and max_depth < 0):
            raise ValueError("invalid namespace pagination or depth")
        if prefix is not None and (
            not isinstance(prefix, tuple)
            or not all(isinstance(part, str) and part for part in prefix)
        ):
            raise ValueError("prefix must be a tuple of non-empty strings")
        if suffix is not None and (
            not isinstance(suffix, tuple)
            or not all(isinstance(part, str) and part for part in suffix)
        ):
            raise ValueError("suffix must be a tuple of non-empty strings")
        namespaces = set()
        token = self._token_provider()
        tenant = self._tenant_for_token(token)
        tenant_prefix = _object_prefix(tenant)
        latest: Dict[str, Any] = {}
        for node in self.repository.list_nodes(object_id_prefix=tenant_prefix):
            latest[node.object_id] = node
        for object_id, node in latest.items():
            if self.repository.is_revoked(node.node_id):
                continue
            try:
                decoded_tenant, namespace, _key = _decode_object_id(object_id)
            except ValueError:
                continue
            if decoded_tenant != _tenant_digest(tenant):
                continue
            if prefix is not None and (
                len(prefix) > len(namespace)
                or any(expected != "*" and namespace[index] != expected
                       for index, expected in enumerate(prefix))
            ):
                continue
            if suffix is not None and (
                len(suffix) > len(namespace)
                or any(expected != "*" and namespace[len(namespace) - len(suffix) + index] != expected
                       for index, expected in enumerate(suffix))
            ):
                continue
            if max_depth is not None:
                namespace = namespace[:max_depth]
            # Namespace enumeration discloses object metadata. Apply the
            # same ancestry, tenant, inherited-authority and application policy
            # checks as value retrieval, without fetching the protected value.
            self.memory.authorize_metadata(
                object_id,
                node.version_id,
                purpose=self.purpose,
                capability_token=token,
            )
            namespaces.add(namespace)
        return sorted(namespaces)[offset:offset + limit]

    async def aput(
        self,
        namespace: Tuple[str, ...],
        key: str,
        value: Mapping[str, Any],
        index: Any = None,
        *,
        ttl: Any = NOT_PROVIDED,
    ) -> None:
        await asyncio.to_thread(self.put, namespace, key, value, index, ttl=ttl)

    async def aget(
        self,
        namespace: Tuple[str, ...],
        key: str,
        *,
        refresh_ttl: Optional[bool] = None,
    ) -> Optional[Item]:
        return await asyncio.to_thread(self.get, namespace, key, refresh_ttl=refresh_ttl)

    async def adelete(self, namespace: Tuple[str, ...], key: str) -> None:
        await asyncio.to_thread(self.delete, namespace, key)

    async def asearch(
        self,
        namespace_prefix: Tuple[str, ...],
        *,
        query: Optional[str] = None,
        filter: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        offset: int = 0,
        refresh_ttl: Optional[bool] = None,
    ) -> list[SearchItem]:
        return await asyncio.to_thread(
            self.search, namespace_prefix, query=query, filter=filter,
            limit=limit, offset=offset, refresh_ttl=refresh_ttl,
        )

    async def alist_namespaces(
        self,
        *,
        prefix: Optional[Tuple[str, ...]] = None,
        suffix: Optional[Tuple[str, ...]] = None,
        max_depth: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Tuple[str, ...]]:
        return await asyncio.to_thread(
            self.list_namespaces, prefix=prefix, suffix=suffix,
            max_depth=max_depth, limit=limit, offset=offset,
        )


class PACALangChainToolMiddleware(AgentMiddleware):
    """Intercept every LangChain/LangGraph agent tool call through PACA runtime.

    request_factory is trusted application code. It must map every configured tool
    to an action-specific PACA Request and preserve argument/resource provenance.
    Unknown or unmapped tools fail closed. The middleware does not modify tools or
    allow an unmediated fallback path.
    """

    def __init__(
        self,
        runtime: Any,
        *,
        capability_token_provider: Callable[[Any], str],
        tool_manifest_provider: Callable[[Any], Tool],
        request_factory: Callable[[Any], Request],
    ) -> None:
        super().__init__()
        if (
            not callable(capability_token_provider)
            or not callable(tool_manifest_provider)
            or not callable(request_factory)
        ):
            raise TypeError(
                "trusted capability, registered-tool manifest and action-mapping callbacks are required"
            )
        self.runtime = runtime
        self._token_provider = capability_token_provider
        self._tool_manifest_provider = tool_manifest_provider
        self._request_factory = request_factory

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        tool_call = getattr(request, "tool_call", None)
        tool = getattr(request, "tool", None)
        if (
            not isinstance(tool_call, Mapping)
            or not isinstance(tool_call.get("name"), str)
            or not tool_call.get("name")
            or tool is None
            or getattr(tool, "name", None) != tool_call.get("name")
        ):
            raise MemoryAccessDenied("LangChain tool identity is missing or does not match the registered tool")
        tool_call_digest = _tool_call_digest(tool_call)
        actual_manifest = self._tool_manifest_provider(tool)
        if (
            not isinstance(actual_manifest, Tool)
            or actual_manifest.name != tool_call["name"]
        ):
            raise MemoryAccessDenied("registered tool has no trusted PACA manifest or its identity differs")
        paca_request = self._request_factory(request)
        if not isinstance(paca_request, Request):
            raise TypeError("request_factory must return a PACA Request")
        if paca_request.tool != actual_manifest:
            raise MemoryAccessDenied("PACA action mapping does not match the registered tool manifest")
        if _tool_call_digest(getattr(request, "tool_call", {})) != tool_call_digest:
            raise MemoryAccessDenied("LangChain tool call changed while its PACA request was being constructed")
        frozen_request = _snapshot_tool_call_request(
            request, tool_call, tool_call_digest,
        )
        if self._tool_manifest_provider(frozen_request.tool) != actual_manifest:
            raise MemoryAccessDenied("snapshotted tool implementation differs from the registered manifest")
        token = self._token_provider(request)
        signed = self.runtime.authority.verify(token)
        pin = signed.capability.tool_pins.get(tool_call["name"])
        if pin is None or not hmac.compare_digest(pin, actual_manifest.hash):
            raise MemoryAccessDenied("LangChain tool manifest is not pinned by the authenticated capability")

        def checked_handler(_validated: Any) -> Any:
            current_call = getattr(request, "tool_call", None)
            current_tool = getattr(request, "tool", None)
            if (
                not isinstance(current_call, Mapping)
                or _tool_call_digest(current_call) != tool_call_digest
                or current_tool is None
                or getattr(current_tool, "name", None) != actual_manifest.name
            ):
                raise MemoryAccessDenied("LangChain tool call or identity changed after PACA authorization")
            current_manifest = self._tool_manifest_provider(current_tool)
            if current_manifest != actual_manifest:
                raise MemoryAccessDenied("registered tool manifest changed after PACA authorization")
            if _tool_call_digest(frozen_request.tool_call) != tool_call_digest:
                raise MemoryAccessDenied("frozen LangChain tool call changed before handler invocation")
            if self._tool_manifest_provider(frozen_request.tool) != actual_manifest:
                raise MemoryAccessDenied("snapshotted tool manifest changed before handler invocation")
            return handler(frozen_request)

        decision, result = self.runtime.execute_effect(
            token,
            paca_request,
            checked_handler,
        )
        if decision.verdict != "allow":
            raise MemoryAccessDenied("PACA denied the LangChain tool call")
        return result

    async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        tool_call = getattr(request, "tool_call", None)
        tool = getattr(request, "tool", None)
        if (
            not isinstance(tool_call, Mapping)
            or not isinstance(tool_call.get("name"), str)
            or not tool_call.get("name")
            or tool is None
            or getattr(tool, "name", None) != tool_call.get("name")
        ):
            raise MemoryAccessDenied("LangChain tool identity is missing or does not match the registered tool")
        tool_call_digest = _tool_call_digest(tool_call)
        actual_manifest = self._tool_manifest_provider(tool)
        if (
            not isinstance(actual_manifest, Tool)
            or actual_manifest.name != tool_call["name"]
        ):
            raise MemoryAccessDenied("registered tool has no trusted PACA manifest or its identity differs")
        paca_request = self._request_factory(request)
        if not isinstance(paca_request, Request):
            raise TypeError("request_factory must return a PACA Request")
        if paca_request.tool != actual_manifest:
            raise MemoryAccessDenied("PACA action mapping does not match the registered tool manifest")
        if _tool_call_digest(getattr(request, "tool_call", {})) != tool_call_digest:
            raise MemoryAccessDenied("LangChain tool call changed while its PACA request was being constructed")
        frozen_request = _snapshot_tool_call_request(
            request, tool_call, tool_call_digest,
        )
        if self._tool_manifest_provider(frozen_request.tool) != actual_manifest:
            raise MemoryAccessDenied("snapshotted tool implementation differs from the registered manifest")
        token = self._token_provider(request)
        signed = self.runtime.authority.verify(token)
        pin = signed.capability.tool_pins.get(tool_call["name"])
        if pin is None or not hmac.compare_digest(pin, actual_manifest.hash):
            raise MemoryAccessDenied("LangChain tool manifest is not pinned by the authenticated capability")

        async def checked_handler(_validated: Any) -> Any:
            current_call = getattr(request, "tool_call", None)
            current_tool = getattr(request, "tool", None)
            if (
                not isinstance(current_call, Mapping)
                or _tool_call_digest(current_call) != tool_call_digest
                or current_tool is None
                or getattr(current_tool, "name", None) != actual_manifest.name
            ):
                raise MemoryAccessDenied("LangChain tool call or identity changed after PACA authorization")
            current_manifest = self._tool_manifest_provider(current_tool)
            if current_manifest != actual_manifest:
                raise MemoryAccessDenied("registered tool manifest changed after PACA authorization")
            if _tool_call_digest(frozen_request.tool_call) != tool_call_digest:
                raise MemoryAccessDenied("frozen LangChain tool call changed before handler invocation")
            if self._tool_manifest_provider(frozen_request.tool) != actual_manifest:
                raise MemoryAccessDenied("snapshotted tool manifest changed before handler invocation")
            result = handler(frozen_request)
            if hasattr(result, "__await__"):
                return await result
            return result

        decision, result = await self.runtime.aexecute_effect(
            token,
            paca_request,
            checked_handler,
        )
        if decision.verdict != "allow":
            raise MemoryAccessDenied("PACA denied the LangChain tool call")
        return result


__all__ = ["PACALangChainToolMiddleware", "PACAProvenanceLangGraphStore"]
