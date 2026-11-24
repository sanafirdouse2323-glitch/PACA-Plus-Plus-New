from __future__ import annotations

import asyncio
import threading

import pytest

pytest.importorskip("langgraph")

from paca.integrations.langgraph import (
    NOT_PROVIDED,
    PACAProvenanceLangGraphStore,
    _snapshot_async_inputs,
)
from paca.memory import MemoryAccessDenied


def test_async_store_inputs_are_deep_copied_before_thread_handoff(monkeypatch):
    store = object.__new__(PACAProvenanceLangGraphStore)
    seen = {}

    def put(namespace, key, value, index=None, *, ttl=None):
        seen["put"] = (namespace, key, value, index, ttl)

    def batch(ops):
        seen["batch"] = ops
        return ["ok"] * len(ops)

    def search(namespace_prefix, **kwargs):
        seen["search"] = (namespace_prefix, kwargs)
        return []

    def list_namespaces(**kwargs):
        seen["namespaces"] = kwargs
        return []

    store.put = put
    store.batch = batch
    store.search = search
    store.list_namespaces = list_namespaces

    async def inline_to_thread(function, *args, **kwargs):
        # Execute with precisely the objects captured by the wrapper.
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", inline_to_thread)

    async def exercise():
        value = {"nested": [{"text": "before handoff"}]}
        await store.aput(("acme", "memory"), "one", value)
        value["nested"][0]["text"] = "mutated by caller"
        assert seen["put"][2] == {"nested": [{"text": "before handoff"}]}
        assert seen["put"][2] is not value
        assert seen["put"][4] is NOT_PROVIDED

        operations = [{"operation": "put", "value": {"body": "original"}}]
        result = await store.abatch(operations)
        operations[0]["value"]["body"] = "changed"
        assert result == ["ok"]
        assert seen["batch"][0]["value"]["body"] == "original"
        assert seen["batch"] is not operations

        filters = {"kind": {"$in": ["report", "summary"]}}
        await store.asearch(("acme",), filter=filters)
        filters["kind"]["$in"].append("secret")
        assert seen["search"][1]["filter"] == {
            "kind": {"$in": ["report", "summary"]},
        }
        assert seen["search"][1]["filter"] is not filters

        prefix = ("acme", "memory")
        await store.alist_namespaces(prefix=prefix, limit=10)
        assert seen["namespaces"]["prefix"] == prefix

    asyncio.run(exercise())


def test_async_store_snapshot_rejects_inputs_that_cannot_be_copied():
    lock = threading.Lock()
    with pytest.raises(MemoryAccessDenied, match="cannot be safely snapshotted"):
        _snapshot_async_inputs({"runtime_lock": lock})


def test_async_store_read_and_delete_wrappers_use_snapshotted_arguments(monkeypatch):
    store = object.__new__(PACAProvenanceLangGraphStore)
    seen = []

    def get(namespace, key, *, refresh_ttl=None):
        seen.append(("get", namespace, key, refresh_ttl))
        return "item"

    def delete(namespace, key):
        seen.append(("delete", namespace, key))

    store.get = get
    store.delete = delete

    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", inline_to_thread)

    async def exercise():
        namespace = ("acme", "memory")
        assert await store.aget(namespace, "key", refresh_ttl=False) == "item"
        await store.adelete(namespace, "key")

    asyncio.run(exercise())
    assert seen == [
        ("get", ("acme", "memory"), "key", False),
        ("delete", ("acme", "memory"), "key"),
    ]


def test_langchain_middleware_old_import_path_is_compatible():
    pytest.importorskip("langchain")
    from paca.integrations.langchain_middleware import (
        PACALangChainToolMiddleware as ExtractedMiddleware,
    )
    from paca.integrations.langgraph import (
        PACALangChainToolMiddleware as CompatibilityMiddleware,
    )

    assert CompatibilityMiddleware is ExtractedMiddleware
