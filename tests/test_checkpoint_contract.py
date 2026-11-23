from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("langgraph.checkpoint.postgres")

from langgraph.checkpoint.base import CheckpointTuple

from paca.integrations.langgraph_checkpoint import PACAProvenancePostgresSaver
from paca.memory import MemoryIntegrityError


class _Repository:
    def __init__(self, nodes):
        self._nodes = {node.node_id: node for node in nodes}

    def get_node(self, node_id):
        return self._nodes.get(node_id)


def _node(node_id, version_id, parent_ids=()):
    return SimpleNamespace(
        node_id=node_id,
        object_id="mem/checkpoints/tenant/thread/namespace",
        version_id=version_id,
        parent_ids=tuple(parent_ids),
    )


def _saver_with_lineage():
    parent = _node("parent-node", "parent-checkpoint")
    current = _node("current-node", "current-checkpoint", ("parent-node",))
    saver = object.__new__(PACAProvenancePostgresSaver)
    saver.repository = _Repository((parent, current))
    return saver, current, parent


def _provider_config(checkpoint_id):
    return {
        "configurable": {
            "thread_id": "paca-thread-hash",
            "checkpoint_ns": "worker",
            "checkpoint_id": checkpoint_id,
        }
    }


def test_provider_tuple_scope_and_parent_are_bound_to_paca_lineage():
    saver, current, _parent = _saver_with_lineage()
    result = CheckpointTuple(
        config=_provider_config("current-checkpoint"),
        checkpoint={},
        metadata={},
        parent_config=_provider_config("parent-checkpoint"),
        pending_writes=[],
    )

    saver._assert_provider_tuple(
        result,
        tenant="tenant-a",
        thread_id="thread",
        namespace="worker",
        node=current,
    )


@pytest.mark.parametrize(
    ("config", "parent_config"),
    [
        (_provider_config("current-checkpoint") | {"configurable": {
            "thread_id": "paca-other-thread",
            "checkpoint_ns": "worker",
            "checkpoint_id": "current-checkpoint",
        }}, _provider_config("parent-checkpoint")),
        (_provider_config("current-checkpoint") | {"configurable": {
            "thread_id": "paca-thread-hash",
            "checkpoint_ns": "other-namespace",
            "checkpoint_id": "current-checkpoint",
        }}, _provider_config("parent-checkpoint")),
        (_provider_config("wrong-checkpoint"), _provider_config("parent-checkpoint")),
        (_provider_config("current-checkpoint"), _provider_config("unrelated-parent")),
    ],
)
def test_provider_tuple_rejects_wrong_checkpoint_scope_or_parent(config, parent_config):
    saver, current, _parent = _saver_with_lineage()
    result = CheckpointTuple(
        config=config,
        checkpoint={},
        metadata={},
        parent_config=parent_config,
        pending_writes=[],
    )

    with pytest.raises(MemoryIntegrityError):
        saver._assert_provider_tuple(
            result,
            tenant="tenant-a",
            thread_id="thread",
            namespace="worker",
            node=current,
        )


def test_provider_tuple_rejects_missing_recorded_parent():
    saver, current, _parent = _saver_with_lineage()
    result = CheckpointTuple(
        config=_provider_config("current-checkpoint"),
        checkpoint={},
        metadata={},
        parent_config=None,
        pending_writes=[],
    )

    with pytest.raises(MemoryIntegrityError, match="omitted the parent checkpoint"):
        saver._assert_provider_tuple(
            result,
            tenant="tenant-a",
            thread_id="thread",
            namespace="worker",
            node=current,
        )


def test_provider_config_requires_authenticated_thread_namespace_and_id():
    valid = _provider_config("checkpoint-1")
    assert PACAProvenancePostgresSaver._provider_configurable(
        valid,
        expected_thread_id="paca-thread-hash",
        expected_namespace="worker",
        expected_checkpoint_id="checkpoint-1",
    ) == valid["configurable"]

    with pytest.raises(MemoryIntegrityError, match="thread namespace"):
        PACAProvenancePostgresSaver._provider_configurable(
            _provider_config("checkpoint-1") | {"configurable": {
                "thread_id": "paca-other-thread",
                "checkpoint_ns": "worker",
                "checkpoint_id": "checkpoint-1",
            }},
            expected_thread_id="paca-thread-hash",
            expected_namespace="worker",
            expected_checkpoint_id="checkpoint-1",
        )

def test_checkpoint_list_rejects_cursor_from_another_thread_or_namespace():
    from paca.memory import MemoryAccessDenied

    saver = object.__new__(PACAProvenancePostgresSaver)
    saver._normalized_config = lambda _config, action: (
        "signed-token", "tenant-a", "thread-a", "worker", "object-id", {},
    )
    config = {
        "configurable": {
            "thread_id": "thread-a",
            "checkpoint_ns": "worker",
        }
    }
    cursors = (
        {
            "configurable": {
                "thread_id": "thread-b",
                "checkpoint_ns": "worker",
                "checkpoint_id": "same-checkpoint-id",
            }
        },
        {
            "configurable": {
                "thread_id": "thread-a",
                "checkpoint_ns": "other-namespace",
                "checkpoint_id": "same-checkpoint-id",
            }
        },
    )
    for cursor in cursors:
        with pytest.raises(MemoryAccessDenied, match="different thread or namespace|another thread or namespace"):
            list(saver.list(config, before=cursor))
