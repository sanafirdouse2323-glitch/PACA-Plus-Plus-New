from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("langgraph.checkpoint.postgres")

from langgraph.checkpoint.base import CheckpointTuple

from paca.integrations.langgraph_checkpoint import (
    PACAProvenancePostgresSaver,
    _provider_thread_id,
)
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


def _authenticated_thread():
    return _provider_thread_id("tenant-a", "thread")


def _provider_config(checkpoint_id, *, thread_id="paca-thread-hash"):
    return {
        "configurable": {
            "thread_id": thread_id,
            "checkpoint_ns": "worker",
            "checkpoint_id": checkpoint_id,
        }
    }


def test_provider_tuple_scope_and_parent_are_bound_to_paca_lineage():
    saver, current, _parent = _saver_with_lineage()
    authenticated_thread = _provider_thread_id("tenant-a", "thread")
    result = CheckpointTuple(
        config=_provider_config("current-checkpoint", thread_id=authenticated_thread),
        checkpoint={},
        metadata={},
        parent_config=_provider_config("parent-checkpoint", thread_id=authenticated_thread),
        pending_writes=[],
    )

    saver._assert_provider_tuple(
        result,
        tenant="tenant-a",
        thread_id="thread",
        namespace="worker",
        node=current,
        expected_parent_id="parent-checkpoint",
    )


@pytest.mark.parametrize(
    ("config", "parent_config"),
    [
        (_provider_config("current-checkpoint", thread_id="paca-other-thread"),
         _provider_config("parent-checkpoint", thread_id=_authenticated_thread())),
        (_provider_config("current-checkpoint", thread_id=_authenticated_thread()) | {"configurable": {
            "thread_id": _authenticated_thread(),
            "checkpoint_ns": "other-namespace",
            "checkpoint_id": "current-checkpoint",
        }}, _provider_config("parent-checkpoint", thread_id=_authenticated_thread())),
        (_provider_config("wrong-checkpoint", thread_id=_authenticated_thread()),
         _provider_config("parent-checkpoint", thread_id=_authenticated_thread())),
        (_provider_config("current-checkpoint", thread_id=_authenticated_thread()),
         _provider_config("unrelated-parent", thread_id=_authenticated_thread())),
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
            expected_parent_id="parent-checkpoint",
        )


def test_provider_tuple_rejects_missing_recorded_parent():
    saver, current, _parent = _saver_with_lineage()
    result = CheckpointTuple(
        config=_provider_config(
            "current-checkpoint",
            thread_id=_provider_thread_id("tenant-a", "thread"),
        ),
        checkpoint={},
        metadata={},
        parent_config=None,
        pending_writes=[],
    )

    with pytest.raises(MemoryIntegrityError, match="omitted the expected parent checkpoint config"):
        saver._assert_provider_tuple(
            result,
            tenant="tenant-a",
            thread_id="thread",
            namespace="worker",
            node=current,
            expected_parent_id="parent-checkpoint",
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

def test_async_checkpoint_thread_handoff_snapshots_mutable_inputs():
    from paca.integrations.langgraph_checkpoint import _snapshot_thread_arguments

    checkpoint = {
        "id": "checkpoint-1",
        "channel_values": {"messages": [{"content": "original"}]},
    }
    writes = [("messages", {"content": "before thread handoff"})]
    args, kwargs = _snapshot_thread_arguments(
        {"configurable": {"thread_id": "thread-1"}},
        checkpoint,
        writes,
        task_id="task-1",
    )

    checkpoint["channel_values"]["messages"][0]["content"] = "mutated"
    writes[0][1]["content"] = "mutated"
    assert args[1]["channel_values"]["messages"][0]["content"] == "original"
    assert args[2][0][1]["content"] == "before thread handoff"
    assert kwargs["task_id"] == "task-1"

def test_provider_tuple_rejects_parent_when_transition_evidence_has_none():
    saver, current, _parent = _saver_with_lineage()
    result = CheckpointTuple(
        config=_provider_config("current-checkpoint", thread_id=_authenticated_thread()),
        checkpoint={},
        metadata={},
        parent_config=_provider_config("parent-checkpoint", thread_id=_authenticated_thread()),
        pending_writes=[],
    )

    with pytest.raises(MemoryIntegrityError, match="not recorded by the checkpointer transition"):
        saver._assert_provider_tuple(
            result,
            tenant="tenant-a",
            thread_id="thread",
            namespace="worker",
            node=current,
            expected_parent_id=None,
        )
