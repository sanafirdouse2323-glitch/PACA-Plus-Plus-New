from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone

import pytest

DSN = os.environ.get("PACA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(
    not DSN, reason="PACA_TEST_POSTGRES_DSN is not configured",
)


def _environment(tmp_path):
    from paca.authority_runtime import HMACCapabilityAuthority, SQLiteAuthorityRegistry
    from paca.durable import SQLiteProvenanceRepository
    from paca.memory import (
        SQLiteMemoryValueStore,
        TrustedConnectorAdapter,
        TrustedMemoryAdapter,
    )

    clock = lambda: 1_000
    registry = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3", clock=clock)
    issuer = HMACCapabilityAuthority(
        registry,
        issuer_id="postgres-checkpoint-test",
        key_id="postgres-checkpoint-key",
        key=b"P" * 32,
        audience="postgres-checkpoint-runtime",
        identity_verifier=lambda principal, tenant: bool(principal and tenant == "acme"),
        clock=clock,
    )
    root = issuer.issue(
        principal="agent-a",
        tenant="acme",
        task_id="task-postgres",
        purpose="resume-agent",
        grants={
            "mem_read": ("mem/*",),
            "mem_write": ("mem/*",),
            "mem_delete": ("mem/*",),
        },
        expires_at=2_000,
        max_calls=200,
    )
    repository = SQLiteProvenanceRepository(tmp_path / "lineage.sqlite3")
    values = SQLiteMemoryValueStore(tmp_path / "values.sqlite3")
    memory = TrustedMemoryAdapter(
        repository,
        values,
        issuer,
        authorize=lambda _context, _node: True,
        clock=clock,
    )
    connector = TrustedConnectorAdapter(
        memory,
        connector_id="fixture:trusted-input",
        source_class="external_content",
        tenant="acme",
        integrity="untrusted",
    )
    source = connector.ingest(
        {"text": "captured input before checkpoint"},
        object_id="mem/postgres-source",
        version_id="v1",
        purpose="resume-agent",
        capability_token=root.token,
    )
    return root, repository, memory, source


def _wrap(raw, root, memory, source):
    from paca.integrations.langgraph_checkpoint import PACAProvenancePostgresSaver

    return PACAProvenancePostgresSaver(
        raw,
        memory,
        capability_token_provider=lambda: root.token,
        provenance_provider=lambda _config, _checkpoint, _metadata: (source,),
        writes_provenance_provider=lambda _config, _writes, _task, _path: (source,),
        purpose="resume-agent",
    )


def _checkpoint(
    checkpoint_id: str,
    answer: str,
    timestamp: datetime,
    channel_version: str = "1",
):
    return {
        "v": 4,
        "id": checkpoint_id,
        "ts": timestamp.isoformat(),
        "channel_values": {
            "answer": answer,
            "created_at": timestamp,
        },
        "channel_versions": {"created_at": channel_version},
        "versions_seen": {},
    }


def test_postgres_checkpoint_and_pending_write_paths_are_mediated(tmp_path, monkeypatch):
    from langgraph.checkpoint.postgres import PostgresSaver
    from paca.integrations.langgraph_checkpoint import _provider_thread_id
    from paca.memory import MemoryAccessDenied

    root, repository, memory, source = _environment(tmp_path)
    thread_id = "paca-test-" + uuid.uuid4().hex
    timestamp = datetime(2026, 11, 23, tzinfo=timezone.utc)
    checkpoint_id = str(uuid.uuid4())

    with PostgresSaver.from_conn_string(DSN) as raw:
        saver = _wrap(raw, root, memory, source)
        saver.setup()
        config = {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
        first_config = saver.put(
            config,
            _checkpoint(checkpoint_id, "safe-to-resume", timestamp, channel_version="1"),
            {"source": "input", "step": -1},
            {"created_at": "1"},
        )
        assert first_config["configurable"]["thread_id"] == thread_id

        task_id = str(uuid.uuid4())
        saver.put_writes(
            first_config,
            [("answer", "pending-safe")],
            task_id,
            task_path="node:worker-a",
        )
        result = saver.get_tuple(first_config)
        assert result is not None
        assert result.checkpoint["channel_values"]["answer"] == "safe-to-resume"
        assert result.checkpoint["channel_values"]["created_at"] == timestamp
        assert (task_id, "answer", "pending-safe") in result.pending_writes

        second_id = str(uuid.uuid4())
        second_config = saver.put(
            first_config,
            _checkpoint(
                second_id,
                "next-step",
                datetime(2026, 11, 23, 0, 0, 1, tzinfo=timezone.utc),
                channel_version="2",
            ),
            {"source": "loop", "step": 0},
            {"created_at": "2"},
        )
        checkpoint_nodes = repository.list_nodes(object_id_prefix="mem/checkpoints/")
        second_node = next(node for node in checkpoint_nodes if node.version_id == second_id)
        first_node = next(node for node in checkpoint_nodes if node.version_id == checkpoint_id)
        assert first_node.node_id in second_node.parent_ids
        assert saver.get_tuple(second_config).checkpoint["channel_values"]["answer"] == "next-step"

        # A revoked source must block before the raw PostgreSQL provider is called.
        source_id = next(iter(source.lineage_refs))
        repository.revoke_lineage(source_id, "checkpoint source revoked")
        calls = []
        original_get_tuple = raw.get_tuple
        monkeypatch.setattr(
            raw,
            "get_tuple",
            lambda cfg: (calls.append(cfg), original_get_tuple(cfg))[1],
        )
        with pytest.raises(MemoryAccessDenied):
            saver.get_tuple(first_config)
        assert calls == []

        # Negative control: a caller that retains the raw provider handle bypasses
        # the PACA wrapper. This is a known trust-boundary requirement.
        provider_config = {
            "configurable": {
                "thread_id": _provider_thread_id("acme", thread_id),
                "checkpoint_ns": "",
                "checkpoint_id": checkpoint_id,
            }
        }
        raw_result = original_get_tuple(provider_config)
        assert raw_result is not None
        assert raw_result.checkpoint["channel_values"]["answer"] == "safe-to-resume"

        saver.delete_thread(thread_id)


def test_postgres_checkpoint_list_and_async_contracts(tmp_path):
    from langgraph.checkpoint.postgres import PostgresSaver

    root, repository, memory, source = _environment(tmp_path)
    thread_id = "paca-test-" + uuid.uuid4().hex
    timestamp = datetime(2026, 11, 23, tzinfo=timezone.utc)
    first_id = "f" * 32
    second_id = "0" * 32

    with PostgresSaver.from_conn_string(DSN) as raw:
        saver = _wrap(raw, root, memory, source)
        saver.setup()
        config = {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
        first = saver.put(
            config,
            _checkpoint(first_id, "first-checkpoint", timestamp, channel_version="1"),
            {"source": "input", "step": -1},
            {"created_at": "1"},
        )
        second = saver.put(
            first,
            _checkpoint(
                second_id,
                "second-checkpoint",
                datetime(2026, 11, 23, 0, 0, 1, tzinfo=timezone.utc),
                channel_version="2",
            ),
            {"source": "loop", "step": 0},
            {"created_at": "2"},
        )

        # Checkpoint identifiers are opaque. Listing must use durable insertion
        # chronology, not lexical sorting of those identifiers.
        listed = list(saver.list(config))
        assert [
            item.config["configurable"]["checkpoint_id"] for item in listed
        ] == [second_id, first_id]
        before_second = {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": "",
                "checkpoint_id": second_id,
            }
        }
        assert [
            item.config["configurable"]["checkpoint_id"]
            for item in saver.list(config, before=before_second)
        ] == [first_id]

        assert saver.get_tuple(second) is not None
        assert asyncio.run(saver.aget_tuple(second)) is not None
        task_id = str(uuid.uuid4())
        saver.put_writes(
            second,
            [("answer", "pending-safe")],
            task_id,
            task_path="node:worker-a",
        )
        result = saver.get_tuple(second)
        assert result is not None
        assert (task_id, "answer", "pending-safe") in result.pending_writes

        from paca.integrations.langgraph_checkpoint import _writes_prefix
        writes_prefix = _writes_prefix("acme", thread_id, "", second_id)
        pending_nodes = repository.list_nodes(object_id_prefix=writes_prefix)
        assert pending_nodes
        assert not any(repository.is_revoked(node.node_id) for node in pending_nodes)

        async def collect_async_list():
            return [item async for item in saver.alist(config)]

        assert len(asyncio.run(collect_async_list())) == 2
        saver.delete_thread(thread_id)
        assert all(
            repository.is_revoked(node.node_id) for node in pending_nodes
        )
