from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from paca.authority_runtime import (
    HMACCapabilityAuthority,
    SQLiteAuthorityRegistry,
)
from paca.durable import SQLiteProvenanceRepository
from paca.memory import (
    HMACAgentMessageCodec,
    MemoryAccessDenied,
    PACAAgentRuntime,
    SQLiteMemoryValueStore,
    TrustedConnectorAdapter,
    TrustedMemoryAdapter,
    canonical_value_bytes,
)
from paca.provenance import Arg, Label
from paca.resource_commit import ResourceCommitDenied, SQLiteFencedResourceExecutor
from paca.runtime import Decision, Request, Tool


def _write_tool() -> Tool:
    return Tool("write_file", "1.0", "Write a file to the workspace", ("path", "content"))


def _environment(tmp_path, *, max_calls=40):
    now = [1_000]
    clock = lambda: now[0]
    registry = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3", clock=clock)
    issuer = HMACCapabilityAuthority(
        registry,
        issuer_id="fenced-test-issuer",
        key_id="fenced-test-key",
        key=b"R" * 32,
        audience="fenced-test-runtime",
        identity_verifier=lambda principal, tenant: bool(principal and tenant == "acme"),
        task_context_verifier=lambda principal, tenant, task_id, purpose: (
            principal == "agent-a"
            and tenant == "acme"
            and task_id == "task-fence"
            and purpose == "write-report"
        ),
        clock=clock,
    )
    tool = _write_tool()
    signed = issuer.issue(
        principal="agent-a",
        tenant="acme",
        task_id="task-fence",
        purpose="write-report",
        grants={
            "mem_read": ("mem/*",),
            "write_file": ("/acme/*",),
        },
        expires_at=2_000,
        max_calls=max_calls,
        max_fanout=2,
        tool_pins={"write_file": tool.hash},
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
    messages = HMACAgentMessageCodec(
        b"S" * 32, issuer, repository, memory=memory, clock=clock,
    )
    connector = TrustedConnectorAdapter(
        memory,
        connector_id="fixture:trusted-input",
        source_class="tool_input",
        tenant="acme",
        sensitivity=1,
        integrity="untrusted",
    )
    path = connector.ingest(
        "/acme/reports/report.txt",
        object_id="mem/fence/path",
        version_id="v1",
        purpose="write-report",
        capability_token=signed.token,
    )
    content = connector.ingest(
        "approved report body",
        object_id="mem/fence/content",
        version_id="v1",
        purpose="write-report",
        capability_token=signed.token,
    )

    class AllowMonitor:
        def decide(self, request):
            return Decision("allow", digest=request.digest)

        def verify(self, request, decision):
            return decision.digest == request.digest

    runtime = PACAAgentRuntime(
        issuer,
        memory,
        AllowMonitor(),
        messages,
        require_resource_commit_fence=True,
    )
    request = Request(
        "write_file",
        {"path": path, "content": content},
        issuer.verify(signed.token).capability,
        1,
        tool=tool,
    )
    executor = SQLiteFencedResourceExecutor(issuer)
    return {
        "clock": clock,
        "registry": registry,
        "issuer": issuer,
        "signed": signed,
        "repository": repository,
        "memory": memory,
        "runtime": runtime,
        "request": request,
        "executor": executor,
        "tool": tool,
    }


def _stored_resource(registry, *, resource="/acme/reports/report.txt"):
    with sqlite3.connect(registry.database) as connection:
        row = connection.execute(
            "SELECT value_json,payload_digest,version,authority_id,request_digest,commit_nonce "
            "FROM paca_resource_values WHERE tenant=? AND task_id=? AND resource_key=?",
            ("acme", "task-fence", resource),
        ).fetchone()
    return row


def test_resource_write_and_effect_budget_commit_in_one_authority_transaction(tmp_path):
    env = _environment(tmp_path)
    decision, result = env["runtime"].execute_effect(
        env["signed"].token,
        env["request"],
        env["executor"],
    )

    assert decision.verdict == "allow"
    assert result["resource"] == "/acme/reports/report.txt"
    assert result["version"] == 1
    stored = _stored_resource(env["registry"])
    assert stored is not None
    assert json.loads(stored[0]) == {"content": "approved report body"}
    assert stored[1] == hashlib.sha256(
        canonical_value_bytes({"content": "approved report body"})
    ).hexdigest()
    assert stored[2] == 1
    assert stored[3] == env["signed"].capability.cap_id
    # Two source-argument reads and the actual effect commit were charged.
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 3
    assert env["registry"].task_usage("acme", "task-fence")[0] == 3


def test_strict_runtime_rejects_in_process_executor_before_any_budget_or_effect(tmp_path):
    env = _environment(tmp_path)
    executed = []
    with pytest.raises(MemoryAccessDenied, match="requires the runtime-bound"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            lambda request: executed.append(request) or "unsafe",
        )
    assert executed == []
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 0
    assert _stored_resource(env["registry"]) is None


def test_revocation_between_runtime_authorization_and_resource_commit_blocks_write(tmp_path):
    env = _environment(tmp_path)
    executor = env["executor"]
    original = executor.execute_authorized

    def revoke_before_commit(request, permit):
        env["registry"].revoke(
            env["signed"].capability.cap_id,
            "test revocation before resource commit",
        )
        return original(request, permit)

    executor.execute_authorized = revoke_before_commit
    with pytest.raises(ResourceCommitDenied, match="atomic authority fence"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            executor,
        )

    assert _stored_resource(env["registry"]) is None
    # Only the two source-read charges happened; the fenced effect was not charged.
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 2


def test_commit_permit_is_one_use_and_cannot_be_replayed(tmp_path, monkeypatch):
    env = _environment(tmp_path)
    issued = []
    original_issue = env["issuer"].issue_resource_commit_permit

    def capture_permit(*args, **kwargs):
        permit = original_issue(*args, **kwargs)
        issued.append(permit)
        return permit

    monkeypatch.setattr(env["issuer"], "issue_resource_commit_permit", capture_permit)
    env["runtime"].execute_effect(env["signed"].token, env["request"], env["executor"])
    usage_after_first_commit = env["registry"].usage(env["signed"].capability.cap_id)[0]
    with pytest.raises(ResourceCommitDenied, match="atomic authority fence"):
        env["executor"].execute_authorized(env["request"], issued[0])

    stored = _stored_resource(env["registry"])
    assert stored is not None and stored[2] == 1
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == usage_after_first_commit


def test_resource_commit_rejects_modified_signed_permit(tmp_path):
    env = _environment(tmp_path)
    permit = env["issuer"].issue_resource_commit_permit(
        env["signed"].token,
        request_digest=env["request"].digest,
        action="write_file",
        resource="/acme/reports/report.txt",
        payload_digest=hashlib.sha256(
            canonical_value_bytes({"content": "approved report body"})
        ).hexdigest(),
    )
    tampered = permit[:-1] + ("A" if permit[-1] != "A" else "B")
    with pytest.raises(ResourceCommitDenied, match="permit authentication"):
        env["executor"].execute_authorized(env["request"], tampered)
    assert _stored_resource(env["registry"]) is None


def test_revocation_waits_for_inflight_commit_and_linearizes_after_it(tmp_path, monkeypatch):
    env = _environment(tmp_path)
    permit = env["issuer"].issue_resource_commit_permit(
        env["signed"].token,
        request_digest=env["request"].digest,
        action="write_file",
        resource="/acme/reports/report.txt",
        payload_digest=hashlib.sha256(
            canonical_value_bytes({"content": "approved report body"})
        ).hexdigest(),
    )
    registry = env["registry"]
    original_is_active = registry._is_active
    checked_active = threading.Event()
    release_commit = threading.Event()
    revoke_started = threading.Event()

    def pause_after_active_check(connection, authority_id):
        active = original_is_active(connection, authority_id)
        if authority_id == env["signed"].capability.cap_id:
            checked_active.set()
            if not release_commit.wait(timeout=10):
                raise RuntimeError("test did not release the commit transaction")
        return active

    monkeypatch.setattr(registry, "_is_active", pause_after_active_check)

    def commit():
        return env["executor"].execute_authorized(env["request"], permit)

    def revoke():
        revoke_started.set()
        return registry.revoke(
            env["signed"].capability.cap_id,
            "revocation serialized after an in-flight local resource commit",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        commit_future = pool.submit(commit)
        assert checked_active.wait(timeout=10)
        revoke_future = pool.submit(revoke)
        assert revoke_started.wait(timeout=10)
        # The commit is holding BEGIN IMMEDIATE; revoke cannot overtake it.
        release_commit.set()
        committed = commit_future.result(timeout=10)
        revoked = revoke_future.result(timeout=10)

    assert committed["version"] == 1
    assert env["signed"].capability.cap_id in revoked
    assert not registry.is_active(env["signed"].capability.cap_id)
    assert _stored_resource(registry) is not None


def test_task_quota_exhaustion_prevents_resource_write_and_rolls_back_receipt(tmp_path):
    env = _environment(tmp_path, max_calls=3)
    # Pre-consume one unit. The two lineage reads can then complete, but
    # the commit transaction sees an exhausted quota and cannot write.
    env["registry"].consume_effect(
        env["signed"].capability.cap_id,
        max_calls=3,
    )
    with pytest.raises(ResourceCommitDenied, match="atomic authority fence"):
        env["runtime"].execute_effect(
            env["signed"].token,
            env["request"],
            env["executor"],
        )
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 3
    assert _stored_resource(env["registry"]) is None
    with sqlite3.connect(env["registry"].database) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM paca_resource_commit_receipts"
        ).fetchone()[0]
    assert count == 0


def test_async_runtime_uses_the_same_resource_commit_fence(tmp_path):
    env = _environment(tmp_path)

    async def exercise():
        decision, result = await env["runtime"].aexecute_effect(
            env["signed"].token,
            env["request"],
            env["executor"],
        )
        assert decision.verdict == "allow"
        assert result["version"] == 1

    asyncio.run(exercise())
    stored = _stored_resource(env["registry"])
    assert stored is not None
    assert json.loads(stored[0]) == {"content": "approved report body"}
    assert env["registry"].usage(env["signed"].capability.cap_id)[0] == 3
