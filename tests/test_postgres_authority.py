from __future__ import annotations

import hashlib
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace

import pytest

DSN = os.environ.get("PACA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(
    not DSN,
    reason="PACA_TEST_POSTGRES_DSN is not configured",
)


def _environment(*, max_task_calls=20):
    from paca.authority_runtime import HMACCapabilityAuthority
    from paca.memory import canonical_value_bytes
    from paca.postgres_authority import PostgresAuthorityRegistry
    from paca.runtime import Tool

    suffix = uuid.uuid4().hex
    tenant = "tenant-" + suffix
    task_id = "task-" + suffix
    now = [1_000]

    def clock():
        return now[0]

    registry_a = PostgresAuthorityRegistry(DSN, clock=clock, timeout=20)
    registry_b = PostgresAuthorityRegistry(DSN, clock=clock, timeout=20)

    def identity(principal, requested_tenant):
        return principal in {"agent-a", "agent-b"} and requested_tenant == tenant

    def task_context(principal, requested_tenant, requested_task, purpose):
        return (
            principal in {"agent-a", "agent-b"}
            and requested_tenant == tenant
            and requested_task == task_id
            and purpose == "write-report"
        )

    key = hashlib.sha256(("key-" + suffix).encode()).digest()
    write_tool = Tool(
        "write_file",
        "1.0",
        "Write a file to the workspace",
        ("path", "content"),
    )
    common = {
        "issuer_id": "postgres-issuer-" + suffix,
        "key_id": "postgres-key-" + suffix,
        "key": key,
        "audience": "postgres-test-" + suffix,
        "identity_verifier": identity,
        "task_context_verifier": task_context,
        "clock": clock,
    }
    issuer_a = HMACCapabilityAuthority(registry_a, **common)
    issuer_b = HMACCapabilityAuthority(registry_b, **common)
    root = issuer_a.issue(
        principal="agent-a",
        tenant=tenant,
        task_id=task_id,
        purpose="write-report",
        grants={
            "read_file": ("/workspace/*",),
            "write_file": ("/workspace/*",),
            "mem_read": ("mem/*",),
            "mem_write": ("mem/*",),
            "receive_agent_message": ("agent-a", "agent-b"),
            "send_agent_message": ("agent-a", "agent-b"),
        },
        expires_at=2_000,
        max_calls=30,
        max_fanout=4,
        tool_pins={"write_file": write_tool.hash},
        max_task_calls=max_task_calls,
    )
    resource_payload = {"content": "shared-primary resource"}
    resource_digest = hashlib.sha256(
        canonical_value_bytes(resource_payload)
    ).hexdigest()
    permit = issuer_a.issue_resource_commit_permit(
        root.token,
        request_digest="a" * 64,
        action="write_file",
        resource="/workspace/" + suffix + ".txt",
        payload_digest=resource_digest,
    )
    verified_permit = issuer_b.verify_resource_commit_permit(permit)
    return {
        "tenant": tenant,
        "task_id": task_id,
        "clock": clock,
        "registry_a": registry_a,
        "registry_b": registry_b,
        "issuer_a": issuer_a,
        "issuer_b": issuer_b,
        "root": root,
        "write_tool": write_tool,
        "resource_payload": resource_payload,
        "resource_digest": resource_digest,
        "permit_token": permit,
        "permit": verified_permit,
    }


def test_postgres_registry_shares_aggregate_quota_across_independent_clients():
    from paca.authority_runtime import AuthorityRegistryError

    env = _environment(max_task_calls=3)
    authority_id = env["root"].capability.cap_id
    for _ in range(3):
        env["registry_a"].consume_effect(authority_id, max_calls=10)

    assert env["registry_b"].task_usage(env["tenant"], env["task_id"]) == (3, 3)
    with pytest.raises(AuthorityRegistryError, match="task-wide call budget"):
        env["registry_b"].consume_effect(authority_id, max_calls=10)
    assert env["registry_a"].usage(authority_id) == (3, 0)


def test_postgres_revocation_is_visible_to_independent_verifier_instance():
    from paca.authority_runtime import CapabilityAuthenticationError

    env = _environment()
    env["registry_a"].revoke(
        env["root"].capability.cap_id,
        "cross-client PostgreSQL revocation propagation test",
    )
    with pytest.raises(
        CapabilityAuthenticationError,
        match="capability authentication or active-state validation failed",
    ):
        env["issuer_b"].verify(env["root"].token)
    assert not env["registry_b"].is_active(env["root"].capability.cap_id)


def test_postgres_message_receipt_prevents_replay_across_independent_clients():
    from paca.authority_runtime import AuthorityRegistryError

    env = _environment()
    message_id = "message-" + uuid.uuid4().hex
    authority_id = env["root"].capability.cap_id
    env["registry_a"].consume_message(
        authority_id,
        message_id,
        max_calls=30,
    )
    with pytest.raises(AuthorityRegistryError, match="replay"):
        env["registry_b"].consume_message(
            authority_id,
            message_id,
            max_calls=30,
        )
    assert env["registry_b"].usage(authority_id) == (1, 0)


def test_postgres_fenced_resource_commit_and_quota_are_shared_across_clients():
    from paca.authority_runtime import AuthorityRegistryError

    env = _environment()
    first = env["registry_a"].commit_fenced_resource_write(
        env["permit"],
        env["resource_payload"],
    )
    assert first["version"] == 1
    assert env["registry_b"].task_usage(env["tenant"], env["task_id"]) == (1, 20)

    with pytest.raises(AuthorityRegistryError):
        env["registry_b"].commit_fenced_resource_write(
            env["permit"],
            env["resource_payload"],
        )
    assert env["registry_a"].usage(env["root"].capability.cap_id) == (1, 0)

    with closing(env["registry_b"]._connect()) as connection:
        row = connection.execute(
            "SELECT value_json,payload_digest,version FROM paca_resource_values "
            "WHERE tenant=? AND task_id=? AND resource_key=?",
            (env["tenant"], env["task_id"], first["resource"]),
        ).fetchone()
    assert row is not None
    assert row["value_json"] == '{"content":"shared-primary resource"}'
    assert row["payload_digest"] == env["resource_digest"]
    assert row["version"] == 1


def test_postgres_resource_commit_serializes_before_revoke_across_clients(monkeypatch):
    env = _environment()
    registry_a = env["registry_a"]
    registry_b = env["registry_b"]
    authority_id = env["root"].capability.cap_id
    original_is_active = registry_a._is_active
    checked = threading.Event()
    release_commit = threading.Event()
    revoke_started = threading.Event()

    def pause_after_active_check(connection, checked_authority_id):
        active = original_is_active(connection, checked_authority_id)
        if checked_authority_id == authority_id:
            checked.set()
            if not release_commit.wait(timeout=15):
                raise RuntimeError(
                    "test did not release the PostgreSQL commit transaction"
                )
        return active

    monkeypatch.setattr(registry_a, "_is_active", pause_after_active_check)

    def commit():
        return registry_a.commit_fenced_resource_write(
            env["permit"],
            env["resource_payload"],
        )

    def revoke():
        revoke_started.set()
        return registry_b.revoke(
            authority_id,
            "PostgreSQL resource commit serializes before revoke",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        commit_future = pool.submit(commit)
        assert checked.wait(timeout=15)
        revoke_future = pool.submit(revoke)
        assert revoke_started.wait(timeout=15)
        release_commit.set()
        committed = commit_future.result(timeout=20)
        revoked = revoke_future.result(timeout=20)

    assert committed["version"] == 1
    assert authority_id in revoked
    assert not registry_a.is_active(authority_id)
    assert registry_b.usage(authority_id) == (1, 0)


def test_postgres_filesystem_commit_callback_serializes_with_revocation(
    tmp_path,
    monkeypatch,
):
    env = _environment()
    target = tmp_path / "resource.txt"
    staged = tmp_path / "resource.staged"
    with staged.open("wb") as stream:
        stream.write(b"postgres transactional filesystem resource")
        stream.flush()
        os.fsync(stream.fileno())

    renamed = threading.Event()
    allow_transaction_commit = threading.Event()
    revoke_begin_attempted = threading.Event()
    revoke_finished = threading.Event()
    original_connect = env["registry_b"]._connect

    def tracked_connect():
        connection = original_connect()
        original_execute = connection.execute

        def tracked_execute(statement, parameters=()):
            if statement.strip() == "BEGIN IMMEDIATE":
                revoke_begin_attempted.set()
            return original_execute(statement, parameters)

        connection.execute = tracked_execute
        return connection

    monkeypatch.setattr(env["registry_b"], "_connect", tracked_connect)

    def commit_callback():
        os.replace(staged, target)
        directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        renamed.set()
        if not allow_transaction_commit.wait(timeout=20):
            raise RuntimeError("test did not release PostgreSQL filesystem commit")

    def commit():
        return env["registry_a"].commit_fenced_filesystem_write(
            env["permit"],
            env["resource_payload"],
            commit_callback=commit_callback,
        )

    def revoke():
        try:
            return env["registry_b"].revoke(
                env["root"].capability.cap_id,
                "PostgreSQL filesystem commit serializes before revocation",
            )
        finally:
            revoke_finished.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        commit_future = pool.submit(commit)
        assert renamed.wait(timeout=20)
        revoke_future = pool.submit(revoke)
        assert revoke_begin_attempted.wait(timeout=20)
        # The second client reached BEGIN IMMEDIATE while the first transaction
        # still holds its registry-wide write lock. Revocation must remain blocked.
        assert not revoke_finished.wait(timeout=0.5)
        allow_transaction_commit.set()
        committed = commit_future.result(timeout=30)
        revoked = revoke_future.result(timeout=30)

    assert target.read_bytes() == b"postgres transactional filesystem resource"
    assert committed["version"] == 1
    assert env["root"].capability.cap_id in revoked
    assert not env["registry_a"].is_active(env["root"].capability.cap_id)
    receipt = env["registry_b"].get_resource_commit_receipt(committed["commit_nonce"])
    assert receipt is not None
    assert receipt["task_id"] == env["task_id"]


def test_postgres_fenced_runtime_commits_through_shared_primary_registry(tmp_path):
    from paca.durable import SQLiteProvenanceRepository
    from paca.memory import (
        HMACAgentMessageCodec,
        PACAAgentRuntime,
        SQLiteMemoryValueStore,
        TrustedConnectorAdapter,
        TrustedMemoryAdapter,
    )
    from paca.resource_commit import FencedResourceExecutor
    from paca.runtime import Decision, Request

    env = _environment()
    repository = SQLiteProvenanceRepository(tmp_path / "lineage.sqlite3")
    values = SQLiteMemoryValueStore(tmp_path / "values.sqlite3")
    memory = TrustedMemoryAdapter(
        repository,
        values,
        env["issuer_a"],
        authorize=lambda _context, _node: True,
        clock=env["clock"],
    )
    messages = HMACAgentMessageCodec(
        b"M" * 32,
        env["issuer_a"],
        repository,
        memory=memory,
        clock=env["clock"],
    )
    source_id = "fixture:postgres-runtime-" + uuid.uuid4().hex
    connector = TrustedConnectorAdapter(
        memory,
        connector_id=source_id,
        source_class="tool_input",
        tenant=env["tenant"],
        sensitivity=1,
        integrity="untrusted",
    )
    suffix = uuid.uuid4().hex
    resource = f"/workspace/{suffix}.txt"
    path_argument = connector.ingest(
        resource,
        object_id="mem/postgres-runtime/path-" + suffix,
        version_id="v1",
        purpose="write-report",
        capability_token=env["root"].token,
    )
    content_argument = connector.ingest(
        "PostgreSQL strict-runtime write",
        object_id="mem/postgres-runtime/content-" + suffix,
        version_id="v1",
        purpose="write-report",
        capability_token=env["root"].token,
    )

    class AllowMonitor:
        def decide(self, request):
            return Decision("allow", digest=request.digest)

        def verify(self, request, decision):
            return decision.digest == request.digest

    assert env["registry_a"].authority_store_id == env["registry_b"].authority_store_id
    assert env["registry_a"].authority_store_id.startswith("postgresql:")
    assert DSN not in env["registry_a"].authority_store_id

    verifier_store_id = env["registry_b"].authority_store_id
    env["registry_b"].authority_store_id = "postgresql:" + uuid.uuid4().hex
    with pytest.raises(ValueError, match="authority store"):
        PACAAgentRuntime(
            env["issuer_a"],
            memory,
            AllowMonitor(),
            messages,
            require_resource_commit_fence=True,
            resource_commit_verifier=env["issuer_b"],
        )
    env["registry_b"].authority_store_id = verifier_store_id

    runtime = PACAAgentRuntime(
        env["issuer_a"],
        memory,
        AllowMonitor(),
        messages,
        require_resource_commit_fence=True,
        resource_commit_verifier=env["issuer_b"],
    )
    request = Request(
        "write_file",
        {"path": path_argument, "content": content_argument},
        env["issuer_a"].verify(env["root"].token).capability,
        1,
        tool=env["write_tool"],
    )
    executor = FencedResourceExecutor(env["issuer_b"])

    decision, result = runtime.execute_effect(
        env["root"].token,
        request,
        executor,
    )

    assert decision.verdict == "allow"
    assert result["resource"] == resource
    assert result["version"] == 1
    assert env["registry_b"].task_usage(env["tenant"], env["task_id"]) == (5, 20)
    assert env["registry_a"].usage(env["root"].capability.cap_id)[0] == 5

    with closing(env["registry_b"]._connect()) as connection:
        row = connection.execute(
            "SELECT value_json,payload_digest,version,authority_id "
            "FROM paca_resource_values "
            "WHERE tenant=? AND task_id=? AND resource_key=?",
            (env["tenant"], env["task_id"], resource),
        ).fetchone()
    assert row is not None
    assert row["value_json"] == '{"content":"PostgreSQL strict-runtime write"}'
    assert (
        row["payload_digest"]
        == hashlib.sha256(b'{"content":"PostgreSQL strict-runtime write"}').hexdigest()
    )
    assert row["version"] == 1
    assert row["authority_id"] == env["root"].capability.cap_id


def _broker_access_receipt(
    session_id: str,
    operation_id: str,
    nonce: str,
    request_digest: str,
    payload_digest: str | None = None,
) -> dict[str, str]:
    nonce_digest = hashlib.sha256(
        b"PACA++/BROKER-NONCE/V1\\n"
        + session_id.encode("utf-8")
        + b"\\n"
        + nonce.encode("utf-8")
    ).hexdigest()
    receipt = {
        "session_id": session_id,
        "nonce_digest": nonce_digest,
        "operation_id": operation_id,
        "request_digest": request_digest,
    }
    if payload_digest is not None:
        receipt["payload_digest"] = payload_digest
    return receipt


def test_postgres_resource_read_and_write_receipts_are_shared_and_replay_safe():
    from paca.authority_runtime import AuthorityRegistryError
    from paca.contracts import digest_object

    env = _environment()
    authority_id = env["root"].capability.cap_id
    resource = "/workspace/" + uuid.uuid4().hex + ".json"
    payload = {"content": "postgres broker resource", "version": 1}
    payload_digest = digest_object(payload, purpose="payload")
    write_operation_id = "write-" + uuid.uuid4().hex
    write_request_digest = digest_object(
        {"operation_id": write_operation_id, "resource": resource},
        purpose="request",
    )
    write_receipt = _broker_access_receipt(
        "session-" + uuid.uuid4().hex,
        write_operation_id,
        "nonce-" + uuid.uuid4().hex,
        write_request_digest,
        payload_digest,
    )
    permit_token = env["issuer_a"].issue_resource_commit_permit(
        env["root"].token,
        request_digest=write_request_digest,
        action="write_file",
        resource=resource,
        payload_digest=payload_digest,
    )
    permit = replace(
        env["issuer_b"].verify_resource_commit_permit(permit_token),
        permit_id="protocol-commit-" + uuid.uuid4().hex,
        idempotency_key=write_operation_id,
    )
    provenance = {
        "tenant": env["tenant"],
        "task_id": env["task_id"],
        "purpose": "write-report",
        "payload_digest": payload_digest,
        "integrity": "untrusted",
        "sensitivity": 1,
        "provenance_refs": ["postgres-source:v1"],
        "evidence_digest": digest_object(
            {"source": "postgres-source:v1", "payload_digest": payload_digest},
            purpose="provenance",
        ),
    }

    committed = env["registry_a"].commit_fenced_resource_write(
        permit,
        payload,
        expected_principal="agent-a",
        access_receipt=write_receipt,
        provenance_metadata=provenance,
        protocol_payload_digest=True,
        expected_resource_version=0,
    )
    assert committed["version"] == 1
    assert committed["idempotent_replay"] is False

    exact_retry = env["registry_b"].commit_fenced_resource_write(
        permit,
        payload,
        expected_principal="agent-a",
        access_receipt=write_receipt,
        provenance_metadata=provenance,
        protocol_payload_digest=True,
        expected_resource_version=0,
    )
    assert exact_retry["version"] == 1
    assert exact_retry["idempotent_replay"] is True

    replacement_permit = replace(
        permit,
        nonce="replacement-nonce-" + uuid.uuid4().hex,
        permit_id="replacement-commit-" + uuid.uuid4().hex,
    )
    replacement_retry = env["registry_b"].commit_fenced_resource_write(
        replacement_permit,
        payload,
        expected_principal="agent-a",
        access_receipt=write_receipt,
        provenance_metadata=provenance,
        protocol_payload_digest=True,
        expected_resource_version=0,
    )
    assert replacement_retry["version"] == 1
    assert replacement_retry["idempotent_replay"] is True
    assert env["registry_a"].usage(authority_id) == (1, 0)

    with closing(env["registry_b"]._connect()) as connection:
        commit_rows = connection.execute(
            "SELECT permit_id,idempotency_key,result_version "
            "FROM paca_resource_commit_receipts "
            "WHERE tenant=? AND task_id=? AND resource_key=?",
            (env["tenant"], env["task_id"], resource),
        ).fetchall()
    assert len(commit_rows) == 2
    assert {row["permit_id"] for row in commit_rows} == {
        permit.permit_id,
        replacement_permit.permit_id,
    }
    assert sum(row["idempotency_key"] == write_operation_id for row in commit_rows) == 1
    assert all(row["result_version"] == 1 for row in commit_rows)

    read_operation_id = "read-" + uuid.uuid4().hex
    read_request_digest = digest_object(
        {"operation_id": read_operation_id, "resource": resource},
        purpose="request",
    )
    read_receipt = _broker_access_receipt(
        "session-" + uuid.uuid4().hex,
        read_operation_id,
        "nonce-" + uuid.uuid4().hex,
        read_request_digest,
    )
    result = env["registry_b"].read_fenced_resource(
        authority_id=authority_id,
        tenant=env["tenant"],
        task_id=env["task_id"],
        purpose="write-report",
        resource=resource,
        max_calls=env["root"].capability.max_calls,
        access_receipt=read_receipt,
        expected_resource_version=1,
    )

    assert result["found"] is True
    assert result["value"] == payload
    assert result["provenance_metadata"] == provenance
    assert result["payload_digest"] == payload_digest
    assert env["registry_a"].usage(authority_id)[0] == 2

    with closing(env["registry_a"]._connect()) as connection:
        access_rows = connection.execute(
            "SELECT operation_id,action,outcome,payload_digest "
            "FROM paca_resource_access_receipts "
            "WHERE operation_id IN (?,?) ORDER BY operation_id",
            (write_operation_id, read_operation_id),
        ).fetchall()
    assert len(access_rows) == 2
    assert {row["operation_id"] for row in access_rows} == {
        write_operation_id,
        read_operation_id,
    }
    assert {row["outcome"] for row in access_rows} == {"committed", "found"}

    with pytest.raises(AuthorityRegistryError, match="replay|duplicate"):
        env["registry_a"].read_fenced_resource(
            authority_id=authority_id,
            tenant=env["tenant"],
            task_id=env["task_id"],
            purpose="write-report",
            resource=resource,
            max_calls=env["root"].capability.max_calls,
            access_receipt=read_receipt,
            expected_resource_version=1,
        )

    assert env["registry_b"].usage(authority_id)[0] == 2
