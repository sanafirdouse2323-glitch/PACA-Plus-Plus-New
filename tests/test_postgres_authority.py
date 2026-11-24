from __future__ import annotations

import hashlib
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

DSN = os.environ.get("PACA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(
    not DSN, reason="PACA_TEST_POSTGRES_DSN is not configured",
)


def _environment(*, max_task_calls=20):
    from paca.authority_runtime import HMACCapabilityAuthority
    from paca.memory import canonical_value_bytes
    from paca.postgres_authority import PostgresAuthorityRegistry

    suffix = uuid.uuid4().hex
    tenant = "tenant-" + suffix
    task_id = "task-" + suffix
    now = [1_000]
    clock = lambda: now[0]
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
            "write_file": ("/workspace/*",),
            "mem_read": ("mem/*",),
            "receive_agent_message": ("agent-a", "agent-b"),
            "send_agent_message": ("agent-a", "agent-b"),
        },
        expires_at=2_000,
        max_calls=30,
        max_fanout=4,
        max_task_calls=max_task_calls,
    )
    resource_payload = {"content": "shared-primary resource"}
    resource_digest = hashlib.sha256(canonical_value_bytes(resource_payload)).hexdigest()
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
    with pytest.raises(CapabilityAuthenticationError, match="authentication failed"):
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

    with env["registry_b"]._connect() as connection:
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
                raise RuntimeError("test did not release the PostgreSQL commit transaction")
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
