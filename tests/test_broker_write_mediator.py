from __future__ import annotations

import hashlib
import sqlite3
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from paca.authority_runtime import HMACCapabilityAuthority, SQLiteAuthorityRegistry
from paca.broker import BrokerResourceDenied
from paca.broker_write import InProcessBrokerWriteMediator
from paca.contracts import (
    BrokerOperationVerifier,
    BrokerSessionContext,
    MessageSigner,
    MessageVerifier,
    TrustedMessageKey,
    digest_object,
)
from paca.durable import SQLiteProvenanceRepository
from paca.memory import canonical_value_bytes
from paca.provenance import Label, LineageNode

BROKER_ISSUER = "worker-issuer"
BROKER_KEY_ID = "worker-key-1"
BROKER_AUDIENCE = "paca-broker"
GRANT_ISSUER = "capability-issuer"
GRANT_AUDIENCE = "paca-resource-broker"
PERMIT_ISSUER = "commit-issuer"
PERMIT_KEY_ID = "commit-key-1"
PERMIT_AUDIENCE = "paca-local-commit-pep"
DESTINATION = "local-logical-resource-registry"
CHANNEL_BINDING = "a" * 64
TENANT = "tenant-1"
TASK = "task-1"
PRINCIPAL = "agent-1"
PURPOSE = "report-generation"
RESOURCE = "reports/report.json"
TEST_NOW = 1_795_600_800.0
NOW_TEXT = "2026-11-25T10:00:00Z"
EXPIRY_TEXT = "2026-11-25T10:00:15Z"


def _signed_message_tools():
    worker_private = Ed25519PrivateKey.generate()
    worker_signer = MessageSigner(
        key_id=BROKER_KEY_ID,
        issuer=BROKER_ISSUER,
        audiences=frozenset({BROKER_AUDIENCE}),
        private_key=worker_private,
    )
    worker_verifier = MessageVerifier(
        {
            BROKER_KEY_ID: TrustedMessageKey(
                public_key=worker_private.public_key(),
                issuer=BROKER_ISSUER,
                audiences=frozenset({BROKER_AUDIENCE}),
                message_types=frozenset({"paca.broker-operation.v1"}),
            )
        }
    )

    permit_private = Ed25519PrivateKey.generate()
    permit_signer = MessageSigner(
        key_id=PERMIT_KEY_ID,
        issuer=PERMIT_ISSUER,
        audiences=frozenset({PERMIT_AUDIENCE}),
        private_key=permit_private,
    )
    permit_verifier = MessageVerifier(
        {
            PERMIT_KEY_ID: TrustedMessageKey(
                public_key=permit_private.public_key(),
                issuer=PERMIT_ISSUER,
                audiences=frozenset({PERMIT_AUDIENCE}),
                message_types=frozenset({"paca.commit-permit.v1"}),
            )
        }
    )
    return worker_signer, worker_verifier, permit_signer, permit_verifier


def _environment(tmp_path):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3",
        clock=lambda: TEST_NOW,
    )
    provenance_repository = SQLiteProvenanceRepository(tmp_path / "provenance.sqlite3")
    provenance_node = LineageNode(
        object_id="report-source",
        version_id="source-v1",
        source="trusted-test-source",
        source_class="external_content",
        content_digest="b" * 64,
        label=Label(
            integrity="untrusted",
            sensitivity=1,
            tenant=TENANT,
            origins=frozenset({"trusted-test-source"}),
        ),
        purpose=PURPOSE,
    )
    provenance_repository.add(provenance_node)
    authority = HMACCapabilityAuthority(
        registry,
        issuer_id=GRANT_ISSUER,
        key_id="grant-key-1",
        key=b"G" * 32,
        audience=GRANT_AUDIENCE,
        identity_verifier=lambda principal, tenant: (
            principal == PRINCIPAL and tenant == TENANT
        ),
        task_context_verifier=lambda principal, tenant, task_id, purpose: (
            principal == PRINCIPAL
            and tenant == TENANT
            and task_id == TASK
            and purpose == PURPOSE
        ),
        clock=lambda: TEST_NOW,
    )
    grant = authority.issue(
        principal=PRINCIPAL,
        tenant=TENANT,
        task_id=TASK,
        purpose=PURPOSE,
        grants={
            "read_file": ("reports/*",),
            "write_file": ("reports/*",),
        },
        expires_at=int(TEST_NOW) + 900,
        max_calls=10,
        max_task_calls=30,
    )

    initial_payload = {"content": "old version"}
    initial_digest = hashlib.sha256(canonical_value_bytes(initial_payload)).hexdigest()
    initial_permit = authority.verify_resource_commit_permit(
        authority.issue_resource_commit_permit(
            grant.token,
            request_digest="d" * 64,
            action="write_file",
            resource=RESOURCE,
            payload_digest=initial_digest,
        )
    )
    registry.commit_fenced_resource_write(initial_permit, initial_payload)

    worker_signer, worker_verifier, permit_signer, permit_verifier = (
        _signed_message_tools()
    )
    session = BrokerSessionContext(
        session_id="session-write-1",
        issuer=BROKER_ISSUER,
        key_id=BROKER_KEY_ID,
        audience=BROKER_AUDIENCE,
        channel_binding_digest=CHANNEL_BINDING,
        principal_id=PRINCIPAL,
        workload_id="worker-1",
        tenant_id=TENANT,
        task_id=TASK,
        purpose=PURPOSE,
    )
    permit_store = {}

    def resolve_permit(permit_id):
        return permit_store[permit_id]

    def verify_provenance(operation, record, refs, repository):
        if record.authority_id != grant.capability.cap_id:
            raise ValueError("wrong grant for provenance")
        if refs != [
            {
                "object_id": "report-source",
                "version_id": "source-v1",
                "content_digest": {
                    "algorithm": "sha-256",
                    "value": "b" * 64,
                },
            }
        ]:
            raise ValueError("unexpected provenance references")
        source = repository.get_version("report-source", "source-v1")
        if (
            source is None
            or source.node_id != provenance_node.node_id
            or source.content_digest != "b" * 64
            or source.purpose != PURPOSE
            or TENANT not in source.label.tenants
            or repository.is_revoked(source.node_id)
        ):
            raise ValueError("source lineage is absent, mismatched or revoked")
        return {
            "classification": "internal",
            "source_refs": ["report-source@source-v1"],
            "lineage_refs": [source.node_id],
            "verified_by": "trusted-test-adapter",
        }

    mediator = InProcessBrokerWriteMediator(
        BrokerOperationVerifier(worker_verifier, clock=lambda: TEST_NOW),
        permit_verifier,
        registry,
        grant_issuer=GRANT_ISSUER,
        grant_audience=GRANT_AUDIENCE,
        permit_issuer=PERMIT_ISSUER,
        permit_audience=PERMIT_AUDIENCE,
        destination_id=DESTINATION,
        permit_resolver=resolve_permit,
        provenance_repository=provenance_repository,
        provenance_commit_check=verify_provenance,
        clock=lambda: TEST_NOW,
    )
    return {
        "registry": registry,
        "provenance_repository": provenance_repository,
        "provenance_node": provenance_node,
        "authority": authority,
        "grant": grant,
        "worker_signer": worker_signer,
        "permit_signer": permit_signer,
        "permit_store": permit_store,
        "session": session,
        "mediator": mediator,
        "provenance_check": verify_provenance,
    }


def _unsigned_write_message(env, *, operation_id="operation-write-2", version="1"):
    payload = {"content": "new protected report"}
    return {
        "message_id": "message-write-2",
        "message_type": "paca.broker-operation.v1",
        "contract_version": "1.0.0",
        "created_at": NOW_TEXT,
        "issuer": BROKER_ISSUER,
        "audience": BROKER_AUDIENCE,
        "operation_id": operation_id,
        "session_id": env["session"].session_id,
        "channel_binding_digest": {
            "algorithm": "sha-256",
            "value": CHANNEL_BINDING,
        },
        "request_nonce": "worker-request-nonce-0002",
        "operation": "write",
        "resource": {
            "resource_type": "file",
            "resource_id": RESOURCE,
            "version_id": version,
        },
        "authorization_grant_ref": env["grant"].capability.cap_id,
        "idempotency_key": operation_id,
        "payload_digest": {
            "algorithm": "sha-256",
            "value": digest_object(payload, purpose="payload"),
        },
        "payload": payload,
        "provenance_refs": [
            {
                "object_id": "report-source",
                "version_id": "source-v1",
                "content_digest": {
                    "algorithm": "sha-256",
                    "value": "b" * 64,
                },
            }
        ],
    }


def _signed_write(
    env,
    *,
    permit_id="commit-permit-2",
    permit_nonce="commit-permit-nonce-0002",
    permit_overrides=None,
    operation_overrides=None,
):
    message = _unsigned_write_message(env)
    if operation_overrides:
        message.update(operation_overrides)
    intent_digest = digest_object(message, purpose="request")
    payload_digest = message["payload_digest"]["value"]
    permit_message = {
        "message_id": "commit-permit-message-2",
        "message_type": "paca.commit-permit.v1",
        "contract_version": "1.0.0",
        "created_at": NOW_TEXT,
        "issuer": PERMIT_ISSUER,
        "audience": PERMIT_AUDIENCE,
        "permit_id": permit_id,
        "grant_id": env["grant"].capability.cap_id,
        "operation_id": message["operation_id"],
        "subject": {"kind": "agent", "id": PRINCIPAL},
        "tenant_id": TENANT,
        "task_id": TASK,
        "purpose": PURPOSE,
        "action": "write_file",
        "resource": {
            "resource_type": "file",
            "resource_id": RESOURCE,
            "version_id": message["resource"]["version_id"],
        },
        "destination": DESTINATION,
        "arguments_digest": {
            "algorithm": "sha-256",
            "value": intent_digest,
        },
        "payload_digest": {
            "algorithm": "sha-256",
            "value": payload_digest,
        },
        "resource_version_precondition": message["resource"]["version_id"],
        "policy_epoch": env["registry"].current_epoch(),
        "issued_at": NOW_TEXT,
        "expires_at": EXPIRY_TEXT,
        "nonce": permit_nonce,
        "idempotency_key": message["idempotency_key"],
        "single_use": True,
    }
    if permit_overrides:
        permit_message.update(permit_overrides)
    env["permit_store"][permit_id] = env["permit_signer"].sign(permit_message)
    message["commit_permit_ref"] = permit_id
    return env["worker_signer"].sign(message)


def _read_value(registry):
    with sqlite3.connect(registry.database) as connection:
        row = connection.execute(
            "SELECT value_json,payload_digest,version "
            "FROM paca_resource_values WHERE tenant=? AND task_id=? AND resource_key=?",
            (TENANT, TASK, RESOURCE),
        ).fetchone()
    return row


def _receipts(registry):
    with sqlite3.connect(registry.database) as connection:
        rows = connection.execute(
            "SELECT operation_id,action,resource_key,request_digest,payload_digest,outcome "
            "FROM paca_resource_access_receipts ORDER BY created_at,operation_id"
        ).fetchall()
    return rows


def test_broker_write_verifies_commit_permit_and_commits_atomically(tmp_path):
    env = _environment(tmp_path)
    message = _signed_write(env)
    result = env["mediator"].write(message, session=env["session"])

    assert result["resource"] == RESOURCE
    assert result["action"] == "write_file"
    assert result["version"] == 2
    stored = _read_value(env["registry"])
    assert stored is not None
    assert stored[2] == 2
    assert stored[0] == '{"content":"new protected report"}'
    assert result["payload_digest"] == digest_object(
        {"content": "new protected report"},
        purpose="payload",
    )
    receipts = _receipts(env["registry"])
    assert len(receipts) == 1
    assert receipts[0][0] == "operation-write-2"
    assert receipts[0][1] == "write_file"
    assert receipts[0][2] == RESOURCE
    assert receipts[0][4] == result["payload_digest"]
    assert receipts[0][5] == "committed"
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 2


def test_broker_write_replays_exact_commit_idempotently_without_second_effect(tmp_path):
    env = _environment(tmp_path)
    message = _signed_write(env)
    first = env["mediator"].write(message, session=env["session"])
    assert first["version"] == 2
    assert first["idempotent_replay"] is False

    replay = env["mediator"].write(message, session=env["session"])

    assert replay["version"] == first["version"]
    assert replay["commit_nonce"] == first["commit_nonce"]
    assert replay["idempotent_replay"] is True
    assert _read_value(env["registry"])[2] == 2
    assert len(_receipts(env["registry"])) == 1
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 2


def test_broker_write_recovers_after_committed_response_is_lost(tmp_path, monkeypatch):
    """A lost client response must not create a second local effect on exact retry."""
    env = _environment(tmp_path)
    message = _signed_write(env)
    registry = env["registry"]
    commit = registry.commit_fenced_resource_write

    def commit_then_lose_response(*args, **kwargs):
        commit(*args, **kwargs)
        raise TimeoutError("simulated response loss after durable commit")

    monkeypatch.setattr(
        registry,
        "commit_fenced_resource_write",
        commit_then_lose_response,
    )
    with pytest.raises(TimeoutError, match="response loss"):
        env["mediator"].write(message, session=env["session"])

    # The first attempt already committed. The caller cannot know that from its
    # timeout, so it retries the identical signed operation and idempotency key.
    assert _read_value(registry)[2] == 2
    assert len(_receipts(registry)) == 1
    assert registry.usage(env["grant"].capability.cap_id)[0] == 2

    monkeypatch.setattr(registry, "commit_fenced_resource_write", commit)
    retry = env["mediator"].write(message, session=env["session"])

    assert retry["version"] == 2
    assert retry["idempotent_replay"] is True
    assert _read_value(registry)[2] == 2
    assert len(_receipts(registry)) == 1
    assert registry.usage(env["grant"].capability.cap_id)[0] == 2


def test_broker_write_consumes_replacement_permit_on_safe_idempotent_retry(
    tmp_path,
):
    env = _environment(tmp_path)
    first_message = _signed_write(env)
    first = env["mediator"].write(first_message, session=env["session"])
    replacement_message = _signed_write(
        env,
        permit_id="commit-permit-replacement",
        permit_nonce="commit-permit-nonce-replacement",
    )

    replay = env["mediator"].write(
        replacement_message,
        session=env["session"],
    )

    assert first["version"] == replay["version"] == 2
    assert replay["idempotent_replay"] is True
    assert _read_value(env["registry"])[2] == 2
    assert len(_receipts(env["registry"])) == 1
    with sqlite3.connect(env["registry"].database) as connection:
        commit_rows = connection.execute(
            "SELECT permit_id,idempotency_key,result_version "
            "FROM paca_resource_commit_receipts "
            "ORDER BY committed_at,nonce"
        ).fetchall()
    # The fixture's initial resource seed uses the legacy registry permit
    # path and intentionally has no protocol permit ID or schema-v7 result
    # version. Assert only the two protocol-permit receipts introduced here.
    protocol_rows = [row for row in commit_rows if row[0] is not None]
    assert {row[0] for row in protocol_rows} == {
        "commit-permit-2",
        "commit-permit-replacement",
    }
    assert sum(row[1] == "operation-write-2" for row in protocol_rows) == 1
    assert all(row[2] == 2 for row in protocol_rows)
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 2


def test_broker_write_rejects_permit_payload_or_request_digest_mismatch(tmp_path):
    env = _environment(tmp_path)
    message = _signed_write(
        env,
        permit_overrides={
            "payload_digest": {"algorithm": "sha-256", "value": "c" * 64}
        },
    )

    with pytest.raises(BrokerResourceDenied, match="request/payload digest"):
        env["mediator"].write(message, session=env["session"])

    assert _read_value(env["registry"])[2] == 1
    assert _receipts(env["registry"]) == []
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 1


@pytest.mark.parametrize(
    "permit_overrides",
    [
        {"destination": "different-resource-pep"},
        {"action": "delete"},
        {"single_use": False},
        {"policy_epoch": 99},
        {"resource_version_precondition": "0"},
        {"idempotency_key": "different-idempotency-key"},
        {"tenant_id": "different-tenant"},
        {"task_id": "different-task"},
        {"purpose": "different-purpose"},
        {"subject": {"kind": "agent", "id": "different-agent"}},
        {"subject": {"kind": "administrator", "id": PRINCIPAL}},
        {"arguments_digest": {"algorithm": "sha-512", "value": "d" * 64}},
        {"arguments_digest": {"algorithm": "sha-256", "value": "D" * 64}},
        {"payload_digest": {"algorithm": "sha-512", "value": "e" * 64}},
        {"payload_digest": {"algorithm": "sha-256", "value": "E" * 64}},
        {"created_at": "2026-11-25T10:00:31Z"},
        {"issued_at": "2026-11-25T10:00:31Z"},
        {"created_at": "2026-11-25T09:54:59Z"},
        {"expires_at": "2026-11-25T10:00:31Z"},
        {"issued_at": "2026-11-25T09:59:29Z"},
        {
            "resource": {
                "resource_type": "file",
                "resource_id": RESOURCE,
                "version_id": "1",
                "unexpected": "field",
            }
        },
    ],
)
def test_broker_write_fails_closed_on_permit_binding_or_freshness_mismatch(
    tmp_path,
    permit_overrides,
):
    env = _environment(tmp_path)
    message = _signed_write(env, permit_overrides=permit_overrides)

    with pytest.raises(BrokerResourceDenied):
        env["mediator"].write(message, session=env["session"])

    assert _read_value(env["registry"])[2] == 1
    assert _receipts(env["registry"]) == []
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 1


def test_broker_write_fails_closed_on_worker_or_permit_signature_tampering(tmp_path):
    env = _environment(tmp_path)
    message = _signed_write(env)
    tampered = dict(message)
    tampered["resource"] = dict(message["resource"])
    tampered["resource"]["resource_id"] = "reports/attacker.json"

    with pytest.raises(BrokerResourceDenied, match="verification"):
        env["mediator"].write(tampered, session=env["session"])

    env2 = _environment(tmp_path / "second")
    message2 = _signed_write(env2)
    permit = env2["permit_store"]["commit-permit-2"]
    permit["payload_digest"] = {"algorithm": "sha-256", "value": "f" * 64}
    env2["permit_store"]["commit-permit-2"] = permit

    with pytest.raises(BrokerResourceDenied, match="signature verification"):
        env2["mediator"].write(message2, session=env2["session"])

    assert _read_value(env2["registry"])[2] == 1


def test_broker_write_rejects_stale_resource_version_without_charging_quota(tmp_path):
    env = _environment(tmp_path)
    message = _signed_write(
        env,
        operation_overrides={
            "resource": {
                "resource_type": "file",
                "resource_id": RESOURCE,
                "version_id": "0",
            }
        },
    )

    with pytest.raises(BrokerResourceDenied, match="atomic resource enforcement"):
        env["mediator"].write(message, session=env["session"])

    assert _read_value(env["registry"])[2] == 1
    assert _receipts(env["registry"]) == []
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 1


def test_broker_write_rejects_source_revoked_before_commit(tmp_path):
    env = _environment(tmp_path)
    node_id = env["provenance_node"].node_id
    env["provenance_repository"].revoke_lineage(
        node_id,
        "source revoked before broker write",
    )

    with pytest.raises(
        BrokerResourceDenied,
        match="trusted provenance commit evaluation failed",
    ):
        env["mediator"].write(
            _signed_write(env),
            session=env["session"],
        )

    assert _read_value(env["registry"])[2] == 1
    assert _receipts(env["registry"]) == []
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 1


def test_broker_write_serializes_commit_before_concurrent_lineage_revocation(
    tmp_path,
):
    env = _environment(tmp_path)
    repository = env["provenance_repository"]
    node_id = env["provenance_node"].node_id
    original = env["provenance_check"]
    attempted = threading.Event()
    completed = threading.Event()
    threads = []

    def verify_with_concurrent_revocation(operation, record, refs, repo):
        metadata = original(operation, record, refs, repo)

        def revoke():
            attempted.set()
            repo.revoke_lineage(node_id, "concurrent source revocation")
            completed.set()

        worker = threading.Thread(target=revoke, daemon=True)
        threads.append(worker)
        worker.start()
        assert attempted.wait(timeout=5)
        # The destination registry commit runs while the provenance writer
        # reservation is held, so this revocation must wait behind the commit.
        assert not completed.wait(timeout=0.1)
        return metadata

    env["mediator"]._provenance_commit_check = verify_with_concurrent_revocation
    result = env["mediator"].write(
        _signed_write(env),
        session=env["session"],
    )
    for worker in threads:
        worker.join(timeout=5)
        assert not worker.is_alive()

    assert result["version"] == 2
    assert _read_value(env["registry"])[2] == 2
    assert completed.is_set()
    assert repository.is_revoked(node_id)


def test_broker_write_rechecks_revocation_at_commit_boundary(tmp_path):
    env = _environment(tmp_path)
    original = env["provenance_check"]

    def revoke_before_commit(operation, record, refs, repository):
        result = original(operation, record, refs, repository)
        env["registry"].revoke(record.authority_id, "revoked before resource commit")
        return result

    # The provenance callback is the final trusted pre-commit adapter in this
    # profile; the registry must reject its subsequent commit after revocation.
    env["mediator"]._provenance_commit_check = revoke_before_commit
    message = _signed_write(env)

    with pytest.raises(BrokerResourceDenied, match="atomic resource enforcement"):
        env["mediator"].write(message, session=env["session"])

    assert _read_value(env["registry"])[2] == 1
    assert _receipts(env["registry"]) == []
    assert not env["registry"].is_active(env["grant"].capability.cap_id)


def test_broker_write_rejects_idempotency_key_different_from_operation_id(tmp_path):
    env = _environment(tmp_path)
    message = _signed_write(
        env,
        operation_overrides={"idempotency_key": "different-key"},
    )

    with pytest.raises(BrokerResourceDenied, match="idempotency_key to equal"):
        env["mediator"].write(message, session=env["session"])

    assert _read_value(env["registry"])[2] == 1
    assert _receipts(env["registry"]) == []


def test_broker_write_rejects_expired_commit_permit(tmp_path):
    env = _environment(tmp_path)
    message = _signed_write(
        env,
        permit_overrides={"expires_at": "2026-11-25T09:59:59Z"},
    )

    with pytest.raises(
        BrokerResourceDenied, match="expired or has an invalid lifetime"
    ):
        env["mediator"].write(message, session=env["session"])

    assert _read_value(env["registry"])[2] == 1
