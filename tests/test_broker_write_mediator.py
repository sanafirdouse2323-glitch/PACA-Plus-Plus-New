from __future__ import annotations

import hashlib
import sqlite3

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
from paca.memory import canonical_value_bytes

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

    def verify_provenance(operation, record, refs):
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
        return {
            "classification": "internal",
            "source_refs": ["report-source@source-v1"],
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
        provenance_commit_check=verify_provenance,
        clock=lambda: TEST_NOW,
    )
    return {
        "registry": registry,
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


def _signed_write(env, *, permit_overrides=None, operation_overrides=None):
    message = _unsigned_write_message(env)
    if operation_overrides:
        message.update(operation_overrides)
    intent_digest = digest_object(message, purpose="request")
    payload_digest = message["payload_digest"]["value"]
    permit_id = "commit-permit-2"
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
        "nonce": "commit-permit-nonce-0002",
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
    ],
)
def test_broker_write_fails_closed_on_permit_binding_mismatch(
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
    message = _signed_write(env, operation_overrides={"resource": {
        "resource_type": "file",
        "resource_id": RESOURCE,
        "version_id": "0",
    }})

    with pytest.raises(BrokerResourceDenied, match="atomic resource enforcement"):
        env["mediator"].write(message, session=env["session"])

    assert _read_value(env["registry"])[2] == 1
    assert _receipts(env["registry"]) == []
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 1


def test_broker_write_rechecks_revocation_at_commit_boundary(tmp_path):
    env = _environment(tmp_path)
    original = env["provenance_check"]

    def revoke_before_commit(operation, record, refs):
        result = original(operation, record, refs)
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

    with pytest.raises(BrokerResourceDenied, match="validity window"):
        env["mediator"].write(message, session=env["session"])

    assert _read_value(env["registry"])[2] == 1
