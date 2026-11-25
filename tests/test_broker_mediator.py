from __future__ import annotations

import hashlib
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from paca.authority import AuthorityLineage
from paca.authority_runtime import HMACCapabilityAuthority, SQLiteAuthorityRegistry
from paca.broker import BrokerResourceDenied, InProcessBrokerReadMediator
from paca.contracts import (
    BrokerOperationVerifier,
    BrokerSessionContext,
    MessageSigner,
    MessageVerifier,
    TrustedMessageKey,
)
from paca.memory import canonical_value_bytes

BROKER_ISSUER = "worker-issuer"
BROKER_KEY_ID = "worker-key-1"
BROKER_AUDIENCE = "paca-broker"
GRANT_ISSUER = "capability-issuer"
GRANT_AUDIENCE = "paca-resource-broker"
CHANNEL_BINDING = "a" * 64
TENANT = "tenant-1"
TASK = "task-1"
PRINCIPAL = "agent-1"
PURPOSE = "report-generation"
RESOURCE = "reports/report.json"


def _environment(tmp_path, *, provenance_release_check=None, max_calls=5):
    now = [1_000]

    def clock():
        return now[0]

    registry = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3", clock=clock)
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
        clock=clock,
    )
    signed_grant = authority.issue(
        principal=PRINCIPAL,
        tenant=TENANT,
        task_id=TASK,
        purpose=PURPOSE,
        grants={
            "read_file": ("reports/*",),
            "write_file": ("reports/*",),
        },
        expires_at=2_000,
        max_calls=max_calls,
        max_task_calls=20,
    )

    payload = {"content": "brokered secret"}
    payload_digest = hashlib.sha256(canonical_value_bytes(payload)).hexdigest()
    permit = authority.verify_resource_commit_permit(
        authority.issue_resource_commit_permit(
            signed_grant.token,
            request_digest="b" * 64,
            action="write_file",
            resource=RESOURCE,
            payload_digest=payload_digest,
        )
    )
    provenance = {
        "classification": "internal",
        "source": "trusted-fixture",
    }
    registry.commit_fenced_resource_write(
        permit,
        payload,
        provenance_metadata=provenance,
    )

    worker_private_key = Ed25519PrivateKey.generate()
    signer = MessageSigner(
        key_id=BROKER_KEY_ID,
        issuer=BROKER_ISSUER,
        audiences=frozenset({BROKER_AUDIENCE}),
        private_key=worker_private_key,
    )
    message_verifier = MessageVerifier(
        {
            BROKER_KEY_ID: TrustedMessageKey(
                public_key=worker_private_key.public_key(),
                issuer=BROKER_ISSUER,
                audiences=frozenset({BROKER_AUDIENCE}),
                message_types=frozenset({"paca.broker-operation.v1"}),
            )
        }
    )
    session = BrokerSessionContext(
        session_id="session-1",
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
    verifier = BrokerOperationVerifier(message_verifier)
    release_check = provenance_release_check or (
        lambda operation, record, result: (
            record.authority_id == signed_grant.capability.cap_id
            and result["provenance_metadata"] == provenance
        )
    )
    mediator = InProcessBrokerReadMediator(
        verifier,
        registry,
        grant_issuer=GRANT_ISSUER,
        grant_audience=GRANT_AUDIENCE,
        provenance_release_check=release_check,
    )
    return {
        "registry": registry,
        "authority": authority,
        "grant": signed_grant,
        "signer": signer,
        "session": session,
        "mediator": mediator,
        "provenance": provenance,
    }


def _read_message(env, *, max_bytes=4096, operation="read"):
    message = {
        "message_id": "message-1",
        "message_type": "paca.broker-operation.v1",
        "contract_version": "1.0.0",
        "created_at": "2026-11-25T10:00:00Z",
        "issuer": BROKER_ISSUER,
        "audience": BROKER_AUDIENCE,
        "operation_id": "operation-1",
        "session_id": env["session"].session_id,
        "channel_binding_digest": {
            "algorithm": "sha-256",
            "value": CHANNEL_BINDING,
        },
        "request_nonce": "request-nonce-0001",
        "operation": operation,
        "resource": {
            "resource_type": "file",
            "resource_id": RESOURCE,
        },
        "authorization_grant_ref": env["grant"].capability.cap_id,
        "read_constraints": {"max_bytes": max_bytes},
    }
    return env["signer"].sign(message)


def _access_receipts(registry):
    with sqlite3.connect(registry.database) as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM paca_resource_access_receipts"
        ).fetchone()[0]


def test_broker_mediates_signed_read_with_current_grant_and_release_check(tmp_path):
    env = _environment(tmp_path)
    result = env["mediator"].read(
        _read_message(env),
        session=env["session"],
    )

    assert result["found"] is True
    assert result["resource"] == RESOURCE
    assert result["value"] == {"content": "brokered secret"}
    assert result["provenance_metadata"] == env["provenance"]
    assert _access_receipts(env["registry"]) == 1


def test_broker_consumes_replay_receipt_before_returning_read_result(tmp_path):
    env = _environment(tmp_path)
    message = _read_message(env)
    first = env["mediator"].read(message, session=env["session"])
    assert first["found"] is True

    with pytest.raises(BrokerResourceDenied, match="authority enforcement"):
        env["mediator"].read(message, session=env["session"])

    assert _access_receipts(env["registry"]) == 1
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 2


def test_broker_rejects_principal_mismatch_before_resource_access(tmp_path):
    env = _environment(tmp_path)
    session = BrokerSessionContext(
        session_id=env["session"].session_id,
        issuer=env["session"].issuer,
        key_id=env["session"].key_id,
        audience=env["session"].audience,
        channel_binding_digest=env["session"].channel_binding_digest,
        principal_id="different-agent",
        workload_id=env["session"].workload_id,
        tenant_id=TENANT,
        task_id=TASK,
        purpose=PURPOSE,
    )

    with pytest.raises(
        BrokerResourceDenied,
        match="verification or authority enforcement",
    ):
        env["mediator"].read(_read_message(env), session=session)

    assert _access_receipts(env["registry"]) == 0
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 1


def test_broker_rejects_legacy_grant_without_persisted_call_limit(tmp_path):
    env = _environment(tmp_path)
    legacy = AuthorityLineage.create(
        authority_id="legacy-grant",
        issuer=GRANT_ISSUER,
        principal=PRINCIPAL,
        tenant=TENANT,
        task_id=TASK,
        purpose=PURPOSE,
        policy_epoch=env["registry"].current_epoch(),
        expires=2_000,
        grants={"read_file": ("reports/*",)},
        max_task_calls=20,
        audience=GRANT_AUDIENCE,
    )
    env["registry"].register_authority(legacy)

    message = _read_message(env)
    message_unsigned = dict(message)
    message_unsigned.pop("proof")
    message_unsigned["authorization_grant_ref"] = "legacy-grant"
    # Re-sign the changed grant reference; all other session-bound facts remain
    # unchanged and the registry can resolve the legacy authority.
    signed_legacy = env["signer"].sign(message_unsigned)

    with pytest.raises(BrokerResourceDenied, match="legacy grant"):
        env["mediator"].read(signed_legacy, session=env["session"])

    assert _access_receipts(env["registry"]) == 0


def test_broker_rejects_untrusted_grant_audience(tmp_path):
    env = _environment(tmp_path)
    mediator = InProcessBrokerReadMediator(
        env["mediator"]._verifier,
        env["registry"],
        grant_issuer=GRANT_ISSUER,
        grant_audience="different-audience",
        provenance_release_check=lambda operation, record, result: True,
    )
    with pytest.raises(BrokerResourceDenied, match="trusted issuer"):
        mediator.read(_read_message(env), session=env["session"])

    assert _access_receipts(env["registry"]) == 0


def test_broker_denies_read_when_provenance_release_check_fails(tmp_path):
    env = _environment(tmp_path, provenance_release_check=lambda *_: False)

    with pytest.raises(BrokerResourceDenied, match="provenance or disclosure"):
        env["mediator"].read(_read_message(env), session=env["session"])

    # A denied release still consumes the read receipt and budget. It must not
    # be possible to replay the same signed request after a policy denial.
    assert _access_receipts(env["registry"]) == 1
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 2


def test_broker_rejects_unsupported_operations_and_version_selectors(tmp_path):
    env = _environment(tmp_path)
    with pytest.raises(BrokerResourceDenied, match="read operations only"):
        env["mediator"].read(
            _read_message(env, operation="query"),
            session=env["session"],
        )

    message = _read_message(env)
    unsigned = dict(message)
    unsigned.pop("proof")
    unsigned["read_constraints"] = {
        "max_bytes": 4096,
        "expected_version": "v1",
    }
    signed = env["signer"].sign(unsigned)
    with pytest.raises(BrokerResourceDenied, match="version"):
        env["mediator"].read(signed, session=env["session"])

    assert _access_receipts(env["registry"]) == 0


def test_broker_enforces_actual_response_size_without_charging_on_failure(tmp_path):
    env = _environment(tmp_path)
    # The requested cap is structurally valid but too small for the complete
    # returned object (including resource metadata and provenance).
    with pytest.raises(BrokerResourceDenied, match="authority enforcement"):
        env["mediator"].read(
            _read_message(env, max_bytes=1),
            session=env["session"],
        )

    assert _access_receipts(env["registry"]) == 0
    assert env["registry"].usage(env["grant"].capability.cap_id)[0] == 1
