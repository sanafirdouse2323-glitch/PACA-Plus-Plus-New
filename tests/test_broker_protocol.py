from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from paca.contracts import (
    BrokerOperationError,
    BrokerOperationVerifier,
    BrokerSessionContext,
    MessageSigner,
    MessageVerifier,
    TrustedMessageKey,
    digest_object,
    parse_json,
)

MESSAGE_TYPE = "paca.broker-operation.v1"
ISSUER = "worker-issuer"
KEY_ID = "worker-key-01"
AUDIENCE = "paca-broker"
CHANNEL_BINDING = "a" * 64


def _message(operation: str = "write") -> dict[str, object]:
    resource: dict[str, object] = {
        "resource_type": "file",
        "resource_id": "reports/report.txt",
    }
    message: dict[str, object] = {
        "message_id": "message-001",
        "message_type": MESSAGE_TYPE,
        "contract_version": "1.0.0",
        "created_at": "2026-11-25T10:00:00Z",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "operation_id": "operation-001",
        "session_id": "session-001",
        "channel_binding_digest": {
            "algorithm": "sha-256",
            "value": CHANNEL_BINDING,
        },
        "request_nonce": "nonce-0123456789abcdef",
        "operation": operation,
        "resource": resource,
        "authorization_grant_ref": "grant-001",
    }
    if operation in {"read", "query"}:
        message["read_constraints"] = {"max_bytes": 4096}
    if operation in {"write", "delete"}:
        resource["version_id"] = "resource-version-7"
    if operation in {"write", "delete", "send", "execute"}:
        payload = {"content": "approved report"}
        message.update(
            {
                "commit_permit_ref": "permit-001",
                "idempotency_key": "idempotency-001",
                "payload_digest": {
                    "algorithm": "sha-256",
                    "value": digest_object(payload, purpose="payload"),
                },
                "provenance_refs": [
                    {
                        "object_id": "source-001",
                        "version_id": "source-version-1",
                        "content_digest": {
                            "algorithm": "sha-256",
                            "value": "b" * 64,
                        },
                    }
                ],
            }
        )
        if operation != "delete":
            message["payload"] = payload
        else:
            message["payload_digest"] = {
                "algorithm": "sha-256",
                "value": "c" * 64,
            }
    return message


def _verifier_and_session():
    private_key = Ed25519PrivateKey.generate()
    signer = MessageSigner(
        key_id=KEY_ID,
        issuer=ISSUER,
        audiences=frozenset({AUDIENCE}),
        private_key=private_key,
    )
    verifier = MessageVerifier(
        {
            KEY_ID: TrustedMessageKey(
                public_key=private_key.public_key(),
                issuer=ISSUER,
                audiences=frozenset({AUDIENCE}),
                message_types=frozenset({MESSAGE_TYPE}),
            )
        }
    )
    session = BrokerSessionContext(
        session_id="session-001",
        issuer=ISSUER,
        key_id=KEY_ID,
        audience=AUDIENCE,
        channel_binding_digest=CHANNEL_BINDING,
        principal_id="agent-001",
        workload_id="worker-001",
        tenant_id="tenant-001",
        task_id="task-001",
        purpose="report-generation",
    )
    return signer, verifier, session


def test_verifier_accepts_signed_operation_bound_to_authenticated_session():
    message = _message("write")
    signer, verifier, session = _verifier_and_session()
    signed = signer.sign(message)

    verified = BrokerOperationVerifier(verifier).verify(
        signed,
        session=session,
        expected_grant_ref="grant-001",
    )

    intent = dict(signed)
    intent.pop("proof")
    intent.pop("commit_permit_ref")
    assert verified.operation_id == "operation-001"
    assert verified.operation == "write"
    assert verified.session_id == session.session_id
    assert verified.principal_id == session.principal_id
    assert verified.tenant_id == session.tenant_id
    assert verified.authorization_grant_ref == "grant-001"
    assert verified.intent_digest == digest_object(intent, purpose="request")
    assert verified.commit_permit_ref == "permit-001"
    expected_nonce_digest = hashlib.sha256(
        b"PACA++/BROKER-NONCE/V1\n"
        + session.session_id.encode("utf-8")
        + b"\n"
        + message["request_nonce"].encode("utf-8")
    ).hexdigest()
    assert verified.nonce_digest == expected_nonce_digest
    assert verified.payload_digest == digest_object(
        message["payload"], purpose="payload"
    )
    assert verified.registry_access_receipt() == {
        "session_id": session.session_id,
        "nonce_digest": expected_nonce_digest,
        "operation_id": "operation-001",
        "request_digest": verified.intent_digest,
        "payload_digest": verified.payload_digest,
    }


def test_verifier_accepts_bounded_read_without_commit_permit():
    message = _message("read")
    signer, verifier, session = _verifier_and_session()
    signed = signer.sign(message)

    verified = BrokerOperationVerifier(verifier).verify(
        signed,
        session=session,
        expected_grant_ref="grant-001",
    )

    assert verified.operation == "read"
    assert verified.commit_permit_ref is None
    assert verified.max_bytes == 4096
    assert verified.registry_access_receipt() == {
        "session_id": session.session_id,
        "nonce_digest": verified.nonce_digest,
        "operation_id": "operation-001",
        "request_digest": verified.intent_digest,
    }


def test_verifier_rejects_invalid_signature_before_trusting_request():
    message = _message("write")
    signer, verifier, session = _verifier_and_session()
    signed = signer.sign(message)
    signed["resource"]["resource_id"] = "reports/attacker.txt"

    with pytest.raises(BrokerOperationError, match="signature"):
        BrokerOperationVerifier(verifier).verify(
            signed,
            session=session,
            expected_grant_ref="grant-001",
        )


def test_verifier_rejects_session_id_mismatch():
    message = _message("read")
    signer, verifier, session = _verifier_and_session()
    signed = signer.sign(message)
    wrong_session = BrokerSessionContext(
        session_id="different-session",
        issuer=session.issuer,
        key_id=session.key_id,
        audience=session.audience,
        channel_binding_digest=session.channel_binding_digest,
        principal_id=session.principal_id,
        workload_id=session.workload_id,
        tenant_id=session.tenant_id,
        task_id=session.task_id,
        purpose=session.purpose,
    )

    with pytest.raises(BrokerOperationError, match="session"):
        BrokerOperationVerifier(verifier).verify(
            signed,
            session=wrong_session,
            expected_grant_ref="grant-001",
        )


def test_verifier_rejects_channel_binding_mismatch():
    message = _message("read")
    signer, verifier, session = _verifier_and_session()
    signed = signer.sign(message)
    wrong_channel = BrokerSessionContext(
        session_id=session.session_id,
        issuer=session.issuer,
        key_id=session.key_id,
        audience=session.audience,
        channel_binding_digest="d" * 64,
        principal_id=session.principal_id,
        workload_id=session.workload_id,
        tenant_id=session.tenant_id,
        task_id=session.task_id,
        purpose=session.purpose,
    )

    with pytest.raises(BrokerOperationError, match="channel binding"):
        BrokerOperationVerifier(verifier).verify(
            signed,
            session=wrong_channel,
            expected_grant_ref="grant-001",
        )


def test_verifier_rejects_wrong_grant_reference():
    message = _message("read")
    signer, verifier, session = _verifier_and_session()
    signed = signer.sign(message)

    with pytest.raises(BrokerOperationError, match="grant"):
        BrokerOperationVerifier(verifier).verify(
            signed,
            session=session,
            expected_grant_ref="different-grant",
        )


def test_verifier_recomputes_payload_digest_instead_of_trusting_claim():
    message = _message("write")
    message["payload_digest"] = {"algorithm": "sha-256", "value": "e" * 64}
    signer, verifier, session = _verifier_and_session()
    signed = signer.sign(message)

    with pytest.raises(BrokerOperationError, match="payload digest"):
        BrokerOperationVerifier(verifier).verify(
            signed,
            session=session,
            expected_grant_ref="grant-001",
        )


def test_commit_permit_reference_is_signature_bound_but_not_in_intent_digest():
    message = _message("write")
    signer, verifier, session = _verifier_and_session()
    signed = signer.sign(message)
    broker_verifier = BrokerOperationVerifier(verifier)
    first = broker_verifier.verify(
        signed,
        session=session,
        expected_grant_ref="grant-001",
    )

    tampered = dict(signed)
    tampered["commit_permit_ref"] = "substituted-permit"
    with pytest.raises(BrokerOperationError, match="signature"):
        broker_verifier.verify(
            tampered,
            session=session,
            expected_grant_ref="grant-001",
        )

    reissued = dict(message)
    reissued["commit_permit_ref"] = "different-valid-permit"
    second = broker_verifier.verify(
        signer.sign(reissued),
        session=session,
        expected_grant_ref="grant-001",
    )
    assert first.intent_digest == second.intent_digest


def test_verifier_rejects_valid_but_session_unbound_signing_key():
    message = _message("read")
    private_key = Ed25519PrivateKey.generate()
    signer = MessageSigner(
        key_id="other-key",
        issuer=ISSUER,
        audiences=frozenset({AUDIENCE}),
        private_key=private_key,
    )
    _, _, session = _verifier_and_session()
    verifier = MessageVerifier(
        {
            "other-key": TrustedMessageKey(
                public_key=private_key.public_key(),
                issuer=ISSUER,
                audiences=frozenset({AUDIENCE}),
                message_types=frozenset({MESSAGE_TYPE}),
            )
        }
    )
    signed = signer.sign(message)

    with pytest.raises(BrokerOperationError, match="key"):
        BrokerOperationVerifier(verifier).verify(
            signed,
            session=session,
            expected_grant_ref="grant-001",
        )

def test_verified_result_is_detached_from_later_caller_mutation():
    message = _message("write")
    signer, verifier, session = _verifier_and_session()
    signed = signer.sign(message)
    verified = BrokerOperationVerifier(verifier).verify(
        signed,
        session=session,
        expected_grant_ref="grant-001",
    )

    signed["resource"]["resource_id"] = "attacker/changed-after-verification"
    assert verified.resource_id == "reports/report.txt"
    snapshot = parse_json(verified.canonical_message)
    assert snapshot["resource"]["resource_id"] == "reports/report.txt"

