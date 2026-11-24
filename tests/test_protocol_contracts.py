from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "v1.0.0"
    / "paca-contracts.schema.json"
)


@pytest.fixture(scope="module")
def validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())


def envelope(message_type: str) -> dict[str, object]:
    return {
        "message_id": "msg-001",
        "message_type": message_type,
        "contract_version": "1.0.0",
        "created_at": "2026-11-24T12:00:00Z",
        "issuer": "paca-authority",
        "audience": "paca-broker",
        "proof": {
            "key_id": "key-01",
            "algorithm": "Ed25519",
            "signature": "A" * 86,
        },
    }


def valid_identity_context() -> dict[str, object]:
    message = envelope("paca.identity-context.v1")
    message.update(
        {
            "subject": {"kind": "agent", "id": "agent-1"},
            "workload": {"kind": "workload", "id": "worker-1"},
            "tenant_id": "tenant-1",
            "task_id": "task-1",
            "purpose": "report-generation",
            "session_id": "session-1",
            "authentication": {
                "method": "workload_identity",
                "issuer": "https://identity.example.test/",
                "subject_id": "agent-1",
                "credential_digest": {"algorithm": "sha-256", "value": "a" * 64},
                "authenticated_at": "2026-11-24T12:00:00Z",
                "expires_at": "2026-11-24T12:05:00Z",
            },
        }
    )
    return message


def test_schema_is_valid_and_accepts_identity_context(
    validator: jsonschema.Draft202012Validator,
) -> None:
    validator.validate(valid_identity_context())


def test_unknown_security_fields_are_rejected(
    validator: jsonschema.Draft202012Validator,
) -> None:
    message = valid_identity_context()
    message["is_admin"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(message)


def test_broker_write_requires_commit_permit_and_idempotency(
    validator: jsonschema.Draft202012Validator,
) -> None:
    message = envelope("paca.broker-operation.v1")
    message.update(
        {
            "operation_id": "op-1",
            "session_id": "session-1",
            "channel_binding_digest": {"algorithm": "sha-256", "value": "a" * 64},
            "request_nonce": "nonce-000000000001",
            "operation": "write",
            "resource": {"resource_type": "file", "resource_id": "report-1"},
            "authorization_grant_ref": "grant-1",
            "payload": {"text": "approved content"},
            "payload_digest": {"algorithm": "sha-256", "value": "b" * 64},
        }
    )
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(message)
    message["commit_permit_ref"] = "permit-1"
    message["idempotency_key"] = "idem-1"
    validator.validate(message)


def test_broker_read_requires_authorisation_before_disclosure(
    validator: jsonschema.Draft202012Validator,
) -> None:
    message = envelope("paca.broker-operation.v1")
    message.update(
        {
            "operation_id": "op-read-1",
            "session_id": "session-1",
            "channel_binding_digest": {"algorithm": "sha-256", "value": "a" * 64},
            "request_nonce": "nonce-000000000002",
            "operation": "read",
            "resource": {"resource_type": "document", "resource_id": "doc-1"},
        }
    )
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(message)
    message["authorization_grant_ref"] = "grant-1"
    validator.validate(message)


def test_digest_must_be_lowercase_sha256_hex(
    validator: jsonschema.Draft202012Validator,
) -> None:
    message = valid_identity_context()
    message["authentication"]["credential_digest"]["value"] = "A" * 64
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(message)
