from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "v1.0.0"
    / "paca-contracts.schema.json"
)
PACKAGED_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "paca"
    / "contracts"
    / "schemas"
    / "v1.0.0"
    / "paca-contracts.schema.json"
)


def test_packaged_schema_matches_versioned_contract():
    assert PACKAGED_SCHEMA_PATH.read_bytes() == SCHEMA_PATH.read_bytes()


@pytest.fixture(scope="module")
def validator():
    jsonschema = importlib.import_module("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    importlib.import_module("jsonschema").Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )


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


def test_schema_exposes_exact_versioned_message_type_set():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    actual = {
        schema["$defs"][reference["$ref"].rsplit("/", 1)[-1]]["properties"][
            "message_type"
        ]["const"]
        for reference in schema["oneOf"]
    }
    expected = {
        "paca.identity-context.v1",
        "paca.provenance-evidence.v1",
        "paca.policy-evaluation.request.v1",
        "paca.policy-evaluation.response.v1",
        "paca.authorization-grant.v1",
        "paca.pep-invocation.v1",
        "paca.commit-permit.v1",
        "paca.broker-operation.v1",
        "paca.isolation-profile.v1",
        "paca.audit-event.v1",
    }
    assert actual == expected


def test_schema_is_valid_and_accepts_identity_context(
    validator: Any,
) -> None:
    validator.validate(valid_identity_context())


def test_unknown_security_fields_are_rejected(
    validator: Any,
) -> None:
    message = valid_identity_context()
    message["is_admin"] = True
    with pytest.raises(importlib.import_module("jsonschema").ValidationError):
        validator.validate(message)


def test_broker_write_requires_commit_permit_and_idempotency(
    validator: Any,
) -> None:
    message = envelope("paca.broker-operation.v1")
    message.update(
        {
            "operation_id": "op-1",
            "session_id": "session-1",
            "channel_binding_digest": {"algorithm": "sha-256", "value": "a" * 64},
            "request_nonce": "nonce-000000000001",
            "operation": "write",
            "resource": {
                "resource_type": "file",
                "resource_id": "report-1",
                "version_id": "version-1",
            },
            "authorization_grant_ref": "grant-1",
            "payload": {"text": "approved content"},
            "payload_digest": {"algorithm": "sha-256", "value": "b" * 64},
            "provenance_refs": [
                {
                    "object_id": "source-1",
                    "version_id": "source-version-1",
                    "content_digest": {"algorithm": "sha-256", "value": "c" * 64},
                }
            ],
        }
    )
    with pytest.raises(importlib.import_module("jsonschema").ValidationError):
        validator.validate(message)
    message["commit_permit_ref"] = "permit-1"
    message["idempotency_key"] = "idem-1"
    validator.validate(message)


def test_broker_read_requires_authorisation_before_disclosure(
    validator: Any,
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
            "read_constraints": {"max_bytes": 4096},
        }
    )
    with pytest.raises(importlib.import_module("jsonschema").ValidationError):
        validator.validate(message)
    message["authorization_grant_ref"] = "grant-1"
    validator.validate(message)


def _valid_broker_operation(operation: str) -> dict[str, object]:
    message = envelope("paca.broker-operation.v1")
    resource: dict[str, object] = {
        "resource_type": "file",
        "resource_id": "report-1",
    }
    message.update(
        {
            "operation_id": "op-" + operation,
            "session_id": "session-1",
            "channel_binding_digest": {
                "algorithm": "sha-256",
                "value": "a" * 64,
            },
            "request_nonce": "nonce-000000000001",
            "operation": operation,
            "resource": resource,
            "authorization_grant_ref": "grant-1",
        }
    )
    if operation in {"read", "query"}:
        message["read_constraints"] = {"max_bytes": 4096}
    if operation in {"write", "delete"}:
        resource["version_id"] = "version-1"
    if operation in {"write", "delete", "send", "execute"}:
        message.update(
            {
                "commit_permit_ref": "permit-1",
                "idempotency_key": "idem-1",
                "payload_digest": {
                    "algorithm": "sha-256",
                    "value": "b" * 64,
                },
                "provenance_refs": [
                    {
                        "object_id": "source-1",
                        "version_id": "source-version-1",
                        "content_digest": {
                            "algorithm": "sha-256",
                            "value": "c" * 64,
                        },
                    }
                ],
            }
        )
    if operation in {"write", "send", "execute"}:
        message["payload"] = {"content": "approved"}
    return message


def test_broker_mutations_require_permit_replay_binding_and_provenance(
    validator: Any,
) -> None:
    validation_error = importlib.import_module("jsonschema").ValidationError
    for operation in ("write", "delete", "send", "execute"):
        message = _valid_broker_operation(operation)
        validator.validate(message)

        for required_field in (
            "commit_permit_ref",
            "idempotency_key",
            "payload_digest",
            "provenance_refs",
        ):
            incomplete = dict(message)
            incomplete.pop(required_field)
            with pytest.raises(validation_error):
                validator.validate(incomplete)

        no_provenance = dict(message)
        no_provenance["provenance_refs"] = []
        with pytest.raises(validation_error):
            validator.validate(no_provenance)

        if operation in {"write", "send", "execute"}:
            no_payload = dict(message)
            no_payload.pop("payload")
            with pytest.raises(validation_error):
                validator.validate(no_payload)

        if operation == "delete":
            no_version = dict(message)
            no_version["resource"] = {
                "resource_type": "file",
                "resource_id": "report-1",
            }
            with pytest.raises(validation_error):
                validator.validate(no_version)


def test_broker_reads_and_queries_require_bounded_authorised_disclosure(
    validator: Any,
) -> None:
    validation_error = importlib.import_module("jsonschema").ValidationError
    for operation in ("read", "query"):
        message = _valid_broker_operation(operation)
        validator.validate(message)

        no_constraints = dict(message)
        no_constraints.pop("read_constraints")
        with pytest.raises(validation_error):
            validator.validate(no_constraints)

        no_bound = dict(message)
        no_bound["read_constraints"] = {}
        with pytest.raises(validation_error):
            validator.validate(no_bound)

        unbounded = dict(message)
        unbounded["read_constraints"] = {"max_bytes": 0}
        with pytest.raises(validation_error):
            validator.validate(unbounded)

        with_commit_permit = dict(message)
        with_commit_permit["commit_permit_ref"] = "permit-read-forbidden"
        with pytest.raises(validation_error):
            validator.validate(with_commit_permit)


def test_digest_must_be_lowercase_sha256_hex(
    validator: Any,
) -> None:
    message = valid_identity_context()
    message["authentication"]["credential_digest"]["value"] = "A" * 64
    with pytest.raises(importlib.import_module("jsonschema").ValidationError):
        validator.validate(message)


def test_protocol_identifiers_accept_url_safe_authority_references(
    validator: Any,
) -> None:
    for grant_ref in ("_capability_abC_123", "-capability-abC_123"):
        message = _valid_broker_operation("read")
        message["authorization_grant_ref"] = grant_ref
        validator.validate(message)
