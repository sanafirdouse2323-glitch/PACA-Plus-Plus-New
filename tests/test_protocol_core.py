from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from paca.contracts import (
    CanonicalizationError,
    ContractValidationError,
    InvalidJSONError,
    canonicalize,
    digest_object,
    parse_json,
    validate_message,
)


def test_jcs_sorts_object_members_recursively() -> None:
    value = {"z": 3, "a": {"d": 4, "b": 2}}
    assert canonicalize(value) == b'{"a":{"b":2,"d":4},"z":3}'


def test_jcs_uses_ecmascript_number_serialization() -> None:
    value = {"value": 333333333.33333329}
    assert canonicalize(value) == b'{"value":333333333.3333333}'


def test_jcs_preserves_unicode_without_normalization() -> None:
    composed = "\u00e9"
    decomposed = "e\u0301"
    assert canonicalize({"v": composed}) != canonicalize({"v": decomposed})


def test_duplicate_object_keys_are_rejected_after_json_unescaping() -> None:
    with pytest.raises(InvalidJSONError, match="duplicate JSON object member"):
        parse_json('{"role":"user","ro\\u006ce":"admin"}')


def test_non_json_constants_and_non_finite_numbers_are_rejected() -> None:
    with pytest.raises(InvalidJSONError):
        parse_json('{"number":NaN}')
    with pytest.raises(CanonicalizationError):
        canonicalize({"number": float("inf")})


def test_unsafe_exact_integer_values_are_rejected() -> None:
    with pytest.raises(InvalidJSONError):
        parse_json('{"counter":9007199254740992}')
    with pytest.raises(CanonicalizationError):
        canonicalize({"counter": 9007199254740992})


def test_unpaired_unicode_surrogates_are_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({"bad": chr(0xD800)})


def test_digest_is_domain_separated_by_purpose() -> None:
    value = {"a": 1}
    request = digest_object(value, purpose="request")
    payload = digest_object(value, purpose="payload")
    expected = hashlib.sha256(
        b"PACA++/DIGEST/V1\nrequest\n" + canonicalize(value)
    ).hexdigest()
    assert request == expected
    assert request != payload


def test_digest_purpose_is_a_fixed_ascii_protocol_token() -> None:
    with pytest.raises(ValueError):
        digest_object({"a": 1}, purpose="../request")


def test_validator_accepts_valid_identity_context_message() -> None:
    message = {
        "message_id": "msg-valid",
        "message_type": "paca.identity-context.v1",
        "contract_version": "1.0.0",
        "created_at": "2026-11-24T12:00:00Z",
        "issuer": "identity-authority",
        "audience": "paca-core",
        "proof": {
            "key_id": "key-1",
            "algorithm": "Ed25519",
            "signature": "A" * 86,
        },
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
    validate_message(message)


def test_validator_rejects_unknown_fields() -> None:
    message = {
        "message_id": "msg-001",
        "message_type": "paca.identity-context.v1",
        "contract_version": "1.0.0",
        "created_at": "2026-11-24T12:00:00Z",
        "issuer": "identity-authority",
        "audience": "paca-core",
        "proof": {
            "key_id": "key-1",
            "algorithm": "Ed25519",
            "signature": "A" * 86,
        },
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
        "administrator": True,
    }
    with pytest.raises(ContractValidationError):
        validate_message(message)


def test_packaged_schema_matches_source_contract_schema() -> None:
    source_schema = (
        Path(__file__).resolve().parents[1]
        / "contracts"
        / "v1.0.0"
        / "paca-contracts.schema.json"
    )
    packaged_schema = (
        Path(__file__).resolve().parents[1]
        / "paca"
        / "contracts"
        / "schemas"
        / "v1.0.0"
        / "paca-contracts.schema.json"
    )
    assert json.loads(source_schema.read_text(encoding="utf-8")) == json.loads(
        packaged_schema.read_text(encoding="utf-8")
    )


def _base_message() -> dict[str, object]:
    return {
        "message_id": "signed-message-1",
        "message_type": "paca.identity-context.v1",
        "contract_version": "1.0.0",
        "created_at": "2026-11-24T12:00:00Z",
        "issuer": "identity-authority",
        "audience": "paca-core",
        "subject": {"kind": "agent", "id": "agent-1"},
    }


def test_ed25519_message_signature_verifies_with_scoped_key() -> None:
    from paca.contracts import MessageSigner, MessageVerifier, TrustedMessageKey

    private_key = Ed25519PrivateKey.generate()
    signer = MessageSigner(
        key_id="identity-key-1",
        issuer="identity-authority",
        audiences=frozenset({"paca-core"}),
        private_key=private_key,
    )
    signed = signer.sign(_base_message())
    verifier = MessageVerifier(
        {
            "identity-key-1": TrustedMessageKey(
                public_key=private_key.public_key(),
                issuer="identity-authority",
                audiences=frozenset({"paca-core"}),
                message_types=frozenset({"paca.identity-context.v1"}),
            )
        }
    )
    verified = verifier.verify(signed)
    assert verified.key_id == "identity-key-1"
    assert verified.issuer == "identity-authority"
    assert verified.audience == "paca-core"


def test_ed25519_message_signature_detects_payload_tampering() -> None:
    from paca.contracts import (
        MessageAuthenticationError,
        MessageSigner,
        MessageVerifier,
        TrustedMessageKey,
    )

    private_key = Ed25519PrivateKey.generate()
    signed = MessageSigner(
        key_id="key-1",
        issuer="identity-authority",
        audiences=frozenset({"paca-core"}),
        private_key=private_key,
    ).sign(_base_message())
    signed["subject"] = {"kind": "agent", "id": "attacker"}
    verifier = MessageVerifier(
        {
            "key-1": TrustedMessageKey(
                public_key=private_key.public_key(),
                issuer="identity-authority",
                audiences=frozenset({"paca-core"}),
                message_types=frozenset({"paca.identity-context.v1"}),
            )
        }
    )
    with pytest.raises(MessageAuthenticationError):
        verifier.verify(signed)


def test_ed25519_message_key_is_scoped_to_issuer_audience_and_type() -> None:
    from paca.contracts import (
        MessageAuthenticationError,
        MessageSigner,
        MessageVerifier,
        TrustedMessageKey,
    )

    private_key = Ed25519PrivateKey.generate()
    signed = MessageSigner(
        key_id="key-1",
        issuer="identity-authority",
        audiences=frozenset({"paca-core"}),
        private_key=private_key,
    ).sign(_base_message())
    verifier = MessageVerifier(
        {
            "key-1": TrustedMessageKey(
                public_key=private_key.public_key(),
                issuer="another-issuer",
                audiences=frozenset({"paca-core"}),
                message_types=frozenset({"paca.identity-context.v1"}),
            )
        }
    )
    with pytest.raises(MessageAuthenticationError):
        verifier.verify(signed)


def test_message_signer_rejects_preexisting_proof_and_wrong_audience() -> None:
    from paca.contracts import MessageSigner

    private_key = Ed25519PrivateKey.generate()
    signer = MessageSigner(
        key_id="key-1",
        issuer="identity-authority",
        audiences=frozenset({"paca-core"}),
        private_key=private_key,
    )
    signed = signer.sign(_base_message())
    with pytest.raises(ValueError):
        signer.sign(signed)
    wrong_audience = _base_message()
    wrong_audience["audience"] = "other-service"
    with pytest.raises(ValueError):
        signer.sign(wrong_audience)


def test_source_schema_itself_is_valid() -> None:
    source_schema = (
        Path(__file__).resolve().parents[1]
        / "contracts"
        / "v1.0.0"
        / "paca-contracts.schema.json"
    )
    Draft202012Validator.check_schema(
        json.loads(source_schema.read_text(encoding="utf-8"))
    )
