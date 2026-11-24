from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from paca.authority_runtime import (
    CapabilityAuthenticationError,
    Ed25519CapabilityAuthority,
    HMACCapabilityAuthority,
    SQLiteAuthorityRegistry,
)


def _keypair():
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def _callbacks():
    return {
        "identity_verifier": lambda principal, tenant: bool(
            principal and tenant == "acme"
        ),
        "task_context_verifier": lambda principal, tenant, task_id, purpose: (
            bool(principal)
            and tenant == "acme"
            and task_id == "task-ed25519"
            and purpose == "signing-test"
        ),
        "clock": lambda: 1_000,
    }


def _ed_issuer(
    registry, private_key, public_key, *, key_id="ed-key-1", audience="paca-test"
):
    return Ed25519CapabilityAuthority(
        registry,
        issuer_id="ed-issuer",
        key_id=key_id,
        audience=audience,
        private_key=private_key,
        public_key=public_key,
        **_callbacks(),
    )


def _ed_verifier(registry, public_key, *, key_id="ed-key-1", audience="paca-test"):
    return Ed25519CapabilityAuthority(
        registry,
        issuer_id="ed-issuer",
        key_id=key_id,
        audience=audience,
        public_key=public_key,
        **_callbacks(),
    )


def _capability(issuer):
    return issuer.issue(
        principal="agent-a",
        tenant="acme",
        task_id="task-ed25519",
        purpose="signing-test",
        grants={
            "mem_read": ("mem/*",),
            "write_file": ("/acme/*",),
        },
        expires_at=1_900,
        max_calls=20,
    )


def test_ed25519_public_key_only_verifier_validates_but_cannot_mint(tmp_path):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    private_key, public_key = _keypair()
    issuer = _ed_issuer(registry, private_key, public_key)
    verifier = _ed_verifier(registry, public_key)

    signed = _capability(issuer)
    verified = verifier.verify(signed.token)
    assert verified.capability.principal == "agent-a"
    assert verified.capability.task_id == "task-ed25519"

    with pytest.raises(CapabilityAuthenticationError, match="public-key-only verifier"):
        verifier.issue(
            principal="forged-agent",
            tenant="acme",
            task_id="task-ed25519",
            purpose="signing-test",
            grants={"write_file": ("/acme/*",)},
            expires_at=1_900,
        )
    with pytest.raises(CapabilityAuthenticationError, match="public-key-only verifier"):
        verifier.issue_resource_commit_permit(
            signed.token,
            request_digest="a" * 64,
            action="write_file",
            resource="/acme/report.txt",
            payload_digest="b" * 64,
        )


def test_ed25519_resource_commit_permit_is_verified_by_public_key_only_verifier(
    tmp_path,
):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    private_key, public_key = _keypair()
    issuer = _ed_issuer(registry, private_key, public_key)
    verifier = _ed_verifier(registry, public_key)
    signed = _capability(issuer)

    permit = issuer.issue_resource_commit_permit(
        signed.token,
        request_digest="a" * 64,
        action="write_file",
        resource="/acme/report.txt",
        payload_digest="b" * 64,
    )
    verified = verifier.verify_resource_commit_permit(permit)
    assert verified.authority_id == signed.capability.cap_id
    assert verified.action == "write_file"
    assert verified.resource == "/acme/report.txt"
    assert verified.request_digest == "a" * 64
    assert verified.payload_digest == "b" * 64


def test_ed25519_wrong_key_id_audience_public_key_and_tampering_fail_closed(tmp_path):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    private_key, public_key = _keypair()
    _, wrong_public = _keypair()
    issuer = _ed_issuer(registry, private_key, public_key)
    signed = _capability(issuer)

    with pytest.raises(CapabilityAuthenticationError):
        _ed_verifier(registry, public_key, key_id="rotated-key").verify(signed.token)
    with pytest.raises(CapabilityAuthenticationError):
        _ed_verifier(registry, public_key, audience="wrong-audience").verify(
            signed.token
        )
    with pytest.raises(CapabilityAuthenticationError):
        _ed_verifier(registry, wrong_public).verify(signed.token)

    key_id, body, signature = signed.token.split(".")
    changed_body = ("A" if body[0] != "A" else "B") + body[1:]
    tampered = key_id + "." + changed_body + "." + signature
    with pytest.raises(CapabilityAuthenticationError):
        _ed_verifier(registry, public_key).verify(tampered)


def test_ed25519_rejects_mismatched_private_and_public_keys(tmp_path):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    private_key, _public_key = _keypair()
    _, mismatched_public = _keypair()

    with pytest.raises(ValueError, match="does not match"):
        Ed25519CapabilityAuthority(
            registry,
            issuer_id="ed-issuer",
            key_id="ed-key-1",
            audience="paca-test",
            private_key=private_key,
            public_key=mismatched_public,
            **_callbacks(),
        )


def test_ed25519_issuer_can_derive_verification_key_from_private_seed(tmp_path):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    private_key, public_key = _keypair()
    issuer = Ed25519CapabilityAuthority(
        registry,
        issuer_id="ed-issuer",
        key_id="ed-key-1",
        audience="paca-test",
        private_key=private_key,
        **_callbacks(),
    )
    signed = _capability(issuer)

    assert (
        _ed_verifier(registry, public_key).verify(signed.token).capability.principal
        == "agent-a"
    )


def test_ed25519_rejects_validly_signed_algorithm_downgrade(tmp_path):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    private_key, public_key = _keypair()
    issuer = _ed_issuer(registry, private_key, public_key)
    verifier = _ed_verifier(registry, public_key)
    signed = _capability(issuer)

    key_id, body, _signature = signed.token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["signature_algorithm"] = "HS256"
    downgraded_body_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    downgraded_body = (
        base64.urlsafe_b64encode(
            downgraded_body_bytes,
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    signing_input = key_id + "." + downgraded_body
    downgrade_signature = Ed25519PrivateKey.from_private_bytes(
        private_key,
    ).sign(signing_input.encode("ascii"))
    downgrade_token = (
        signing_input
        + "."
        + base64.urlsafe_b64encode(downgrade_signature).rstrip(b"=").decode("ascii")
    )

    with pytest.raises(CapabilityAuthenticationError) as error:
        verifier.verify(downgrade_token)
    assert "token signature algorithm mismatch" in str(error.value.__cause__)


def test_ed25519_rejects_validly_signed_resource_permit_algorithm_downgrade(tmp_path):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    private_key, public_key = _keypair()
    issuer = _ed_issuer(registry, private_key, public_key)
    verifier = _ed_verifier(registry, public_key)
    signed = _capability(issuer)
    permit = issuer.issue_resource_commit_permit(
        signed.token,
        request_digest="a" * 64,
        action="write_file",
        resource="/acme/report.txt",
        payload_digest="b" * 64,
    )

    version, key_id, body, _signature = permit.split(".")
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["signature_algorithm"] = "HS256"
    downgraded_body_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    downgraded_body = (
        base64.urlsafe_b64encode(
            downgraded_body_bytes,
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    signing_input = version + "." + key_id + "." + downgraded_body
    downgrade_signature = Ed25519PrivateKey.from_private_bytes(
        private_key,
    ).sign(signing_input.encode("ascii"))
    downgrade_permit = (
        signing_input
        + "."
        + base64.urlsafe_b64encode(downgrade_signature).rstrip(b"=").decode("ascii")
    )

    with pytest.raises(CapabilityAuthenticationError) as error:
        verifier.verify_resource_commit_permit(downgrade_permit)
    assert "resource commit permit signature algorithm mismatch" in str(
        error.value.__cause__
    )


def test_hmac_v2_tokens_with_legacy_payload_without_algorithm_remain_verifiable(
    tmp_path,
):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    issuer = HMACCapabilityAuthority(
        registry,
        issuer_id="hmac-issuer",
        key_id="hmac-key-1",
        key=b"H" * 32,
        audience="paca-hmac-test",
        **_callbacks(),
    )
    signed = issuer.issue(
        principal="agent-a",
        tenant="acme",
        task_id="task-ed25519",
        purpose="signing-test",
        grants={"mem_read": ("mem/*",)},
        expires_at=1_900,
    )
    key_id, body, _signature = signed.token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload.pop("signature_algorithm", None)
    legacy_body_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    legacy_body = (
        base64.urlsafe_b64encode(legacy_body_bytes).rstrip(b"=").decode("ascii")
    )
    signing_input = key_id + "." + legacy_body
    legacy_signature = hmac.new(
        issuer._key,
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    legacy_token = (
        signing_input
        + "."
        + base64.urlsafe_b64encode(legacy_signature).rstrip(b"=").decode("ascii")
    )
    assert issuer.verify(legacy_token).capability.principal == "agent-a"


def test_ed25519_key_ring_supports_rotation_overlap_and_retirement(tmp_path):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    old_private, old_public = _keypair()
    new_private, new_public = _keypair()
    old_issuer = _ed_issuer(registry, old_private, old_public)
    old_signed = _capability(old_issuer)

    rotated_issuer = Ed25519CapabilityAuthority(
        registry,
        issuer_id="ed-issuer",
        key_id="ed-key-2",
        audience="paca-test",
        private_key=new_private,
        verification_keys={
            "ed-key-1": old_public,
            "ed-key-2": new_public,
        },
        **_callbacks(),
    )
    overlapping_verifier = Ed25519CapabilityAuthority(
        registry,
        issuer_id="ed-issuer",
        key_id="ed-key-2",
        audience="paca-test",
        verification_keys={
            "ed-key-1": old_public,
            "ed-key-2": new_public,
        },
        **_callbacks(),
    )

    # During rotation overlap, the new issuer/verifier can still validate
    # credentials signed by the previous key while new credentials use key 2.
    assert (
        overlapping_verifier.verify(old_signed.token).capability.principal == "agent-a"
    )
    new_signed = _capability(rotated_issuer)
    assert (
        overlapping_verifier.verify(new_signed.token).capability.principal == "agent-a"
    )

    old_permit = old_issuer.issue_resource_commit_permit(
        old_signed.token,
        request_digest="a" * 64,
        action="write_file",
        resource="/acme/old.txt",
        payload_digest="b" * 64,
    )
    new_permit = rotated_issuer.issue_resource_commit_permit(
        old_signed.token,
        request_digest="c" * 64,
        action="write_file",
        resource="/acme/new.txt",
        payload_digest="d" * 64,
    )
    assert (
        overlapping_verifier.verify_resource_commit_permit(old_permit).key_id
        == "ed-key-1"
    )
    assert (
        overlapping_verifier.verify_resource_commit_permit(new_permit).key_id
        == "ed-key-2"
    )

    # Retirement is explicit: a verifier configured only with key 2 no longer
    # accepts credentials or permits signed with key 1.
    retired_verifier = _ed_verifier(
        registry, new_public, key_id="ed-key-2", audience="paca-test"
    )
    with pytest.raises(CapabilityAuthenticationError):
        retired_verifier.verify(old_signed.token)
    with pytest.raises(CapabilityAuthenticationError):
        retired_verifier.verify_resource_commit_permit(old_permit)


def test_ed25519_key_ring_rejects_current_key_mismatch(tmp_path):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    private_key, public_key = _keypair()
    _other_private, other_public = _keypair()

    with pytest.raises(ValueError, match="does not match"):
        Ed25519CapabilityAuthority(
            registry,
            issuer_id="ed-issuer",
            key_id="ed-key-1",
            audience="paca-test",
            private_key=private_key,
            verification_keys={"ed-key-1": other_public},
            **_callbacks(),
        )


def test_ed25519_verification_key_ring_has_a_safe_size_limit(tmp_path):
    registry = SQLiteAuthorityRegistry(
        tmp_path / "authority.sqlite3", clock=lambda: 1_000
    )
    _private_key, public_key = _keypair()
    keys = {f"ed-key-{index}": public_key for index in range(33)}

    with pytest.raises(ValueError, match="limited to 32 keys"):
        Ed25519CapabilityAuthority(
            registry,
            issuer_id="ed-issuer",
            key_id="ed-key-0",
            audience="paca-test",
            verification_keys=keys,
            **_callbacks(),
        )
