"""Authenticated HMAC and Ed25519 capability issuance and verification.

HMAC is used as a dependency-free research reference mechanism. It is a shared-secret
MAC, not a public-key credential format or an OAuth authorization server. Every party
holding the verification key can also mint credentials, so key distribution and the
issuer process remain part of the trusted computing base. Persistent authority state
and SQLite resource-commit records live in :mod:`paca.authority_registry`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .authority import AuthorityLineage
from .authority_registry import (
    AuthorityRegistryError,
    SQLiteAuthorityRegistry,
    VerifiedResourceCommitPermit,
    _canonical,
    _record_from_dict,
)
from .runtime import Capability


class CapabilityAuthenticationError(PermissionError):
    """A signed capability failed authentication or validation."""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(
        value + ("=" * (-len(value) % 4)),
        altchars=b"-_",
        validate=True,
    )


@dataclass(frozen=True)
class SignedCapability:
    token: str
    capability: Capability


class HMACCapabilityAuthority:
    """Issue and verify audience-bound, HMAC-authenticated capability envelopes."""

    TOKEN_VERSION = 2
    SIGNATURE_ALGORITHM = "HS256"
    DEFAULT_TASK_MAX_CALLS = 100

    def __init__(
        self,
        registry: SQLiteAuthorityRegistry,
        *,
        issuer_id: str,
        key_id: str,
        key: bytes,
        audience: str,
        identity_verifier: Callable[[str, str], bool],
        task_context_verifier: Callable[[str, str, str, str], bool],
        clock=time.time,
    ) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("HMAC key must contain at least 32 bytes")
        for name, value in (
            ("issuer_id", issuer_id),
            ("key_id", key_id),
            ("audience", audience),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(name + " must be a non-empty string")
        self.registry = registry
        self.issuer_id = issuer_id
        self.key_id = key_id
        self._key = bytes(key)
        if not callable(identity_verifier):
            raise TypeError(
                "identity_verifier must bind a principal to a tenant using trusted identity state"
            )
        if not callable(task_context_verifier):
            raise TypeError(
                "task_context_verifier must validate principal, tenant, task and purpose "
                "against trusted orchestrator state"
            )
        self.audience = audience
        self.identity_verifier = identity_verifier
        self.task_context_verifier = task_context_verifier
        self.clock = clock

    def _sign_bytes(self, message: bytes) -> bytes:
        """Sign bytes with the configured issuer key."""
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def _accepts_key_id(self, key_id: str) -> bool:
        """Return whether this authority is configured to trust the key identifier."""
        return isinstance(key_id, str) and key_id == self.key_id

    def _verify_bytes(
        self,
        message: bytes,
        signature: bytes,
        *,
        key_id: str | None = None,
    ) -> bool:
        """Verify bytes using the configured verification key."""
        if key_id is not None and not self._accepts_key_id(key_id):
            return False
        return hmac.compare_digest(self._sign_bytes(message), signature)

    def _encode(self, payload: Mapping[str, object]) -> str:
        encoded_payload = dict(payload)
        encoded_payload["signature_algorithm"] = self.SIGNATURE_ALGORITHM
        body = _b64encode(_canonical(encoded_payload))
        signing_input = self.key_id + "." + body
        signature = _b64encode(self._sign_bytes(signing_input.encode("ascii")))
        return signing_input + "." + signature

    def issue_resource_commit_permit(
        self,
        capability_token: str,
        *,
        request_digest: str,
        action: str,
        resource: str,
        payload_digest: str,
        lifetime_seconds: int = 15,
    ) -> str:
        """Issue a one-use, short-lived signed permit for one exact resource write.

        The signature implementation is selected by this authority instance.
        HMAC verifiers are also signers; Ed25519 verifiers can hold only a public
        key and cannot mint permits.
        """
        for name, value in (
            ("request_digest", request_digest),
            ("payload_digest", payload_digest),
        ):
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if action not in {"write_file", "mem_write"}:
            raise ValueError(
                "resource commit permits are supported only for write_file and mem_write"
            )
        if not isinstance(resource, str) or not resource or len(resource) > 4096:
            raise ValueError("resource must be a non-empty bounded key")
        if (
            isinstance(lifetime_seconds, bool)
            or not isinstance(lifetime_seconds, int)
            or not 1 <= lifetime_seconds <= 30
        ):
            raise ValueError(
                "resource commit permit lifetime must be between 1 and 30 seconds"
            )
        signed = self.verify(capability_token)
        capability = signed.capability
        record = capability.authority_lineage
        if record is None:
            raise CapabilityAuthenticationError(
                "resource commit capability lacks authority lineage"
            )
        now = int(self.clock())
        payload: dict[str, object] = {
            "version": 1,
            "issuer": self.issuer_id,
            "key_id": self.key_id,
            "audience": self.audience,
            "authority_id": record.authority_id,
            "tenant": record.tenant,
            "task_id": record.task_id,
            "purpose": record.purpose,
            "policy_epoch": record.policy_epoch,
            "issued_at": now,
            "expires_at": now + lifetime_seconds,
            "max_calls": capability.max_calls,
            "action": action,
            "resource": resource,
            "request_digest": request_digest,
            "payload_digest": payload_digest,
            "nonce": secrets.token_urlsafe(24),
        }
        payload["signature_algorithm"] = self.SIGNATURE_ALGORITHM
        body = _b64encode(_canonical(payload))
        signing_input = "resource-commit-v1." + self.key_id + "." + body
        signature = _b64encode(self._sign_bytes(signing_input.encode("ascii")))
        return signing_input + "." + signature

    def verify_resource_commit_permit(
        self,
        token: str,
    ) -> VerifiedResourceCommitPermit:
        """Authenticate a resource permit; active-state checks happen in commit SQL."""
        try:
            if not isinstance(token, str) or len(token) > 16_384:
                raise ValueError("invalid resource commit permit size or type")
            version, key_id, body, signature = token.split(".")
            if version != "resource-commit-v1" or not self._accepts_key_id(key_id):
                raise ValueError(
                    "resource commit permit version or key identifier mismatch"
                )
            signing_input = version + "." + key_id + "." + body
            if not self._verify_bytes(
                signing_input.encode("ascii"),
                _b64decode(signature),
                key_id=key_id,
            ):
                raise ValueError("resource commit permit signature mismatch")
            payload = json.loads(_b64decode(body))
            if not isinstance(payload, dict) or payload.get("version") != 1:
                raise ValueError("resource commit permit payload is malformed")
            if payload.get("issuer") != self.issuer_id:
                raise ValueError("resource commit permit issuer mismatch")
            if (
                payload.get("key_id") != key_id
                or payload.get("audience") != self.audience
            ):
                raise ValueError("resource commit permit key or audience mismatch")
            if payload.get("signature_algorithm") != self.SIGNATURE_ALGORITHM:
                raise ValueError("resource commit permit signature algorithm mismatch")
            expected_fields = {
                "version",
                "signature_algorithm",
                "issuer",
                "key_id",
                "audience",
                "authority_id",
                "tenant",
                "task_id",
                "purpose",
                "policy_epoch",
                "issued_at",
                "expires_at",
                "max_calls",
                "action",
                "resource",
                "request_digest",
                "payload_digest",
                "nonce",
            }
            if set(payload) != expected_fields:
                raise ValueError(
                    "resource commit permit contains missing or unknown fields"
                )
            result = VerifiedResourceCommitPermit(
                nonce=payload["nonce"],
                issuer=payload["issuer"],
                key_id=payload["key_id"],
                audience=payload["audience"],
                authority_id=payload["authority_id"],
                tenant=payload["tenant"],
                task_id=payload["task_id"],
                purpose=payload["purpose"],
                policy_epoch=payload["policy_epoch"],
                issued_at=payload["issued_at"],
                expires_at=payload["expires_at"],
                max_calls=payload["max_calls"],
                action=payload["action"],
                resource=payload["resource"],
                request_digest=payload["request_digest"],
                payload_digest=payload["payload_digest"],
            )
            now = int(self.clock())
            if (
                result.issued_at > now + 30
                or result.expires_at <= now
                or result.expires_at <= result.issued_at
                or result.expires_at - result.issued_at > 30
            ):
                raise ValueError(
                    "resource commit permit is expired or has an invalid lifetime"
                )
            return result
        except (
            ValueError,
            TypeError,
            KeyError,
            json.JSONDecodeError,
            AuthorityRegistryError,
            sqlite3.Error,
        ) as exc:
            raise CapabilityAuthenticationError(
                "resource commit permit authentication failed"
            ) from exc

    def issue(
        self,
        *,
        principal: str,
        tenant: str | None = None,
        task_id: str | None = None,
        purpose: str | None = None,
        grants: Mapping[str, Iterable[str]],
        expires_at: int,
        role: str = "assistant",
        max_calls: int = 40,
        max_fanout: int = 5,
        max_task_calls: int | None = None,
        tool_pins: Mapping[str, str] | None = None,
        parent_token: str | None = None,
    ) -> SignedCapability:
        now = int(self.clock())
        if (
            isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
            or expires_at <= now
        ):
            raise ValueError("expires_at must be a future Unix timestamp in seconds")
        if (
            isinstance(max_calls, bool)
            or not isinstance(max_calls, int)
            or max_calls < 1
        ):
            raise ValueError("max_calls must be a positive integer")
        if (
            isinstance(max_fanout, bool)
            or not isinstance(max_fanout, int)
            or max_fanout < 1
        ):
            raise ValueError("max_fanout must be a positive integer")
        if max_task_calls is not None and (
            isinstance(max_task_calls, bool)
            or not isinstance(max_task_calls, int)
            or max_task_calls < 1
        ):
            raise ValueError("max_task_calls must be a positive integer")
        if (
            not isinstance(principal, str)
            or not principal
            or not isinstance(role, str)
            or not role
        ):
            raise ValueError("principal and role must be non-empty strings")
        pins = dict(tool_pins or {})
        if any(
            not isinstance(k, str) or not k or not isinstance(v, str) or not v
            for k, v in pins.items()
        ):
            raise ValueError("tool pins must map non-empty names to non-empty hashes")
        epoch = self.registry.current_epoch()
        parent_id = None
        parent_digest = None
        if parent_token is not None:
            parent_signed = self.verify(parent_token)
            parent_record = parent_signed.capability.authority_lineage
            if parent_record is None:
                raise CapabilityAuthenticationError(
                    "delegation parent lacks authority lineage"
                )
            parent_id = parent_record.authority_id
            self.registry.assert_active(parent_id)
            if (
                max_task_calls is not None
                and max_task_calls != parent_record.max_task_calls
            ):
                raise ValueError(
                    "delegated capability must preserve its parent's task-wide call quota"
                )
            max_task_calls = parent_record.max_task_calls
            delegated_targets = dict(parent_record.grants).get("delegate", ())
            from .authority import grant_pattern_is_subset

            if not delegated_targets or not any(
                grant_pattern_is_subset(principal, target)
                for target in delegated_targets
            ):
                raise ValueError(
                    "parent capability does not authorise delegation to this principal"
                )
            parent_pins = parent_signed.capability.tool_pins
            if any(parent_pins.get(name) != digest for name, digest in pins.items()):
                raise ValueError(
                    "delegated tool pins must be a subset of the parent's pins"
                )
            tenant = parent_record.tenant
            task_id = parent_record.task_id
            purpose = parent_record.purpose
            if expires_at > parent_record.expires:
                raise ValueError("delegated capability cannot outlive its parent")
            if max_calls > parent_signed.capability.max_calls:
                raise ValueError("delegated call budget cannot exceed its parent")
            if max_fanout > parent_signed.capability.max_fanout:
                raise ValueError("delegated fan-out cannot exceed its parent")
            parent_digest = self.registry.chain_digest(parent_id)
        if max_task_calls is None:
            max_task_calls = self.DEFAULT_TASK_MAX_CALLS
        if any(
            value is None or not isinstance(value, str) or not value
            for value in (tenant, task_id, purpose)
        ):
            raise ValueError(
                "root capability issuance requires tenant, task_id and purpose"
            )
        try:
            authenticated = bool(self.identity_verifier(principal, str(tenant)))
        except Exception as exc:
            raise CapabilityAuthenticationError(
                "trusted principal authentication failed"
            ) from exc
        if not authenticated:
            raise CapabilityAuthenticationError(
                "principal is not authenticated for the requested tenant"
            )
        try:
            task_context_authenticated = bool(
                self.task_context_verifier(
                    principal,
                    str(tenant),
                    str(task_id),
                    str(purpose),
                )
            )
        except Exception as exc:
            raise CapabilityAuthenticationError(
                "trusted task context authentication failed"
            ) from exc
        if not task_context_authenticated:
            raise CapabilityAuthenticationError(
                "principal is not authorised for the requested task and purpose"
            )
        authority_id = secrets.token_urlsafe(18)
        record = AuthorityLineage.create(
            authority_id=authority_id,
            issuer=self.issuer_id,
            principal=principal,
            tenant=str(tenant),
            task_id=str(task_id),
            purpose=str(purpose),
            policy_epoch=epoch,
            expires=expires_at,
            grants=grants,
            parent_id=parent_id,
            parent_digest=parent_digest,
            max_task_calls=max_task_calls,
            max_calls=max_calls,
            audience=self.audience,
        )
        self.registry.register_authority(
            record,
            parent_max_fanout=(
                parent_signed.capability.max_fanout
                if parent_token is not None
                else None
            ),
            parent_max_calls=(
                parent_signed.capability.max_calls if parent_token is not None else None
            ),
        )
        capability = Capability(
            cap_id=record.authority_id,
            principal=record.principal,
            tenant=record.tenant,
            task_id=record.task_id,
            role=role,
            grants={action: patterns for action, patterns in record.grants},
            expires=record.expires,
            max_calls=max_calls,
            max_fanout=max_fanout,
            tool_pins=pins,
            parent=record.parent_id,
            authority_lineage=record,
        )
        payload: dict[str, object] = {
            "version": self.TOKEN_VERSION,
            "issuer": self.issuer_id,
            "audience": self.audience,
            "issued_at": now,
            "key_id": self.key_id,
            "authority": record.as_dict(),
            "role": role,
            "max_calls": max_calls,
            "max_fanout": max_fanout,
            "tool_pins": pins,
        }
        return SignedCapability(self._encode(payload), capability)

    def verify(self, token: str, *, audience: str | None = None) -> SignedCapability:
        try:
            if not isinstance(token, str):
                raise TypeError("token must be a string")
            if len(token) > 65536:
                raise ValueError("token exceeds the maximum size")
            key_id, body, signature = token.split(".")
            if not self._accepts_key_id(key_id):
                raise ValueError("unknown signing key")
            signing_input = key_id + "." + body
            supplied = _b64decode(signature)
            if not self._verify_bytes(
                signing_input.encode("ascii"),
                supplied,
                key_id=key_id,
            ):
                raise ValueError("signature mismatch")
            payload = json.loads(_b64decode(body))
            if not isinstance(payload, dict):
                raise TypeError("token payload must be an object")
            if payload.get("version") != self.TOKEN_VERSION:
                raise ValueError("unsupported token version")
            token_algorithm = payload.get("signature_algorithm")
            if token_algorithm not in (None, self.SIGNATURE_ALGORITHM):
                raise ValueError("token signature algorithm mismatch")
            if (
                self.SIGNATURE_ALGORITHM != "HS256"
                and token_algorithm != self.SIGNATURE_ALGORITHM
            ):
                raise ValueError(
                    "asymmetric token is missing its required signature algorithm"
                )
            if (
                payload.get("key_id") != key_id
                or payload.get("issuer") != self.issuer_id
            ):
                raise ValueError("issuer or key identifier mismatch")
            expected_audience = audience or self.audience
            if payload.get("audience") != expected_audience:
                raise ValueError("token audience mismatch")
            issued_at = payload.get("issued_at")
            if (
                isinstance(issued_at, bool)
                or not isinstance(issued_at, int)
                or issued_at > int(self.clock()) + 30
            ):
                raise ValueError("invalid token issuance time")
            authority_data = payload.get("authority")
            if not isinstance(authority_data, dict):
                raise TypeError("authority record must be an object")
            record = _record_from_dict(authority_data)
            if record.issuer != self.issuer_id:
                raise ValueError("authority issuer mismatch")
            if record.audience is not None and record.audience != expected_audience:
                raise ValueError("authority audience mismatch")
            stored = self.registry.get_authority(record.authority_id)
            if stored != record:
                raise ValueError("signed authority does not match the trusted registry")
            self.registry.assert_active(record.authority_id)
            role = payload.get("role")
            max_calls = payload.get("max_calls")
            max_fanout = payload.get("max_fanout")
            pins = payload.get("tool_pins")
            if not isinstance(role, str) or not role:
                raise ValueError("invalid capability role")
            if (
                isinstance(max_calls, bool)
                or not isinstance(max_calls, int)
                or max_calls < 1
            ):
                raise ValueError("invalid call budget")
            if (
                isinstance(max_fanout, bool)
                or not isinstance(max_fanout, int)
                or max_fanout < 1
            ):
                raise ValueError("invalid fan-out budget")
            if not isinstance(pins, dict) or any(
                not isinstance(k, str) or not isinstance(v, str)
                for k, v in pins.items()
            ):
                raise ValueError("invalid tool pins")
            capability = Capability(
                cap_id=record.authority_id,
                principal=record.principal,
                tenant=record.tenant,
                task_id=record.task_id,
                role=role,
                grants={action: patterns for action, patterns in record.grants},
                expires=record.expires,
                max_calls=max_calls,
                max_fanout=max_fanout,
                tool_pins=pins,
                parent=record.parent_id,
                authority_lineage=record,
            )
            capability.validate_authority_lineage()
            return SignedCapability(token, capability)
        except (
            ValueError,
            TypeError,
            KeyError,
            json.JSONDecodeError,
            AuthorityRegistryError,
            sqlite3.Error,
        ) as exc:
            if isinstance(exc, CapabilityAuthenticationError):
                raise
            raise CapabilityAuthenticationError(
                "capability authentication or active-state validation failed"
            ) from exc


class Ed25519CapabilityAuthority(HMACCapabilityAuthority):
    """Ed25519 authority with distinct private-key issuer and public-key verifier roles.

    The verifier receives only public keys and cannot mint capabilities or
    resource-commit permits. ``verification_keys`` can hold a bounded static
    key ring for old/new key overlap; removing an ID retires that key for this
    instance. The optional cryptography dependency is imported lazily. Private
    key storage, coordinated rotation and authenticated key distribution remain
    responsibilities of the deployment.
    """

    SIGNATURE_ALGORITHM = "Ed25519"

    def __init__(
        self,
        registry: SQLiteAuthorityRegistry,
        *,
        issuer_id: str,
        key_id: str,
        audience: str,
        identity_verifier: Callable[[str, str], bool],
        task_context_verifier: Callable[[str, str, str, str], bool],
        public_key: bytes | None = None,
        private_key: bytes | None = None,
        verification_keys: Mapping[str, bytes] | None = None,
        clock=time.time,
    ) -> None:
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("key_id must be a non-empty string")
        if len(key_id) > 128 or any(
            not character.isascii() or not (character.isalnum() or character in "_-")
            for character in key_id
        ):
            raise ValueError(
                "key_id must contain 1-128 ASCII letters, digits, hyphens or underscores"
            )
        if public_key is None and private_key is None and verification_keys is None:
            raise ValueError(
                "Ed25519 authority requires a current public/private key or a verification key ring"
            )
        if public_key is not None and (
            not isinstance(public_key, bytes) or len(public_key) != 32
        ):
            raise ValueError("Ed25519 public key must be 32 raw bytes")
        if private_key is not None and (
            not isinstance(private_key, bytes) or len(private_key) != 32
        ):
            raise ValueError("Ed25519 private key seed must be 32 raw bytes")
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
        except ImportError as exc:
            raise ImportError(
                "Ed25519CapabilityAuthority requires the optional 'crypto' dependency"
            ) from exc

        signing_key = (
            Ed25519PrivateKey.from_private_bytes(private_key)
            if private_key is not None
            else None
        )
        derived_public = (
            signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            if signing_key is not None
            else None
        )
        if (
            public_key is not None
            and derived_public is not None
            and not hmac.compare_digest(
                public_key,
                derived_public,
            )
        ):
            raise ValueError(
                "Ed25519 public key does not match the supplied private key"
            )
        configured_verification_keys: dict[str, bytes] = {}
        if verification_keys is not None:
            if not isinstance(verification_keys, Mapping):
                raise TypeError(
                    "verification_keys must be a mapping of key IDs to raw public keys"
                )
            configured_verification_keys = dict(verification_keys)
        if len(configured_verification_keys) > 32:
            raise ValueError("Ed25519 verification key rings are limited to 32 keys")
        for (
            configured_key_id,
            configured_public_key,
        ) in configured_verification_keys.items():
            if (
                not isinstance(configured_key_id, str)
                or not configured_key_id
                or len(configured_key_id) > 128
                or any(
                    not character.isascii()
                    or not (character.isalnum() or character in "_-")
                    for character in configured_key_id
                )
                or not isinstance(configured_public_key, bytes)
                or len(configured_public_key) != 32
            ):
                raise ValueError(
                    "verification key rings require non-empty key IDs and 32-byte public keys"
                )

        verification_bytes = public_key or derived_public
        if verification_bytes is not None:
            configured_current = configured_verification_keys.get(key_id)
            if configured_current is not None and not hmac.compare_digest(
                configured_current, verification_bytes
            ):
                raise ValueError(
                    "current Ed25519 key does not match the configured verification key ring"
                )
            configured_verification_keys[key_id] = verification_bytes
        if len(configured_verification_keys) > 32:
            raise ValueError("Ed25519 verification key rings are limited to 32 keys")
        if key_id not in configured_verification_keys:
            raise ValueError(
                "verification key ring must contain the configured current key ID"
            )

        # Satisfy the shared base configuration contract, then discard the
        # placeholder HMAC key. All cryptographic operations use Ed25519 hooks.
        super().__init__(
            registry,
            issuer_id=issuer_id,
            key_id=key_id,
            key=b"\x00" * 32,
            audience=audience,
            identity_verifier=identity_verifier,
            task_context_verifier=task_context_verifier,
            clock=clock,
        )
        self._key = b""
        self._ed25519_signing_key = signing_key
        self._ed25519_verification_keys = MappingProxyType(
            {
                configured_key_id: Ed25519PublicKey.from_public_bytes(
                    configured_public_key
                )
                for configured_key_id, configured_public_key in (
                    configured_verification_keys.items()
                )
            }
        )
        # Retain the active-key attribute for compatibility with code that inspects
        # the authority's configured current verification key.
        self._ed25519_verification_key = self._ed25519_verification_keys[key_id]
        self._ed25519_invalid_signature = InvalidSignature

    def _sign_bytes(self, message: bytes) -> bytes:
        if self._ed25519_signing_key is None:
            raise CapabilityAuthenticationError(
                "public-key-only verifier cannot issue signed artifacts"
            )
        return self._ed25519_signing_key.sign(message)

    def _accepts_key_id(self, key_id: str) -> bool:
        """Accept only key IDs explicitly present in this verifier's key ring."""
        return isinstance(key_id, str) and key_id in self._ed25519_verification_keys

    def _verify_bytes(
        self,
        message: bytes,
        signature: bytes,
        *,
        key_id: str | None = None,
    ) -> bool:
        selected_key_id = self.key_id if key_id is None else key_id
        verification_key = self._ed25519_verification_keys.get(selected_key_id)
        if verification_key is None:
            return False
        try:
            verification_key.verify(signature, message)
            return True
        except self._ed25519_invalid_signature:
            return False

    def issue(self, **kwargs: object) -> SignedCapability:
        if self._ed25519_signing_key is None:
            raise CapabilityAuthenticationError(
                "public-key-only verifier cannot issue capabilities"
            )
        return super().issue(**kwargs)  # type: ignore[arg-type]

    def issue_resource_commit_permit(
        self,
        capability_token: str,
        **kwargs: object,
    ) -> str:
        if self._ed25519_signing_key is None:
            raise CapabilityAuthenticationError(
                "public-key-only verifier cannot issue resource commit permits"
            )
        return super().issue_resource_commit_permit(
            capability_token,
            **kwargs,
        )  # type: ignore[arg-type]


__all__ = [
    "AuthorityRegistryError",
    "CapabilityAuthenticationError",
    "Ed25519CapabilityAuthority",
    "HMACCapabilityAuthority",
    "SQLiteAuthorityRegistry",
    "SignedCapability",
    "VerifiedResourceCommitPermit",
]
