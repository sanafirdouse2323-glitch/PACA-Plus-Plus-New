"""Ed25519 message authentication for PACA++ protocol envelopes.

Key trust is explicitly configured per key ID, issuer, audience and message type.
This module does not provide key generation, storage, rotation or authenticated
key distribution; those remain deployment responsibilities.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import canonicalize

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # pragma: no cover - depends on optional crypto installation
    Ed25519PrivateKey = None
    Ed25519PublicKey = None


_SIGNATURE_DOMAIN = b"PACA++/MESSAGE/V1\n"
_SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{86}$")


class MessageAuthenticationError(PermissionError):
    """A PACA++ message failed its configured issuer/key/signature checks."""


class MessageSigningConfigurationError(ValueError):
    """A signer or trusted key configuration is invalid."""


def _freeze_scope(values: Iterable[str], field_name: str) -> frozenset[str]:
    """Copy a configured string scope into an immutable, validated set."""
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise ValueError(f"{field_name} must be a collection of non-empty strings")
    try:
        frozen = frozenset(values)
    except TypeError as exc:
        raise ValueError(
            f"{field_name} must be a collection of non-empty strings"
        ) from exc
    if not frozen or any(not isinstance(item, str) or not item for item in frozen):
        raise ValueError(f"{field_name} must contain non-empty strings")
    return frozen


@dataclass(frozen=True)
class TrustedMessageKey:
    """A public key trusted only for a specific issuer, audiences and message types."""

    public_key: Any
    issuer: str
    audiences: frozenset[str]
    message_types: frozenset[str]

    def __post_init__(self) -> None:
        if Ed25519PublicKey is None:
            raise MessageSigningConfigurationError(
                "Ed25519 support requires the PACA++ 'protocol' extra"
            )
        if not isinstance(self.public_key, Ed25519PublicKey):
            raise TypeError("public_key must be a cryptography Ed25519PublicKey")
        if not isinstance(self.issuer, str) or not self.issuer:
            raise ValueError("trusted message issuer must be non-empty")
        object.__setattr__(
            self, "audiences", _freeze_scope(self.audiences, "audiences")
        )
        object.__setattr__(
            self, "message_types", _freeze_scope(self.message_types, "message_types")
        )


@dataclass(frozen=True)
class VerifiedMessage:
    """Authenticated message metadata established by a configured verifier key."""

    key_id: str
    issuer: str
    audience: str
    message_type: str
    signed_digest: str


class MessageSigner:
    """Sign one protocol message with an Ed25519 private key.

    The signer requires a message without an existing proof and will only sign
    messages whose issuer and audience match its configured scope.
    """

    def __init__(
        self,
        *,
        key_id: str,
        issuer: str,
        audiences: frozenset[str],
        private_key: Any,
    ) -> None:
        if Ed25519PrivateKey is None:
            raise MessageSigningConfigurationError(
                "Ed25519 support requires the PACA++ 'protocol' extra"
            )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be a cryptography Ed25519PrivateKey")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("key_id must be non-empty")
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("issuer must be non-empty")
        self._key_id = key_id
        self._issuer = issuer
        self._audiences = _freeze_scope(audiences, "audiences")
        self._private_key = private_key

    def sign(self, message: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(message, Mapping):
            raise TypeError("message must be a mapping")
        if "proof" in message:
            raise ValueError("message must not already contain a proof")
        message_type = message.get("message_type")
        audience = message.get("audience")
        if not isinstance(message_type, str) or not message_type:
            raise ValueError("message_type must be non-empty before signing")
        if message.get("issuer") != self._issuer:
            raise ValueError("message issuer does not match the configured signer")
        if not isinstance(audience, str) or audience not in self._audiences:
            raise ValueError("message audience is outside the configured signer scope")
        unsigned = dict(message)
        signing_input = _signing_input(unsigned, message_type)
        signature = self._private_key.sign(signing_input)
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        signed = dict(unsigned)
        signed["proof"] = {
            "key_id": self._key_id,
            "algorithm": "Ed25519",
            "signature": encoded,
        }
        return signed


class MessageVerifier:
    """Verify protocol signatures against an explicit scoped public-key ring.

    Algorithms are selected by trusted configuration: this verifier accepts only
    Ed25519 and never dispatches to an algorithm named by an untrusted message.
    """

    def __init__(self, keys: Mapping[str, TrustedMessageKey]) -> None:
        if Ed25519PublicKey is None:
            raise MessageSigningConfigurationError(
                "Ed25519 support requires the PACA++ 'protocol' extra"
            )
        if not isinstance(keys, Mapping) or not keys:
            raise ValueError("message verification key ring must not be empty")
        normalized: dict[str, TrustedMessageKey] = {}
        for key_id, key in keys.items():
            if not isinstance(key_id, str) or not key_id:
                raise ValueError(
                    "message verification key IDs must be non-empty strings"
                )
            if not isinstance(key, TrustedMessageKey):
                raise TypeError("key ring entries must be TrustedMessageKey instances")
            normalized[key_id] = key
        self._keys = normalized

    def verify(self, message: Mapping[str, Any]) -> VerifiedMessage:
        if not isinstance(message, Mapping):
            raise MessageAuthenticationError("message must be an object")
        proof = message.get("proof")
        if not isinstance(proof, Mapping):
            raise MessageAuthenticationError("message proof is missing or malformed")
        key_id = proof.get("key_id")
        if not isinstance(key_id, str) or key_id not in self._keys:
            raise MessageAuthenticationError(
                "message proof references an untrusted key"
            )
        if proof.get("algorithm") != "Ed25519":
            raise MessageAuthenticationError("message proof algorithm is not permitted")
        encoded = proof.get("signature")
        if not isinstance(encoded, str) or not _SIGNATURE_PATTERN.fullmatch(encoded):
            raise MessageAuthenticationError("message signature encoding is invalid")
        trusted = self._keys[key_id]
        issuer = message.get("issuer")
        audience = message.get("audience")
        message_type = message.get("message_type")
        if not isinstance(issuer, str) or issuer != trusted.issuer:
            raise MessageAuthenticationError(
                "message issuer is not trusted for this key"
            )
        if not isinstance(audience, str) or audience not in trusted.audiences:
            raise MessageAuthenticationError(
                "message audience is not trusted for this key"
            )
        if (
            not isinstance(message_type, str)
            or not message_type
            or message_type not in trusted.message_types
        ):
            raise MessageAuthenticationError("message type is not trusted for this key")
        unsigned = dict(message)
        unsigned.pop("proof", None)
        try:
            signature = base64.urlsafe_b64decode(encoded + "==")
            if (
                len(signature) != 64
                or base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
                != encoded
            ):
                raise ValueError("invalid or non-canonical Ed25519 signature encoding")
            signing_input = _signing_input(unsigned, message_type)
            trusted.public_key.verify(signature, signing_input)
        except (ValueError, binascii.Error, TypeError) as exc:
            raise MessageAuthenticationError(
                "message signature verification failed"
            ) from exc
        except Exception as exc:
            # Cryptography's InvalidSignature is intentionally normalised at this
            # trust boundary without leaking implementation details.
            raise MessageAuthenticationError("message signature verification failed") from exc
        signed_digest = hashlib.sha256(signing_input).hexdigest()
        return VerifiedMessage(
            key_id=key_id,
            issuer=issuer,
            audience=audience,
            message_type=message_type,
            signed_digest=signed_digest,
        )


def _signing_input(message: Mapping[str, Any], message_type: str) -> bytes:
    try:
        type_bytes = message_type.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("message_type must be ASCII") from exc
    return _SIGNATURE_DOMAIN + type_bytes + b"\n" + canonicalize(dict(message))
