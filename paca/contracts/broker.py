"""Authenticated-session binding and semantic checks for broker operations.

This module verifies a signed broker request against facts supplied by a trusted
transport/session adapter. It does not create or authenticate that session, resolve
or evaluate grants, consume nonces, verify commit permits, access resources, or
execute operations. Those responsibilities remain separate enforcement layers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import digest_object
from .signatures import MessageAuthenticationError, MessageVerifier
from .validation import ContractValidationError, validate_message

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BROKER_MESSAGE_TYPE = "paca.broker-operation.v1"
_DIGEST_ALGORITHM = "sha-256"
_MUTATING_OPERATIONS = frozenset({"write", "delete", "send", "execute"})


class BrokerOperationError(PermissionError):
    """A broker operation failed protocol, signature, or session binding checks."""


@dataclass(frozen=True)
class BrokerSessionContext:
    """Session facts established by a trusted, out-of-band transport adapter.

    The caller MUST construct this value only after authenticating the peer and
    deriving the channel-binding digest from the live transport. Never populate
    these fields from the broker-operation message itself. This dataclass is a
    typed hand-off, not an authentication mechanism.
    """

    session_id: str
    issuer: str
    key_id: str
    audience: str
    channel_binding_digest: str
    principal_id: str
    workload_id: str
    tenant_id: str
    task_id: str
    purpose: str

    def __post_init__(self) -> None:
        for field_name in (
            "session_id",
            "issuer",
            "key_id",
            "audience",
            "principal_id",
            "workload_id",
            "tenant_id",
            "task_id",
            "purpose",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} must be a non-empty string")
        if (
            not isinstance(self.channel_binding_digest, str)
            or not _SHA256_RE.fullmatch(self.channel_binding_digest)
        ):
            raise ValueError(
                "channel_binding_digest must be a lowercase SHA-256 hex digest"
            )


@dataclass(frozen=True)
class VerifiedBrokerOperation:
    """Immutable, verified operation facts ready for a later policy/PEP layer.

    The result is not an authorization decision. In particular, grant status,
    policy epoch, provenance release, nonce uniqueness and commit-permit validity
    still require authoritative checks before any disclosure or effect.
    """

    message_id: str
    operation_id: str
    operation: str
    session_id: str
    principal_id: str
    workload_id: str
    tenant_id: str
    task_id: str
    purpose: str
    issuer: str
    key_id: str
    audience: str
    authorization_grant_ref: str
    resource_type: str
    resource_id: str
    resource_version_id: str | None
    request_nonce: str
    intent_digest: str
    payload_digest: str | None
    commit_permit_ref: str | None
    idempotency_key: str | None
    max_bytes: int | None


class BrokerOperationVerifier:
    """Verify v1.0.0 broker-operation envelopes and their session binding.

    The verifier authenticates the message with a configured Ed25519 key ring,
    checks that the signer and message are bound to the supplied authenticated
    session, recomputes the canonical operation-intent digest, and recomputes
    payload digests when a payload is present.

    It is deliberately stateless: callers must persist and atomically consume
    request nonces/idempotency keys in an authoritative replay ledger.
    """

    def __init__(self, message_verifier: MessageVerifier) -> None:
        if not isinstance(message_verifier, MessageVerifier):
            raise TypeError("message_verifier must be a configured MessageVerifier")
        self._message_verifier = message_verifier

    def verify(
        self,
        message: Mapping[str, Any],
        *,
        session: BrokerSessionContext,
        expected_grant_ref: str,
    ) -> VerifiedBrokerOperation:
        """Return verified request facts or fail closed before resource access."""
        if not isinstance(session, BrokerSessionContext):
            raise TypeError("session must come from a trusted transport adapter")
        if not isinstance(expected_grant_ref, str) or not expected_grant_ref:
            raise ValueError("expected_grant_ref must be a non-empty trusted grant ID")
        if not isinstance(message, Mapping):
            raise BrokerOperationError("broker operation must be a JSON object")

        try:
            validate_message(message)
        except ContractValidationError as exc:
            raise BrokerOperationError("broker operation schema validation failed") from exc

        if message.get("message_type") != _BROKER_MESSAGE_TYPE:
            raise BrokerOperationError("message is not a v1.0.0 broker operation")

        try:
            verified = self._message_verifier.verify(message)
        except MessageAuthenticationError as exc:
            raise BrokerOperationError("broker operation signature verification failed") from exc

        if verified.issuer != session.issuer or verified.key_id != session.key_id:
            raise BrokerOperationError(
                "broker operation signing issuer or key does not match the authenticated session"
            )
        if verified.audience != session.audience:
            raise BrokerOperationError(
                "broker operation audience does not match the authenticated session"
            )
        if message.get("session_id") != session.session_id:
            raise BrokerOperationError(
                "broker operation session does not match the authenticated session"
            )

        expected_channel_binding = {
            "algorithm": _DIGEST_ALGORITHM,
            "value": session.channel_binding_digest,
        }
        if message.get("channel_binding_digest") != expected_channel_binding:
            raise BrokerOperationError(
                "broker operation channel binding does not match the authenticated transport"
            )

        grant_ref = message.get("authorization_grant_ref")
        if grant_ref != expected_grant_ref:
            raise BrokerOperationError(
                "broker operation grant reference does not match the resolved grant"
            )

        unsigned_intent = dict(message)
        unsigned_intent.pop("proof", None)
        # The permit reference is signed by the worker, but is excluded from the
        # intent digest to avoid a circular dependency when the permit binds intent.
        unsigned_intent.pop("commit_permit_ref", None)
        try:
            intent_digest = digest_object(unsigned_intent, purpose="request")
        except (TypeError, ValueError) as exc:
            raise BrokerOperationError(
                "broker operation intent cannot be canonically digested"
            ) from exc

        payload_digest_value: str | None = None
        payload = message.get("payload")
        supplied_payload_digest = message.get("payload_digest")
        if payload is not None:
            if not isinstance(payload, Mapping):
                raise BrokerOperationError("broker operation payload must be an object")
            if not isinstance(supplied_payload_digest, Mapping):
                raise BrokerOperationError("broker operation payload digest is missing")
            try:
                payload_digest_value = digest_object(dict(payload), purpose="payload")
            except (TypeError, ValueError) as exc:
                raise BrokerOperationError(
                    "broker operation payload cannot be canonically digested"
                ) from exc
            if supplied_payload_digest != {
                "algorithm": _DIGEST_ALGORITHM,
                "value": payload_digest_value,
            }:
                raise BrokerOperationError(
                    "broker operation payload digest does not match its payload"
                )
        elif supplied_payload_digest is not None:
            if not isinstance(supplied_payload_digest, Mapping):
                raise BrokerOperationError("broker operation payload digest is malformed")
            digest_value = supplied_payload_digest.get("value")
            if (
                supplied_payload_digest.get("algorithm") != _DIGEST_ALGORITHM
                or not isinstance(digest_value, str)
                or not _SHA256_RE.fullmatch(digest_value)
            ):
                raise BrokerOperationError("broker operation payload digest is malformed")
            payload_digest_value = digest_value

        resource = message["resource"]
        if not isinstance(resource, Mapping):
            # The closed JSON Schema already rejects this; retain a local guard so
            # this module does not rely on assertions for security-relevant typing.
            raise BrokerOperationError("broker operation resource is malformed")
        read_constraints = message.get("read_constraints")
        max_bytes: int | None = None
        if isinstance(read_constraints, Mapping):
            candidate = read_constraints.get("max_bytes")
            if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate < 1:
                raise BrokerOperationError("broker read maximum byte bound is invalid")
            max_bytes = candidate

        operation = message["operation"]
        commit_permit_ref = message.get("commit_permit_ref")
        if operation in _MUTATING_OPERATIONS and not isinstance(commit_permit_ref, str):
            raise BrokerOperationError("mutating broker operation lacks a commit permit reference")

        return VerifiedBrokerOperation(
            message_id=message["message_id"],
            operation_id=message["operation_id"],
            operation=operation,
            session_id=session.session_id,
            principal_id=session.principal_id,
            workload_id=session.workload_id,
            tenant_id=session.tenant_id,
            task_id=session.task_id,
            purpose=session.purpose,
            issuer=verified.issuer,
            key_id=verified.key_id,
            audience=verified.audience,
            authorization_grant_ref=grant_ref,
            resource_type=resource["resource_type"],
            resource_id=resource["resource_id"],
            resource_version_id=resource.get("version_id"),
            request_nonce=message["request_nonce"],
            intent_digest=intent_digest,
            payload_digest=payload_digest_value,
            commit_permit_ref=commit_permit_ref,
            idempotency_key=message.get("idempotency_key"),
            max_bytes=max_bytes,
        )


__all__ = [
    "BrokerOperationError",
    "BrokerOperationVerifier",
    "BrokerSessionContext",
    "VerifiedBrokerOperation",
]
