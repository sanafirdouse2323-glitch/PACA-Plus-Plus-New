"""Verification of v1.0.0 PACA++ resource commit permits.

This authenticates the wire artefact and checks freshness only. The broker must
bind every field to the signed operation and the live authority registry.
"""
from __future__ import annotations

import math
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .canonical import CanonicalizationError, canonicalize, parse_json
from .signatures import MessageAuthenticationError, MessageVerifier
from .validation import ContractValidationError, validate_message

_COMMIT_PERMIT_TYPE = "paca.commit-permit.v1"


class CommitPermitError(PermissionError):
    """A protocol commit permit is malformed, unauthenticated or stale."""


def _timestamp(value: object, field: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a timestamp string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    if parsed.microsecond:
        raise ValueError(f"{field} must have whole-second precision")
    result = parsed.timestamp()
    if not math.isfinite(result):
        raise ValueError(f"{field} is outside the supported timestamp range")
    return int(result)


@dataclass(frozen=True)
class VerifiedProtocolCommitPermit:
    """Authenticated commit-permit facts, not an authorization decision."""

    permit_id: str
    grant_id: str
    operation_id: str
    issuer: str
    key_id: str
    audience: str
    subject_kind: str
    subject_id: str
    tenant_id: str
    task_id: str
    purpose: str
    action: str
    destination: str
    arguments_digest: str
    payload_digest: str
    resource_version_precondition: str | None
    policy_epoch: int
    issued_at: int
    expires_at: int
    nonce: str
    idempotency_key: str
    canonical_message: bytes


class ProtocolCommitPermitVerifier:
    """Verify one signed commit permit using an explicitly scoped Ed25519 keyring."""

    def __init__(
        self,
        message_verifier: MessageVerifier,
        *,
        issuer: str,
        audience: str,
        clock=time.time,
        max_lifetime_seconds: int = 30,
        max_message_age_seconds: int = 300,
        clock_skew_seconds: int = 30,
    ) -> None:
        if not isinstance(message_verifier, MessageVerifier):
            raise TypeError("message_verifier must be a configured MessageVerifier")
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("issuer must be a non-empty trusted configuration value")
        if not isinstance(audience, str) or not audience:
            raise ValueError("audience must be a non-empty trusted configuration value")
        if not callable(clock):
            raise TypeError("clock must be a trusted callable")
        for name, value, maximum in (
            ("max_lifetime_seconds", max_lifetime_seconds, 300),
            ("max_message_age_seconds", max_message_age_seconds, 86_400),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"{name} is outside the allowed range")
        if isinstance(clock_skew_seconds, bool) or not isinstance(clock_skew_seconds, int) or not 0 <= clock_skew_seconds <= 300:
            raise ValueError("clock_skew_seconds must be between 0 and 300")
        self._message_verifier = message_verifier
        self._issuer = issuer
        self._audience = audience
        self._clock = clock
        self._max_lifetime_seconds = max_lifetime_seconds
        self._max_message_age_seconds = max_message_age_seconds
        self._clock_skew_seconds = clock_skew_seconds

    def verify(self, message: Mapping[str, Any]) -> VerifiedProtocolCommitPermit:
        """Verify schema, signature, issuer/audience scope and freshness."""
        if not isinstance(message, Mapping):
            raise CommitPermitError("commit permit must be an object")
        try:
            canonical_message = canonicalize(dict(message))
            snapshot = parse_json(canonical_message)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            raise CommitPermitError("commit permit is not canonical JSON/I-JSON") from exc
        if not isinstance(snapshot, dict):
            raise CommitPermitError("commit permit must be a JSON object")
        try:
            validate_message(snapshot)
        except ContractValidationError as exc:
            raise CommitPermitError("commit permit schema validation failed") from exc
        if snapshot.get("message_type") != _COMMIT_PERMIT_TYPE:
            raise CommitPermitError("message is not a v1.0.0 commit permit")
        try:
            verified = self._message_verifier.verify(snapshot)
        except MessageAuthenticationError as exc:
            raise CommitPermitError("commit permit signature verification failed") from exc
        if verified.issuer != self._issuer or verified.audience != self._audience:
            raise CommitPermitError("commit permit issuer or audience is not trusted")
        try:
            now = self._clock()
            if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
                raise ValueError("trusted clock returned an invalid timestamp")
            created_at = _timestamp(snapshot.get("created_at"), "created_at")
            issued_at = _timestamp(snapshot.get("issued_at"), "issued_at")
            expires_at = _timestamp(snapshot.get("expires_at"), "expires_at")
            if created_at > now + self._clock_skew_seconds or issued_at > now + self._clock_skew_seconds:
                raise ValueError("commit permit timestamp is in the future")
            if created_at < now - self._max_message_age_seconds or issued_at < now - self._max_message_age_seconds:
                raise ValueError("commit permit is stale")
            if expires_at <= now or expires_at <= issued_at or expires_at - issued_at > self._max_lifetime_seconds:
                raise ValueError("commit permit is expired or has an invalid lifetime")
            epoch = snapshot["policy_epoch"]
            if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
                raise ValueError("commit permit policy_epoch is invalid")
            subject = snapshot["subject"]
            resource = snapshot["resource"]
            args_digest = snapshot["arguments_digest"]
            payload_digest = snapshot["payload_digest"]
            if not all(isinstance(item, Mapping) for item in (subject, resource, args_digest, payload_digest)):
                raise ValueError("commit permit subject, resource or digests are malformed")
            if snapshot.get("single_use") is not True:
                raise ValueError("commit permit is not single-use")
            return VerifiedProtocolCommitPermit(
                permit_id=snapshot["permit_id"],
                grant_id=snapshot["grant_id"],
                operation_id=snapshot["operation_id"],
                issuer=verified.issuer,
                key_id=verified.key_id,
                audience=verified.audience,
                subject_kind=subject["kind"],
                subject_id=subject["id"],
                tenant_id=snapshot["tenant_id"],
                task_id=snapshot["task_id"],
                purpose=snapshot["purpose"],
                action=snapshot["action"],
                destination=snapshot["destination"],
                arguments_digest=args_digest["value"],
                payload_digest=payload_digest["value"],
                resource_version_precondition=snapshot.get("resource_version_precondition"),
                policy_epoch=epoch,
                issued_at=issued_at,
                expires_at=expires_at,
                nonce=snapshot["nonce"],
                idempotency_key=snapshot["idempotency_key"],
                canonical_message=canonical_message,
            )
        except (KeyError, TypeError, ValueError, OverflowError, OSError) as exc:
            raise CommitPermitError("commit permit fields or freshness constraints are invalid") from exc


__all__ = ["CommitPermitError", "ProtocolCommitPermitVerifier", "VerifiedProtocolCommitPermit"]
