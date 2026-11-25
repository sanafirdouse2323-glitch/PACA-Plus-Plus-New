"""Narrow in-process broker mediation for protocol-bound logical file writes.

This reference adapter accepts only one local operation profile. It verifies a
separately signed v1.0.0 commit permit, cross-binds it to the signed worker
request, then delegates the final CAS/replay/quota operation to the existing
SQLite/PostgreSQL authority transaction.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from .authority import AuthorityLineage
from .authority_registry import (
    AuthorityRegistryError,
    SQLiteAuthorityRegistry,
    VerifiedResourceCommitPermit,
)
from .broker import BrokerResourceDenied
from .contracts.broker import (
    BrokerOperationError,
    BrokerOperationVerifier,
    BrokerSessionContext,
    VerifiedBrokerOperation,
)
from .contracts.canonical import CanonicalizationError, canonicalize, parse_json
from .contracts.signatures import MessageAuthenticationError, MessageVerifier
from .contracts.validation import ContractValidationError, validate_message


PermitResolver = Callable[[str], Mapping[str, Any]]
ProvenanceCommitCheck = Callable[
    [
        VerifiedBrokerOperation,
        AuthorityLineage,
        list[dict[str, Any]],
    ],
    Mapping[str, object],
]


def _timestamp(value: object, field_name: str) -> float:
    if not isinstance(value, str):
        raise BrokerResourceDenied(f"commit permit {field_name} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BrokerResourceDenied(
            f"commit permit {field_name} is not a valid ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BrokerResourceDenied(
            f"commit permit {field_name} must include a timezone"
        )
    return parsed.timestamp()


def _digest_value(value: object, field_name: str) -> str:
    if not isinstance(value, Mapping) or set(value) != {"algorithm", "value"}:
        raise BrokerResourceDenied(f"commit permit {field_name} digest is malformed")
    digest = value.get("value")
    if (
        value.get("algorithm") != "sha-256"
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise BrokerResourceDenied(f"commit permit {field_name} digest is invalid")
    return digest


class InProcessBrokerWriteMediator:
    """Mediate one signed v1.0.0 write into the local logical resource registry.

    The adapter supports exactly one profile: operation write, resource type
    file, a local logical-resource version, no provider or opaque precondition
    digest, and a signed protocol commit permit. The signed idempotency key
    must equal operation_id. The existing registry inserts operation_id and
    the permit nonce in the same resource transaction, providing a durable
    one-use boundary for this restricted profile.

    A trusted provenance callback must resolve and verify every immutable
    provenance reference and return canonical metadata for persistence. A
    trusted permit resolver must fetch a signed permit envelope by reference.
    Neither callback is an authentication mechanism by itself; both are part
    of the broker's trusted computing base.

    This is not a network broker or IPC boundary. The transport adapter must
    authenticate the peer and establish BrokerSessionContext out of band.
    Host filesystem writes, remote providers, deletes, queries, sends and
    arbitrary execution are not implemented here.
    """

    def __init__(
        self,
        operation_verifier: BrokerOperationVerifier,
        permit_verifier: MessageVerifier,
        registry: SQLiteAuthorityRegistry,
        *,
        grant_issuer: str,
        grant_audience: str,
        permit_issuer: str,
        permit_audience: str,
        destination_id: str,
        permit_resolver: PermitResolver,
        provenance_commit_check: ProvenanceCommitCheck,
        clock: Callable[[], float],
        max_permit_bytes: int = 1_048_576,
        max_permit_lifetime_seconds: int = 30,
        clock_skew_seconds: int = 30,
    ) -> None:
        if not isinstance(operation_verifier, BrokerOperationVerifier):
            raise TypeError("operation_verifier must be a BrokerOperationVerifier")
        if not isinstance(permit_verifier, MessageVerifier):
            raise TypeError(
                "permit_verifier must be a separately configured MessageVerifier"
            )
        if not isinstance(registry, SQLiteAuthorityRegistry):
            raise TypeError(
                "registry must implement the PACA authority registry contract"
            )
        for name, value in (
            ("grant_issuer", grant_issuer),
            ("grant_audience", grant_audience),
            ("permit_issuer", permit_issuer),
            ("permit_audience", permit_audience),
            ("destination_id", destination_id),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"{name} must be a non-empty trusted configuration value"
                )
        if not callable(permit_resolver):
            raise TypeError("permit_resolver must be a trusted callable")
        if not callable(provenance_commit_check):
            raise TypeError("provenance_commit_check must be a trusted callable")
        if not callable(clock):
            raise TypeError("clock must be a trusted callable")
        if (
            isinstance(max_permit_bytes, bool)
            or not isinstance(max_permit_bytes, int)
            or not 1 <= max_permit_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("max_permit_bytes must be between 1 and 16 MiB")
        if (
            isinstance(max_permit_lifetime_seconds, bool)
            or not isinstance(max_permit_lifetime_seconds, int)
            or not 1 <= max_permit_lifetime_seconds <= 30
        ):
            raise ValueError("max_permit_lifetime_seconds must be between 1 and 30")
        if (
            isinstance(clock_skew_seconds, bool)
            or not isinstance(clock_skew_seconds, int)
            or not 0 <= clock_skew_seconds <= 300
        ):
            raise ValueError("clock_skew_seconds must be between 0 and 300")

        self._operation_verifier = operation_verifier
        self._permit_verifier = permit_verifier
        self._registry = registry
        self._grant_issuer = grant_issuer
        self._grant_audience = grant_audience
        self._permit_issuer = permit_issuer
        self._permit_audience = permit_audience
        self._destination_id = destination_id
        self._permit_resolver = permit_resolver
        self._provenance_commit_check = provenance_commit_check
        self._clock = clock
        self._max_permit_bytes = max_permit_bytes
        self._max_permit_lifetime_seconds = max_permit_lifetime_seconds
        self._clock_skew_seconds = clock_skew_seconds

    def write(
        self,
        message: Mapping[str, Any],
        *,
        session: BrokerSessionContext,
    ) -> dict[str, object]:
        """Verify, authorise and commit one bounded local logical-file write."""
        try:
            if not isinstance(message, Mapping):
                raise BrokerResourceDenied("broker message must be an object")
            grant_ref = message.get("authorization_grant_ref")
            if not isinstance(grant_ref, str) or not grant_ref:
                raise BrokerResourceDenied("broker message has no grant reference")

            operation = self._operation_verifier.verify(
                message,
                session=session,
                expected_grant_ref=grant_ref,
            )
            if operation.operation != "write" or operation.resource_type != "file":
                raise BrokerResourceDenied(
                    "this mediator supports local file writes only"
                )
            if operation.payload_digest is None:
                raise BrokerResourceDenied(
                    "write operation has no verified payload digest"
                )
            if operation.resource_version_id is None:
                raise BrokerResourceDenied(
                    "local write requires a resource version precondition"
                )
            if operation.idempotency_key is None:
                raise BrokerResourceDenied("write operation has no idempotency key")
            if operation.idempotency_key != operation.operation_id:
                raise BrokerResourceDenied(
                    "local write profile requires idempotency_key to equal operation_id"
                )

            envelope = parse_json(operation.canonical_message)
            resource = envelope["resource"]
            payload = envelope.get("payload")
            if not isinstance(payload, Mapping):
                raise BrokerResourceDenied("write payload must be a JSON object")
            if (
                resource.get("provider") is not None
                or resource.get("precondition_digest") is not None
            ):
                raise BrokerResourceDenied(
                    "provider and digest-precondition resource writes are unsupported"
                )
            resource_version = operation.resource_version_id
            try:
                expected_version = int(resource_version)
            except (TypeError, ValueError) as exc:
                raise BrokerResourceDenied(
                    "local resource version must be a non-negative decimal integer"
                ) from exc
            if expected_version < 0 or str(expected_version) != resource_version:
                raise BrokerResourceDenied(
                    "local resource version must use canonical decimal notation"
                )

            record = self._registry.assert_active(operation.authorization_grant_ref)
            if (
                record.issuer != self._grant_issuer
                or record.audience != self._grant_audience
                or record.principal != operation.principal_id
                or record.tenant != operation.tenant_id
                or record.task_id != operation.task_id
                or record.purpose != operation.purpose
            ):
                raise BrokerResourceDenied(
                    "resolved grant does not match trusted issuer, audience or identity"
                )
            if record.max_calls is None:
                raise BrokerResourceDenied(
                    "legacy grant lacks a persisted per-capability call ceiling"
                )

            permit_ref = operation.commit_permit_ref
            if not isinstance(permit_ref, str) or not permit_ref:
                raise BrokerResourceDenied(
                    "write operation has no commit permit reference"
                )
            try:
                permit_message_input = self._permit_resolver(permit_ref)
            except Exception as exc:
                raise BrokerResourceDenied(
                    "trusted commit-permit resolution failed"
                ) from exc
            if not isinstance(permit_message_input, Mapping):
                raise BrokerResourceDenied(
                    "commit-permit resolver returned a non-object"
                )

            try:
                permit_bytes = canonicalize(dict(permit_message_input))
                if len(permit_bytes) > self._max_permit_bytes:
                    raise BrokerResourceDenied(
                        "commit permit exceeds the configured size limit"
                    )
                permit_message = parse_json(permit_bytes)
                validate_message(permit_message)
                if permit_message.get("message_type") != "paca.commit-permit.v1":
                    raise BrokerResourceDenied(
                        "resolved message is not a v1.0.0 commit permit"
                    )
                verified_permit = self._permit_verifier.verify(permit_message)
            except BrokerResourceDenied:
                raise
            except (
                CanonicalizationError,
                ContractValidationError,
                MessageAuthenticationError,
                TypeError,
                ValueError,
            ) as exc:
                raise BrokerResourceDenied(
                    "commit permit failed canonical, schema or signature verification"
                ) from exc

            now = self._clock()
            if (
                isinstance(now, bool)
                or not isinstance(now, (int, float))
                or not math.isfinite(now)
            ):
                raise BrokerResourceDenied("trusted commit-permit clock is invalid")
            created_at = _timestamp(permit_message.get("created_at"), "created_at")
            issued_at = _timestamp(permit_message.get("issued_at"), "issued_at")
            expires_at = _timestamp(permit_message.get("expires_at"), "expires_at")
            if (
                verified_permit.issuer != self._permit_issuer
                or verified_permit.audience != self._permit_audience
                or permit_message.get("permit_id") != permit_ref
                or permit_message.get("grant_id") != record.authority_id
                or permit_message.get("operation_id") != operation.operation_id
                or not isinstance(permit_message.get("subject"), Mapping)
                or permit_message["subject"].get("id") != operation.principal_id
                or permit_message.get("tenant_id") != operation.tenant_id
                or permit_message.get("task_id") != operation.task_id
                or permit_message.get("purpose") != operation.purpose
                or permit_message.get("action") != "write_file"
                or permit_message.get("destination") != self._destination_id
                or permit_message.get("policy_epoch") != record.policy_epoch
                or permit_message.get("single_use") is not True
                or permit_message.get("idempotency_key") != operation.idempotency_key
            ):
                raise BrokerResourceDenied(
                    "commit permit does not match grant, operation or destination"
                )

            permit_resource = permit_message.get("resource")
            if not isinstance(permit_resource, Mapping):
                raise BrokerResourceDenied("commit permit resource is malformed")
            if (
                permit_resource.get("resource_type") != "file"
                or permit_resource.get("resource_id") != operation.resource_id
                or permit_resource.get("version_id") != resource_version
                or permit_resource.get("provider") is not None
                or permit_resource.get("precondition_digest") is not None
                or permit_message.get("resource_version_precondition")
                != resource_version
            ):
                raise BrokerResourceDenied(
                    "commit permit resource/version precondition mismatch"
                )

            arguments_digest = _digest_value(
                permit_message.get("arguments_digest"),
                "arguments_digest",
            )
            payload_digest = _digest_value(
                permit_message.get("payload_digest"),
                "payload_digest",
            )
            if (
                arguments_digest != operation.intent_digest
                or payload_digest != operation.payload_digest
            ):
                raise BrokerResourceDenied(
                    "commit permit request/payload digest does not match the write"
                )
            if (
                issued_at > now + self._clock_skew_seconds
                or created_at > now + self._clock_skew_seconds
                or abs(created_at - issued_at) > self._clock_skew_seconds
                or expires_at <= now
                or expires_at <= issued_at
                or expires_at - issued_at > self._max_permit_lifetime_seconds
            ):
                raise BrokerResourceDenied(
                    "commit permit is expired or outside the configured validity window"
                )

            provenance_refs = envelope.get("provenance_refs")
            if not isinstance(provenance_refs, list) or not provenance_refs:
                raise BrokerResourceDenied("write requires provenance references")
            try:
                provenance_metadata = self._provenance_commit_check(
                    operation,
                    record,
                    provenance_refs,
                )
                if not isinstance(provenance_metadata, Mapping):
                    raise TypeError("provenance callback must return a JSON object")
                metadata_bytes = canonicalize(dict(provenance_metadata))
                if len(metadata_bytes) > 65_536:
                    raise ValueError("provenance commit metadata exceeds 64 KiB")
                provenance_metadata = parse_json(metadata_bytes)
            except Exception as exc:
                raise BrokerResourceDenied(
                    "trusted provenance commit evaluation failed"
                ) from exc

            # The internal projection preserves the legacy registry binding:
            # the protocol permit issuer is independently checked above, while
            # the registry's permit.issuer field names the immutable grant issuer.
            internal_permit = VerifiedResourceCommitPermit(
                nonce=permit_message["nonce"],
                issuer=record.issuer,
                key_id=verified_permit.key_id,
                audience=verified_permit.audience,
                authority_id=record.authority_id,
                tenant=record.tenant,
                task_id=record.task_id,
                purpose=record.purpose,
                policy_epoch=record.policy_epoch,
                issued_at=int(issued_at),
                expires_at=int(expires_at),
                max_calls=record.max_calls,
                action="write_file",
                resource=operation.resource_id,
                request_digest=operation.intent_digest,
                payload_digest=operation.payload_digest,
            )
            return self._registry.commit_fenced_resource_write(
                internal_permit,
                payload,
                access_receipt=operation.registry_access_receipt(),
                provenance_metadata=provenance_metadata,
                protocol_payload_digest=True,
                expected_resource_version=expected_version,
                expected_principal=operation.principal_id,
            )
        except BrokerResourceDenied:
            raise
        except (
            BrokerOperationError,
            AuthorityRegistryError,
            CanonicalizationError,
            ContractValidationError,
            MessageAuthenticationError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise BrokerResourceDenied(
                "broker write failed verification or atomic resource enforcement"
            ) from exc


__all__ = [
    "InProcessBrokerWriteMediator",
    "PermitResolver",
    "ProvenanceCommitCheck",
]
