"""Narrow in-process broker mediation for protocol-bound logical file reads.

This module is a reference integration, not an authenticated network service or
process boundary. A trusted ingress must construct BrokerSessionContext only
after authenticating the peer and binding its principal to the live channel.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .authority import AuthorityLineage
from .authority_registry import AuthorityRegistryError, SQLiteAuthorityRegistry
from .contracts.broker import (
    BrokerOperationError,
    BrokerOperationVerifier,
    BrokerSessionContext,
    VerifiedBrokerOperation,
)
from .contracts.canonical import parse_json


class BrokerResourceDenied(PermissionError):
    """A brokered resource operation failed authentication or enforcement."""


ProvenanceReleaseCheck = Callable[
    [
        VerifiedBrokerOperation,
        AuthorityLineage,
        Mapping[str, object],
    ],
    bool,
]


class InProcessBrokerReadMediator:
    """Mediate v1.0.0 logical file reads through the existing authority registry.

    The mediator supports exactly one operation: a logical `read` of a local
    `file` resource. It resolves the signed grant reference against the current
    persistent authority registry; binds principal, tenant, task, purpose,
    issuer and audience; requires a persisted per-capability call limit; and
    passes the verified nonce receipt and signed read-byte ceiling into the
    registry's atomic read transaction.

    A mandatory trusted provenance-release callback must approve the returned
    value and provenance metadata before the mediator returns any content.
    Callback denial or failure occurs after the registry transaction, so the
    request receipt and quota remain consumed. This is intentionally fail-closed.

    Writes, deletes, queries, sends, execution, provider resources, version
    selectors and field projections remain rejected. A separate write method
    accepts only local file writes with a separately authenticated v1.0.0
    commit permit and trusted provenance-commit callback. This remains an
    in-process reference mediator, not an authenticated transport/IPC boundary.
    """

    def __init__(
        self,
        verifier: BrokerOperationVerifier,
        registry: SQLiteAuthorityRegistry,
        *,
        grant_issuer: str,
        grant_audience: str,
        provenance_release_check: ProvenanceReleaseCheck,
    ) -> None:
        if not isinstance(verifier, BrokerOperationVerifier):
            raise TypeError("verifier must be a configured BrokerOperationVerifier")
        if not isinstance(registry, SQLiteAuthorityRegistry):
            raise TypeError("registry must implement the authority registry contract")
        for name, value in (
            ("grant_issuer", grant_issuer),
            ("grant_audience", grant_audience),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"{name} must be a non-empty trusted configuration value"
                )
        if not callable(provenance_release_check):
            raise TypeError("provenance_release_check must be a trusted callable")
        self._verifier = verifier
        self._registry = registry
        self._grant_issuer = grant_issuer
        self._grant_audience = grant_audience
        self._provenance_release_check = provenance_release_check

    def read(
        self,
        message: Mapping[str, Any],
        *,
        session: BrokerSessionContext,
    ) -> dict[str, object]:
        """Verify, authorise and perform one bounded logical file read."""
        try:
            if not isinstance(message, Mapping):
                raise BrokerResourceDenied("broker message must be an object")
            grant_ref = message.get("authorization_grant_ref")
            if not isinstance(grant_ref, str) or not grant_ref:
                raise BrokerResourceDenied("broker message has no grant reference")

            operation = self._verifier.verify(
                message,
                session=session,
                expected_grant_ref=grant_ref,
            )
            if operation.operation != "read":
                raise BrokerResourceDenied(
                    "this mediator supports read operations only"
                )
            if operation.resource_type != "file":
                raise BrokerResourceDenied(
                    "this mediator supports local file resources only"
                )
            if operation.max_bytes is None:
                raise BrokerResourceDenied(
                    "broker read has no verified disclosure-byte ceiling"
                )

            envelope = parse_json(operation.canonical_message)
            resource = envelope["resource"]
            constraints = envelope["read_constraints"]
            if (
                resource.get("provider") is not None
                or resource.get("version_id") is not None
                or resource.get("precondition_digest") is not None
                or constraints.get("expected_version") is not None
                or "fields" in constraints
            ):
                raise BrokerResourceDenied(
                    "requested provider, version or field-selection semantics are unsupported"
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
                    "resolved grant does not match trusted issuer, audience or session identity"
                )
            if record.max_calls is None:
                raise BrokerResourceDenied(
                    "legacy grant lacks a persisted per-capability call ceiling"
                )

            result = self._registry.read_fenced_resource(
                authority_id=record.authority_id,
                tenant=operation.tenant_id,
                task_id=operation.task_id,
                purpose=operation.purpose,
                resource=operation.resource_id,
                max_calls=record.max_calls,
                access_receipt=operation.registry_access_receipt(),
                expected_principal=operation.principal_id,
                max_bytes=operation.max_bytes,
            )
            try:
                released = self._provenance_release_check(
                    operation,
                    record,
                    result,
                )
            except Exception as exc:
                raise BrokerResourceDenied(
                    "trusted provenance-release evaluation failed"
                ) from exc
            if released is not True:
                raise BrokerResourceDenied(
                    "resource provenance or disclosure policy denied the read"
                )

            # The registry transaction linearizes the resource snapshot and its
            # replay/quota receipt. Revalidate the grant after the potentially
            # slow release callback so a revocation during that callback blocks
            # the final disclosure. This is the last in-process authorization
            # check before the result leaves the mediator.
            current_record = self._registry.assert_active(record.authority_id)
            if current_record != record:
                raise BrokerResourceDenied(
                    "resolved grant changed before resource disclosure"
                )
            return dict(result)
        except BrokerResourceDenied:
            raise
        except (
            BrokerOperationError,
            AuthorityRegistryError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise BrokerResourceDenied(
                "broker read operation failed verification or authority enforcement"
            ) from exc


class InProcessBrokerMediator(InProcessBrokerReadMediator):
    """Compatibility name for the read-only in-process broker mediator."""


__all__ = [
    "BrokerResourceDenied",
    "InProcessBrokerReadMediator",
    "ProvenanceReleaseCheck",
]
