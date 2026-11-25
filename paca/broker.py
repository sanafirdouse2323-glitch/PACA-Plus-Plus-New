"""Narrow in-process broker mediation for protocol-bound logical file reads.

This module is a reference integration, not an authenticated network service or
process boundary. A trusted ingress must construct BrokerSessionContext only
after authenticating the peer and binding its principal to the live channel.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .authority import AuthorityLineage
from .authority_registry import (
    AuthorityRegistryError,
    SQLiteAuthorityRegistry,
    VerifiedResourceCommitPermit,
)
from .contracts.broker import (
    BrokerOperationError,
    BrokerOperationVerifier,
    BrokerSessionContext,
    VerifiedBrokerOperation,
)
from .contracts.canonical import canonicalize, parse_json
from .contracts.permits import (
    CommitPermitError,
    ProtocolCommitPermitVerifier,
    VerifiedProtocolCommitPermit,
)


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
ProvenanceCommitCheck = Callable[
    [
        VerifiedBrokerOperation,
        AuthorityLineage,
        VerifiedProtocolCommitPermit,
        Mapping[str, object],
        tuple[Mapping[str, object], ...],
    ],
    Mapping[str, object],
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
        commit_permit_verifier: ProtocolCommitPermitVerifier | None = None,
        commit_permit_issuer: str | None = None,
        commit_permit_audience: str | None = None,
        resource_destination: str = "paca.local.resource-registry",
        provenance_commit_check: ProvenanceCommitCheck | None = None,
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
        if commit_permit_verifier is not None and not isinstance(
            commit_permit_verifier, ProtocolCommitPermitVerifier
        ):
            raise TypeError(
                "commit_permit_verifier must be a configured ProtocolCommitPermitVerifier"
            )
        if commit_permit_verifier is not None:
            for name, value in (
                ("commit_permit_issuer", commit_permit_issuer),
                ("commit_permit_audience", commit_permit_audience),
            ):
                if not isinstance(value, str) or not value:
                    raise ValueError(
                        f"{name} must be configured when commit permits are enabled"
                    )
        if not isinstance(resource_destination, str) or not resource_destination:
            raise ValueError("resource_destination must be a non-empty trusted value")
        if provenance_commit_check is not None and not callable(
            provenance_commit_check
        ):
            raise TypeError("provenance_commit_check must be a trusted callable")
        self._verifier = verifier
        self._registry = registry
        self._grant_issuer = grant_issuer
        self._grant_audience = grant_audience
        self._provenance_release_check = provenance_release_check
        self._commit_permit_verifier = commit_permit_verifier
        self._commit_permit_issuer = commit_permit_issuer
        self._commit_permit_audience = commit_permit_audience
        self._resource_destination = resource_destination
        self._provenance_commit_check = provenance_commit_check

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

    def write(
        self,
        message: Mapping[str, Any],
        commit_permit_message: Mapping[str, Any],
        *,
        session: BrokerSessionContext,
    ) -> dict[str, object]:
        """Commit one signed local-file write through a one-use protocol permit.

        The permit is checked against the exact broker intent, payload, resource,
        subject, grant, policy epoch, destination and idempotency key. The
        registry rechecks current authority and consumes the permit, broker
        receipt, quota and resource version in one local database transaction.
        Remote providers and all non-file mutation types remain unsupported.
        """
        if (
            self._commit_permit_verifier is None
            or self._commit_permit_issuer is None
            or self._commit_permit_audience is None
            or self._provenance_commit_check is None
        ):
            raise BrokerResourceDenied(
                "broker write path is disabled until permit and provenance policy are configured"
            )
        try:
            operation = self._verifier.verify(
                message,
                session=session,
                expected_grant_ref=(
                    message.get("authorization_grant_ref")
                    if isinstance(message, Mapping)
                    else ""
                ),
            )
            if operation.operation != "write":
                raise BrokerResourceDenied(
                    "this mediator supports write operations only on this path"
                )
            if operation.resource_type != "file":
                raise BrokerResourceDenied(
                    "this mediator supports local file writes only"
                )
            if (
                operation.commit_permit_ref is None
                or operation.idempotency_key is None
                or operation.payload_digest is None
            ):
                raise BrokerResourceDenied(
                    "write operation is missing permit, idempotency or payload binding"
                )

            request = parse_json(operation.canonical_message)
            resource = request["resource"]
            payload = request["payload"]
            provenance_refs = request["provenance_refs"]
            if not isinstance(resource, Mapping) or not isinstance(payload, Mapping):
                raise BrokerResourceDenied("write resource or payload is malformed")
            if not isinstance(provenance_refs, list) or not provenance_refs:
                raise BrokerResourceDenied(
                    "write operation requires explicit provenance references"
                )
            version_id = resource.get("version_id")
            if (
                not isinstance(version_id, str)
                or not version_id.isascii()
                or not version_id.isdecimal()
                or str(int(version_id)) != version_id
                or int(version_id) > 9_007_199_254_740_991
            ):
                raise BrokerResourceDenied(
                    "local file version_id must be a canonical non-negative decimal registry version"
                )
            if (
                resource.get("provider") is not None
                or resource.get("precondition_digest") is not None
            ):
                raise BrokerResourceDenied(
                    "provider-backed or digest-precondition writes are unsupported"
                )

            permit = self._commit_permit_verifier.verify(commit_permit_message)
            if permit.permit_id != operation.commit_permit_ref:
                raise BrokerResourceDenied(
                    "commit permit ID does not match the signed broker reference"
                )
            if (
                permit.issuer != self._commit_permit_issuer
                or permit.audience != self._commit_permit_audience
                or permit.grant_id != operation.authorization_grant_ref
                or permit.operation_id != operation.operation_id
                or permit.subject_kind != operation.principal_kind
                or permit.subject_id != operation.principal_id
                or permit.tenant_id != operation.tenant_id
                or permit.task_id != operation.task_id
                or permit.purpose != operation.purpose
                or permit.action != "write_file"
                or permit.destination != self._resource_destination
                or permit.arguments_digest != operation.intent_digest
                or permit.payload_digest != operation.payload_digest
                or permit.idempotency_key != operation.idempotency_key
                or permit.resource_version_precondition != version_id
            ):
                raise BrokerResourceDenied(
                    "commit permit does not bind the exact broker request"
                )
            permit_envelope = parse_json(permit.canonical_message)
            if permit_envelope.get("resource") != resource:
                raise BrokerResourceDenied(
                    "commit permit resource/version does not match the broker request"
                )

            record = self._registry.assert_active(operation.authorization_grant_ref)
            if (
                record.issuer != self._grant_issuer
                or record.audience != self._grant_audience
                or record.principal != operation.principal_id
                or record.tenant != operation.tenant_id
                or record.task_id != operation.task_id
                or record.purpose != operation.purpose
                or record.max_calls is None
                or record.policy_epoch != permit.policy_epoch
                or self._registry.current_epoch() != permit.policy_epoch
            ):
                raise BrokerResourceDenied(
                    "resolved grant does not match the current trusted write authority"
                )

            try:
                provenance_metadata = self._provenance_commit_check(
                    operation,
                    record,
                    permit,
                    payload,
                    tuple(provenance_refs),
                )
            except Exception as exc:
                raise BrokerResourceDenied(
                    "trusted provenance-commit evaluation failed"
                ) from exc
            if not isinstance(provenance_metadata, Mapping):
                raise BrokerResourceDenied(
                    "trusted provenance-commit evaluation returned no metadata"
                )

            registry_permit = VerifiedResourceCommitPermit(
                nonce=permit.nonce,
                issuer=permit.issuer,
                key_id=permit.key_id,
                audience=permit.audience,
                authority_id=permit.grant_id,
                tenant=permit.tenant_id,
                task_id=permit.task_id,
                purpose=permit.purpose,
                policy_epoch=permit.policy_epoch,
                issued_at=permit.issued_at,
                expires_at=permit.expires_at,
                max_calls=record.max_calls,
                action=permit.action,
                resource=operation.resource_id,
                request_digest=permit.arguments_digest,
                payload_digest=permit.payload_digest,
                permit_id=permit.permit_id,
                idempotency_key=permit.idempotency_key,
            )
            return self._registry.commit_fenced_resource_write(
                registry_permit,
                payload,
                access_receipt=operation.registry_access_receipt(),
                provenance_metadata=provenance_metadata,
                protocol_payload_digest=True,
                expected_resource_version=int(version_id),
                expected_principal=operation.principal_id,
            )
        except BrokerResourceDenied:
            raise
        except (
            BrokerOperationError,
            CommitPermitError,
            AuthorityRegistryError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise BrokerResourceDenied(
                "broker write failed verification or atomic resource enforcement"
            ) from exc


class InProcessBrokerMediator(InProcessBrokerReadMediator):
    """Read/write local-resource mediator; unsupported operations fail closed."""


__all__ = [
    "BrokerResourceDenied",
    "InProcessBrokerMediator",
    "InProcessBrokerReadMediator",
    "ProvenanceCommitCheck",
    "ProvenanceReleaseCheck",
]
