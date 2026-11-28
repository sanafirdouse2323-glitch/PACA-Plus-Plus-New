"""Authenticated inter-agent message envelopes for PACA++ New.

The codec binds message bytes to immutable provenance and active sender/recipient
authority. It is deliberately separate from memory value storage and policy.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Iterable
from typing import Any

from .authority import grant_pattern_is_subset
from .authority_runtime import AuthorityRegistryError, HMACCapabilityAuthority
from .durable import SQLiteProvenanceRepository
from .memory import MemoryAccessDenied, TrustedMemoryAdapter, canonical_value_bytes
from .provenance import Arg, Label


def _b64encode(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    import base64

    return base64.b64decode(
        value + ("=" * (-len(value) % 4)),
        altchars=b"-_",
        validate=True,
    )


class HMACAgentMessageCodec:
    """Sign inter-agent message envelopes while preserving Arg labels and lineage."""

    def __init__(
        self,
        key: bytes,
        authority: HMACCapabilityAuthority,
        repository: SQLiteProvenanceRepository,
        *,
        memory: TrustedMemoryAdapter,
        clock=time.time,
    ) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("message HMAC key must contain at least 32 bytes")
        if (
            not isinstance(memory, TrustedMemoryAdapter)
            or memory.repository is not repository
            or memory.authority is not authority
        ):
            raise ValueError(
                "message codec, memory adapter and authority must share the same trusted state"
            )
        self._key = bytes(key)
        self.authority = authority
        self.registry = authority.registry
        self.repository = repository
        self.memory = memory
        self.clock = clock

    def _assert_payload_matches_lineage(
        self,
        value: Any,
        lineage_refs: Iterable[str],
    ) -> None:
        """Require the exact message value to match one immutable lineage node.

        A set of source references alone does not prove that a caller-supplied
        value was derived from those sources. Requiring one persisted leaf node
        binds the transmitted bytes to its content digest and parent DAG. Callers
        must persist transformed values through TrustedMemoryAdapter first.
        """
        refs = tuple(lineage_refs)
        if len(refs) != 1 or not isinstance(refs[0], str) or not refs[0]:
            raise MemoryAccessDenied(
                "inter-agent payload must reference one versioned value bound to its exact digest"
            )
        node = self.repository.get_node(refs[0])
        if node is None:
            raise MemoryAccessDenied("inter-agent payload references missing lineage")
        try:
            digest = hashlib.sha256(canonical_value_bytes(value)).hexdigest()
        except (TypeError, ValueError) as exc:
            raise MemoryAccessDenied(
                "inter-agent payload is not canonical JSON bound to its lineage"
            ) from exc
        if not hmac.compare_digest(digest, node.content_digest):
            raise MemoryAccessDenied(
                "inter-agent payload bytes do not match their immutable lineage digest"
            )

    def seal(
        self,
        payload: Arg,
        *,
        sender: str,
        recipient: str,
        capability_token: str,
    ) -> str:
        if (
            not isinstance(payload, Arg)
            or not payload.lineage_refs
            or payload.lineage_incomplete
        ):
            raise MemoryAccessDenied(
                "inter-agent messages require complete explicit provenance"
            )
        signed = self.authority.verify(capability_token)
        authority = signed.capability.authority_lineage
        if authority is None:
            raise MemoryAccessDenied(
                "message sender capability has no authority lineage"
            )
        authority_id = authority.authority_id
        if sender != authority.principal or not recipient:
            raise MemoryAccessDenied(
                "message sender does not match authenticated authority"
            )
        if payload.label.tenant_unknown or any(
            t != authority.tenant for t in payload.label.tenants
        ):
            raise MemoryAccessDenied(
                "message provenance crosses or obscures the sender tenant"
            )
        if payload.label.sensitivity > 0 and not payload.label.tenants:
            raise MemoryAccessDenied("sensitive message has no tenant provenance")
        send_targets = dict(authority.grants).get("send_agent_message", ())
        if not any(
            grant_pattern_is_subset(recipient, pattern) for pattern in send_targets
        ):
            raise MemoryAccessDenied(
                "sender capability does not authorise this recipient"
            )
        # A valid message-send grant does not imply a right to read the data.
        # Re-run the same current memory authority and application policy used
        # for ordinary reads before transferring the persisted value.
        self.memory.authorize_argument(
            payload,
            purpose=authority.purpose,
            capability_token=capability_token,
        )
        for node_id in payload.lineage_refs:
            node = self.repository.get_node(node_id)
            if node is None:
                raise MemoryAccessDenied("message references missing lineage")
            ancestry = self.repository.ancestors(node_id)
            if self.repository.revoked_nodes(item.node_id for item in ancestry):
                raise MemoryAccessDenied("message references revoked lineage")
            for item in ancestry:
                if item.purpose is not None and item.purpose != authority.purpose:
                    raise MemoryAccessDenied(
                        "message source purpose does not match sender authority"
                    )
                if item.label.tenant_unknown or any(
                    tenant != authority.tenant for tenant in item.label.tenants
                ):
                    raise MemoryAccessDenied(
                        "message source lineage crosses or obscures sender tenant"
                    )
                if (
                    item.label.integrity == "untrusted"
                    and payload.label.integrity != "untrusted"
                ):
                    raise MemoryAccessDenied(
                        "message attempts to upgrade source integrity"
                    )
                if payload.label.sensitivity < item.label.sensitivity:
                    raise MemoryAccessDenied("message attempts to lower sensitivity")
                if not item.label.origins.issubset(payload.label.origins):
                    raise MemoryAccessDenied("message attempts to erase source origins")
                if not item.label.tenants.issubset(payload.label.tenants):
                    raise MemoryAccessDenied(
                        "message attempts to erase source tenant lineage"
                    )
                for bound_authority in self.repository.authority_ids_for_node(
                    item.node_id
                ):
                    self.registry.assert_active(bound_authority)
        try:
            self.registry.consume_effect(
                authority_id,
                max_calls=signed.capability.max_calls,
            )
            self.registry.assert_active(authority_id)
        except AuthorityRegistryError as exc:
            raise MemoryAccessDenied(
                "message send budget exhausted or authority revoked"
            ) from exc
        label = {
            "integrity": payload.label.integrity,
            "sensitivity": payload.label.sensitivity,
            "tenants": sorted(payload.label.tenants),
            "tenant_unknown": payload.label.tenant_unknown,
            "origins": sorted(payload.label.origins),
        }
        body = {
            "version": 1,
            "message_id": secrets.token_urlsafe(18),
            "sender": sender,
            "recipient": recipient,
            "task_id": authority.task_id,
            "purpose": authority.purpose,
            "authority_id": authority_id,
            "issued_at": int(self.clock()),
            "value": payload.value,
            "label": label,
            "lineage_refs": sorted(payload.lineage_refs),
        }
        encoded = canonical_value_bytes(body)
        signature = hmac.new(self._key, encoded, hashlib.sha256).digest()
        return _b64encode(encoded) + "." + _b64encode(signature)

    def open(self, token: str, *, recipient_token: str) -> Arg:
        try:
            recipient_capability = self.authority.verify(recipient_token).capability
            recipient_record = recipient_capability.authority_lineage
            recipient = recipient_capability.principal
            if recipient_record is None:
                raise ValueError("recipient capability has no authority lineage")
            if not isinstance(token, str) or len(token) > 1_000_000:
                raise ValueError("invalid message size")
            body_part, signature_part = token.split(".")
            encoded = _b64decode(body_part)
            supplied = _b64decode(signature_part)
            expected = hmac.new(self._key, encoded, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, supplied):
                raise ValueError("message signature mismatch")
            body = json.loads(encoded)
            if not isinstance(body, dict) or body.get("version") != 1:
                raise ValueError("unsupported message envelope")
            message_id = body.get("message_id")
            if (
                not isinstance(message_id, str)
                or not message_id
                or len(message_id) > 256
            ):
                raise ValueError(
                    "message identifier is missing or exceeds the supported length"
                )
            if body.get("recipient") != recipient:
                raise ValueError("message recipient mismatch")
            # The envelope MAC and recipient capability have both been verified.
            # Short-circuit a sequential replay using the composite receipt index
            # before sender-authority lookup and provenance-DAG traversal. This
            # check is not the concurrency boundary: consume_message() below still
            # performs the unique receipt insert and quota charge atomically.
            if self.registry.has_message_receipt(
                recipient_record.principal,
                recipient_record.tenant,
                recipient_record.task_id,
                message_id,
            ):
                # Preserve the explicit denial reason; the outer parser-error
                # handler intentionally normalizes malformed-envelope failures.
                raise MemoryAccessDenied("inter-agent message replay was rejected")
            if int(body.get("issued_at", -1)) > int(self.clock()) + 30:
                raise ValueError("message issuance time is invalid")
            authority_id = body.get("authority_id")
            authority = self.registry.assert_active(str(authority_id))
            if (
                body.get("sender") != authority.principal
                or body.get("task_id") != authority.task_id
                or body.get("purpose") != authority.purpose
                or recipient_record.tenant != authority.tenant
                or recipient_record.task_id != authority.task_id
                or recipient_record.purpose != authority.purpose
            ):
                raise ValueError("message sender, recipient or task authority mismatch")
            send_targets = dict(authority.grants).get("send_agent_message", ())
            if not any(
                grant_pattern_is_subset(recipient, pattern) for pattern in send_targets
            ):
                raise ValueError("sender capability does not authorise this recipient")
            receive_targets = dict(recipient_record.grants).get(
                "receive_agent_message", ()
            )
            if not any(
                grant_pattern_is_subset(authority.principal, pattern)
                for pattern in receive_targets
            ):
                raise ValueError("recipient capability does not authorise this sender")
            label_data = body.get("label")
            refs = body.get("lineage_refs")
            if (
                not isinstance(label_data, dict)
                or not isinstance(refs, list)
                or not refs
                or any(not isinstance(ref, str) or not ref for ref in refs)
            ):
                raise ValueError("message provenance is missing")
            self._assert_payload_matches_lineage(body["value"], refs)
            label = Label(
                integrity=label_data["integrity"],
                sensitivity=label_data["sensitivity"],
                tenant=None,
                tenants=frozenset(label_data["tenants"]),
                tenant_unknown=label_data["tenant_unknown"],
                origins=frozenset(label_data["origins"]),
            )
            if label.tenant_unknown or any(
                t != authority.tenant for t in label.tenants
            ):
                raise ValueError(
                    "message provenance crosses or obscures the recipient authority tenant"
                )
            if label.sensitivity > 0 and not label.tenants:
                raise ValueError("sensitive message has no tenant provenance")
            received = Arg(body["value"], label, frozenset(refs), False)
            for node_id in refs:
                node = self.repository.get_node(node_id)
                if node is None:
                    raise ValueError("message lineage is missing")
                ancestry = self.repository.ancestors(node_id)
                if self.repository.revoked_nodes(item.node_id for item in ancestry):
                    raise ValueError("message lineage is revoked")
                for item in ancestry:
                    if item.purpose is not None and item.purpose != authority.purpose:
                        raise ValueError("message lineage purpose mismatch")
                    if item.label.tenant_unknown or any(
                        tenant != authority.tenant for tenant in item.label.tenants
                    ):
                        raise ValueError("message source lineage tenant mismatch")
                    for bound_authority in self.repository.authority_ids_for_node(
                        item.node_id
                    ):
                        self.registry.assert_active(bound_authority)
                    if (
                        item.label.integrity == "untrusted"
                        and label.integrity != "untrusted"
                    ):
                        raise ValueError("message integrity exceeds its source lineage")
                    if (
                        label.sensitivity < item.label.sensitivity
                        or not item.label.origins.issubset(label.origins)
                        or not item.label.tenants.issubset(label.tenants)
                    ):
                        raise ValueError(
                            "message label is less restrictive than source lineage"
                        )
            try:
                # Consume the replay receipt before charging a memory read. A
                # duplicate delivery must not drain the recipient's memory-read
                # budget on every rejected replay attempt.
                self.registry.consume_message(
                    recipient_capability.cap_id,
                    message_id,
                    max_calls=recipient_capability.max_calls,
                )
            except AuthorityRegistryError as exc:
                raise MemoryAccessDenied(
                    "message replay, receive budget exhaustion or revoked authority was rejected"
                ) from exc
            # A valid receipt does not confer memory access. The recipient must
            # independently pass current mem_read scope and application policy.
            self.memory.authorize_argument(
                received,
                purpose=recipient_record.purpose,
                capability_token=recipient_token,
            )
            return received
        except (
            ValueError,
            TypeError,
            KeyError,
            json.JSONDecodeError,
            AuthorityRegistryError,
        ) as exc:
            raise MemoryAccessDenied(
                "inter-agent message authentication or provenance validation failed"
            ) from exc


# Preserve the original qualified name for imports, reprs and pickle references.
HMACAgentMessageCodec.__module__ = "paca.memory"

__all__ = ["HMACAgentMessageCodec"]
