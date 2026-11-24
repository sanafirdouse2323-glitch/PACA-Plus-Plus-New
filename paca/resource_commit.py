"""Resource-side commit fencing for local PACA reference deployments.

The adapter delegates the final mutation to the configured authority registry.
SQLite uses one local transaction; PostgreSQL uses the registry's serialized
single-primary transaction. Both are logical resource stores, not remote-provider
transaction protocols or proof of host-level filesystem mediation.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .authority_runtime import HMACCapabilityAuthority
from .memory import canonical_value_bytes
from .runtime import ACTIONS, Request


class ResourceCommitDenied(PermissionError):
    """A resource mutation failed its signed permit or active-state checks."""


class FencedResourceExecutor:
    """Commit supported local mutations through the configured registry fence.

    This executor supports the currently mapped `write_file` and `mem_write`
    actions. SQLite stores the logical resource and authority state in one local
    transaction. PostgreSQL uses its registry-level transaction lock to serialize
    the logical write against revocation on one shared primary. Neither backend
    writes to a real filesystem or mediates a remote provider API.
    """

    SUPPORTED_ACTIONS = frozenset({"write_file", "mem_write"})

    def __init__(self, authority: HMACCapabilityAuthority) -> None:
        # Ed25519CapabilityAuthority deliberately subclasses the common
        # authority contract: it can verify permits with a public key, while
        # issuance remains confined to a separately configured private-key
        # authority instance.
        if not isinstance(authority, HMACCapabilityAuthority):
            raise TypeError(
                "authority must implement the PACA capability verification contract"
            )
        self.authority = authority
        self.registry = authority.registry

    def _verify_request(
        self,
        request: Request,
        permit_token: str,
    ) -> tuple[Any, dict[str, Any]]:
        if not isinstance(request, Request):
            raise TypeError("fenced resource executor requires a typed PACA Request")
        if request.action not in self.SUPPORTED_ACTIONS:
            raise ResourceCommitDenied(
                "resource action has no local fenced commit adapter"
            )
        spec = ACTIONS.get(request.action)
        if not isinstance(spec, dict):
            raise ResourceCommitDenied(
                "resource action is missing its trusted action mapping"
            )
        target_name = spec.get("target")
        payload_names = spec.get("payload", ())
        if (
            not isinstance(target_name, str)
            or not target_name
            or not isinstance(payload_names, (list, tuple))
            or not payload_names
        ):
            raise ResourceCommitDenied(
                "resource action mapping does not define a target and payload"
            )
        target_argument = request.args.get(target_name)
        if target_argument is None or not isinstance(target_argument.value, str):
            raise ResourceCommitDenied(
                "fenced resource target must be a typed string argument"
            )
        payload: dict[str, Any] = {}
        for name in payload_names:
            argument = request.args.get(name)
            if argument is None:
                raise ResourceCommitDenied(
                    "fenced resource payload argument is missing"
                )
            payload[name] = argument.value
        try:
            payload_digest = hashlib.sha256(canonical_value_bytes(payload)).hexdigest()
        except (TypeError, ValueError) as exc:
            raise ResourceCommitDenied(
                "fenced resource payload is not canonical JSON"
            ) from exc

        try:
            permit = self.authority.verify_resource_commit_permit(permit_token)
        except Exception as exc:
            raise ResourceCommitDenied(
                "resource commit permit authentication failed"
            ) from exc
        record = request.cap.authority_lineage
        if record is None or (
            permit.authority_id != record.authority_id
            or permit.tenant != record.tenant
            or permit.task_id != record.task_id
            or permit.purpose != record.purpose
            or permit.action != request.action
            or permit.resource != target_argument.value
            or permit.request_digest != request.digest
            or not hmac.compare_digest(permit.payload_digest, payload_digest)
        ):
            raise ResourceCommitDenied(
                "resource request does not match its signed commit permit"
            )
        return permit, payload

    def execute_authorized(self, request: Request, permit_token: str) -> dict[str, Any]:
        """Perform a local mutation under the resource database commit fence."""
        permit, payload = self._verify_request(request, permit_token)
        try:
            return self.registry.commit_fenced_resource_write(permit, payload)
        except Exception as exc:
            raise ResourceCommitDenied(
                "resource commit was rejected by the atomic authority fence"
            ) from exc

    async def aexecute_authorized(
        self, request: Request, permit_token: str
    ) -> dict[str, Any]:
        """Async-compatible adapter; the commit remains one synchronous DB transaction."""
        return self.execute_authorized(request, permit_token)


# Backwards-compatible name for callers that explicitly use the SQLite backend.
# The adapter itself is backend-neutral; its registry determines transaction semantics.
SQLiteFencedResourceExecutor = FencedResourceExecutor


__all__ = [
    "FencedResourceExecutor",
    "ResourceCommitDenied",
    "SQLiteFencedResourceExecutor",
]
