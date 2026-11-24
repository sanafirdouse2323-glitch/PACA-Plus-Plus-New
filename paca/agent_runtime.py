"""PACA agent runtime orchestration across authority, monitor and memory adapters.

The runtime covers only calls routed through its methods. Direct tool clients,
framework callbacks, subprocesses and remote resource servers require separate
integration; a final local registry check cannot make a remote effect atomic with
revocation.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import inspect
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .authority_runtime import HMACCapabilityAuthority
from .memory import (
    HMACAgentMessageCodec,
    MemoryAccessDenied,
    TrustedMemoryAdapter,
    _AuthorizedMemoryReference,
    canonical_value_bytes,
)
from .provenance import Arg
from .runtime import ACTIONS, Decision, Request, Tool


class PACAAgentRuntime:
    """Small reference orchestrator joining signed authority, monitor and message/memory APIs.

    This wrapper covers calls made through its methods only. Direct tool clients,
    framework callbacks, subprocesses and remote resource servers must be integrated
    separately; a final local registry check cannot make a remote effect atomic with
    revocation.
    """

    def __init__(
        self,
        authority: HMACCapabilityAuthority,
        memory: TrustedMemoryAdapter,
        monitor: Any,
        messages: HMACAgentMessageCodec,
        *,
        require_resource_commit_fence: bool = False,
        resource_commit_verifier: HMACCapabilityAuthority | None = None,
    ) -> None:
        if (
            memory.authority is not authority
            or messages.authority is not authority
            or messages.memory is not memory
        ):
            raise ValueError(
                "runtime, memory and message adapters must share the same trusted issuer and memory store"
            )
        monitor_validator = getattr(monitor, "assert_consequential_safe", None)
        if callable(monitor_validator):
            monitor_validator()
        # Research ablations are permitted in the simulator only. A
        # consequential runtime must retain the complete packaged policy profile.
        if "C13" in getattr(monitor, "disable", ()):
            raise ValueError("PACAAgentRuntime requires C13 effect-token verification")
        if not isinstance(require_resource_commit_fence, bool):
            raise TypeError("require_resource_commit_fence must be a boolean")
        if resource_commit_verifier is None:
            if (
                require_resource_commit_fence
                and authority.SIGNATURE_ALGORITHM == "Ed25519"
            ):
                raise ValueError(
                    "Ed25519 strict resource-commit mode requires a separate public-key-only verifier"
                )
            resource_commit_verifier = authority
        if not isinstance(resource_commit_verifier, HMACCapabilityAuthority):
            raise TypeError(
                "resource_commit_verifier must implement the PACA capability verification contract"
            )
        issuer_store_id = getattr(
            authority.registry,
            "authority_store_id",
            authority.registry.database,
        )
        verifier_store_id = getattr(
            resource_commit_verifier.registry,
            "authority_store_id",
            resource_commit_verifier.registry.database,
        )
        if (
            verifier_store_id != issuer_store_id
            or resource_commit_verifier.issuer_id != authority.issuer_id
            or resource_commit_verifier.key_id != authority.key_id
            or resource_commit_verifier.audience != authority.audience
            or resource_commit_verifier.SIGNATURE_ALGORITHM
            != authority.SIGNATURE_ALGORITHM
        ):
            raise ValueError(
                "resource commit verifier must match the issuer identity, key, algorithm and authority store"
            )
        if (
            require_resource_commit_fence
            and authority.SIGNATURE_ALGORITHM == "Ed25519"
            and (
                resource_commit_verifier is authority
                or getattr(resource_commit_verifier, "_ed25519_signing_key", None)
                is not None
            )
        ):
            raise ValueError(
                "Ed25519 resource commit verifier must be a separate public-key-only authority instance"
            )
        self.authority = authority
        self.resource_commit_verifier = resource_commit_verifier
        self.memory = memory
        self.monitor = monitor
        self.messages = messages
        self.require_resource_commit_fence = require_resource_commit_fence

    @staticmethod
    def _assert_tool_binding(capability: Any, request: Request) -> None:
        if request.action in {"mem_read", "mem_write", "delegate"}:
            return
        tool = request.tool
        if not isinstance(tool, Tool):
            raise MemoryAccessDenied(
                "protected agent effect requires an explicit typed tool manifest"
            )
        pinned = capability.tool_pins.get(tool.name)
        if pinned is None or not hmac.compare_digest(pinned, tool.hash):
            raise MemoryAccessDenied(
                "tool manifest is not pinned by the authenticated capability"
            )

    def delegate(
        self,
        parent_token: str,
        *,
        principal: str,
        grants: Mapping[str, Iterable[str]],
        expires_at: int,
        role: str = "assistant",
        max_calls: int = 40,
        max_fanout: int = 5,
        max_task_calls: int | None = None,
    ):
        return self.authority.issue(
            parent_token=parent_token,
            principal=principal,
            grants=grants,
            expires_at=expires_at,
            role=role,
            max_calls=max_calls,
            max_fanout=max_fanout,
            max_task_calls=max_task_calls,
        )

    def send_message(
        self,
        payload: Arg,
        *,
        sender: str,
        recipient: str,
        capability_token: str,
    ) -> str:
        return self.messages.seal(
            payload,
            sender=sender,
            recipient=recipient,
            capability_token=capability_token,
        )

    def receive_message(self, token: str, *, recipient_token: str) -> Arg:
        return self.messages.open(token, recipient_token=recipient_token)

    def revoke_authority(self, authority_id: str, reason: str) -> tuple[str, ...]:
        return self.authority.registry.revoke(authority_id, reason)

    def revoke_information(self, node_id: str, reason: str) -> None:
        self.memory.repository.revoke_lineage(
            node_id, reason, revoked_at=int(self.memory.clock())
        )

    def _prepare_effect(
        self,
        capability_token: str,
        request: Request,
    ) -> tuple[Any, Request, str, tuple[_AuthorizedMemoryReference, ...]]:
        """Authenticate and snapshot an effect before authorizing any consequence."""
        if not isinstance(request, Request):
            raise MemoryAccessDenied("effect request must be a typed PACA Request")
        monitor_validator = getattr(self.monitor, "assert_consequential_safe", None)
        if callable(monitor_validator):
            try:
                monitor_validator()
            except ValueError as exc:
                raise MemoryAccessDenied(
                    "consequential runtime monitor configuration is unsafe: " + str(exc)
                ) from exc
        if self.require_resource_commit_fence and request.action not in {
            "write_file",
            "mem_write",
        }:
            raise MemoryAccessDenied(
                "resource commit fence mode currently supports only write_file and mem_write"
            )
        signed = self.authority.verify(capability_token)
        issued = signed.capability

        try:
            original_digest = request.digest
            snapshot = copy.deepcopy(request)
            snapshot_digest = snapshot.digest
        except Exception as exc:
            raise MemoryAccessDenied(
                "effect request could not be safely snapshotted"
            ) from exc
        if snapshot_digest != original_digest:
            raise MemoryAccessDenied("effect request changed while being snapshotted")

        supplied = snapshot.cap
        try:
            supplied.validate_authority_lineage()
        except Exception as exc:
            raise MemoryAccessDenied("request capability lineage is invalid") from exc
        if (
            supplied.cap_id != issued.cap_id
            or supplied.authority_lineage != issued.authority_lineage
            or supplied.principal != issued.principal
            or supplied.tenant != issued.tenant
            or supplied.task_id != issued.task_id
            or supplied.grants != issued.grants
            or supplied.expires != issued.expires
            or supplied.parent != issued.parent
            or supplied.role != issued.role
            or supplied.max_calls != issued.max_calls
            or supplied.max_fanout != issued.max_fanout
            or supplied.tool_pins != issued.tool_pins
        ):
            raise MemoryAccessDenied(
                "request capability does not match the authenticated token"
            )
        self._assert_tool_binding(issued, snapshot)
        self.authority.registry.assert_active(issued.cap_id)

        authority_record = issued.authority_lineage
        if authority_record is None:
            raise MemoryAccessDenied(
                "effect capability has no immutable authority lineage"
            )
        purpose = authority_record.purpose
        accesses = []
        for argument in snapshot.args.values():
            accesses.extend(
                self.memory.authorize_argument(
                    argument,
                    purpose=purpose,
                    capability_token=capability_token,
                )
            )

        if snapshot.resource_lineage_refs:
            if snapshot.resource is None:
                raise MemoryAccessDenied(
                    "resource lineage references require an explicit resource label"
                )
            for node_id in sorted(snapshot.resource_lineage_refs):
                accesses.append(
                    self.memory.authorize_reference(
                        node_id,
                        label=snapshot.resource,
                        purpose=purpose,
                        capability_token=capability_token,
                    )
                )

        if snapshot.digest != original_digest:
            raise MemoryAccessDenied(
                "effect request changed during provenance authorization"
            )
        return issued, snapshot, original_digest, tuple(accesses)

    def _authorize_effect(
        self,
        capability_token: str,
        request: Request,
    ) -> tuple[
        Decision | None,
        Request | None,
        Any | None,
        tuple[_AuthorizedMemoryReference, ...],
    ]:
        """Run policy and consume a single-use decision for a frozen request snapshot."""
        if "C13" in getattr(self.monitor, "disable", ()):
            raise MemoryAccessDenied(
                "PACAAgentRuntime requires C13 effect-token verification"
            )
        issued, snapshot, request_digest, accesses = self._prepare_effect(
            capability_token,
            request,
        )
        decision = self.monitor.decide(snapshot)
        if decision.verdict != "allow":
            return decision, None, issued, accesses
        if decision.digest != request_digest or snapshot.digest != request_digest:
            raise MemoryAccessDenied(
                "monitor decision is not bound to the unchanged effect request"
            )
        if not self.monitor.verify(snapshot, decision):
            return Decision("deny", digest=request_digest), None, issued, accesses

        if self.require_resource_commit_fence:
            # The resource database transaction performs the effect-budget
            # charge together with the final active-authority check and write.
            # Charging here would split the commit from the quota transaction.
            self.authority.registry.assert_active(issued.cap_id)
        else:
            self.authority.registry.consume_effect(
                issued.cap_id,
                max_calls=issued.max_calls,
            )
            self.authority.registry.assert_active(issued.cap_id)
        authority_record = issued.authority_lineage
        if authority_record is None:
            raise MemoryAccessDenied("effect capability lost its authority lineage")
        if snapshot.digest != request_digest or decision.digest != request_digest:
            raise MemoryAccessDenied("effect request changed before executor entry")
        return decision, snapshot, issued, accesses

    def _require_fenced_executor(self, executor: Any) -> Any:
        """Require the exact runtime-bound local resource commit adapter."""
        if not self.require_resource_commit_fence:
            return None
        from .resource_commit import FencedResourceExecutor

        if (
            not isinstance(executor, FencedResourceExecutor)
            or executor.authority is not self.resource_commit_verifier
        ):
            raise MemoryAccessDenied(
                "resource commit fence mode requires the runtime-bound FencedResourceExecutor"
            )
        return executor

    def _issue_effect_commit_permit(
        self,
        capability_token: str,
        decision: Decision,
        snapshot: Request,
    ) -> str:
        """Bind a short-lived one-use permit to the exact action, target and payload."""
        spec = ACTIONS.get(snapshot.action)
        if not isinstance(spec, dict):
            raise MemoryAccessDenied("resource action has no trusted target mapping")
        target_name = spec.get("target")
        payload_names = spec.get("payload", ())
        if (
            not isinstance(target_name, str)
            or not target_name
            or not isinstance(payload_names, (list, tuple))
            or not payload_names
        ):
            raise MemoryAccessDenied(
                "resource action mapping lacks a target or payload"
            )
        target_argument = snapshot.args.get(target_name)
        if target_argument is None or not isinstance(target_argument.value, str):
            raise MemoryAccessDenied("resource commit target must be a string")
        payload: dict[str, Any] = {}
        for name in payload_names:
            argument = snapshot.args.get(name)
            if argument is None:
                raise MemoryAccessDenied("resource commit payload argument is missing")
            payload[name] = argument.value
        try:
            payload_digest = hashlib.sha256(canonical_value_bytes(payload)).hexdigest()
        except (TypeError, ValueError) as exc:
            raise MemoryAccessDenied(
                "resource commit payload is not canonical JSON"
            ) from exc
        try:
            return self.authority.issue_resource_commit_permit(
                capability_token,
                request_digest=decision.digest,
                action=snapshot.action,
                resource=target_argument.value,
                payload_digest=payload_digest,
            )
        except Exception as exc:
            raise MemoryAccessDenied(
                "could not issue a commit-bound resource permit"
            ) from exc

    def _revalidate_effect_snapshot(
        self,
        capability_token: str,
        decision: Decision,
        snapshot: Request,
        issued: Any,
        accesses: tuple[_AuthorizedMemoryReference, ...],
    ) -> None:
        """Check active authority, dynamic lineage policy and request immutability."""
        self.authority.registry.assert_active(issued.cap_id)
        authority_record = issued.authority_lineage
        if authority_record is None:
            raise MemoryAccessDenied("effect capability lost its authority lineage")
        self.memory.revalidate_authorized_references(
            accesses,
            capability_token=capability_token,
            purpose=authority_record.purpose,
        )
        if snapshot.digest != decision.digest:
            raise MemoryAccessDenied("effect request changed before executor entry")

    async def aexecute_effect(
        self,
        capability_token: str,
        request: Request,
        executor: Callable[[Request], Any],
    ) -> tuple[Decision, Any | None]:
        """Run only a declared async executor after PACA's effect checks.

        A synchronous callable that returns a coroutine is rejected before it is
        invoked: its synchronous prefix could otherwise perform effects before
        the runtime can revalidate authority and provenance.
        """
        fenced_executor = self._require_fenced_executor(executor)
        async_executor = (
            fenced_executor.aexecute_authorized
            if self.require_resource_commit_fence
            else executor
        )
        if not (
            inspect.iscoroutinefunction(async_executor)
            or inspect.iscoroutinefunction(
                getattr(type(async_executor), "__call__", None)
            )
        ):
            raise MemoryAccessDenied(
                "async effect executor must be an async function or async callable object; "
                "use execute_effect for synchronous executors"
            )
        decision, snapshot, issued, accesses = self._authorize_effect(
            capability_token,
            request,
        )
        if decision is None or issued is None:
            return Decision("deny"), None
        if decision.verdict != "allow":
            return decision, None
        if snapshot is None:
            return Decision("deny", digest=decision.digest), None

        self._revalidate_effect_snapshot(
            capability_token,
            decision,
            snapshot,
            issued,
            accesses,
        )
        if self.require_resource_commit_fence:
            permit = self._issue_effect_commit_permit(
                capability_token,
                decision,
                snapshot,
            )
            result = async_executor(snapshot, permit)
        else:
            result = async_executor(snapshot)
        if inspect.isawaitable(result):
            # Only a newly-created native coroutine has a guaranteed lazy body.
            # An asyncio.Task/Future or arbitrary Awaitable may already be running
            # before this runtime can revalidate its authority and source policy.
            if (
                not inspect.iscoroutine(result)
                or inspect.getcoroutinestate(result) != inspect.CORO_CREATED
            ):
                cancel = getattr(result, "cancel", None)
                if callable(cancel):
                    cancel()
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise MemoryAccessDenied(
                    "async executor must return an unstarted native coroutine, not a Task/Future or started awaitable"
                )
            # The coroutine body does not run until awaited. Revalidate again
            # after constructing it and immediately before entering that body.
            try:
                self._revalidate_effect_snapshot(
                    capability_token,
                    decision,
                    snapshot,
                    issued,
                    accesses,
                )
            except Exception:
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise
            result = await result

        # Do not return nested deferred or lazy values to a caller that could
        # execute them after PACA's authorization boundary has ended.
        if inspect.isawaitable(result):
            cancel = getattr(result, "cancel", None)
            if callable(cancel):
                cancel()
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise MemoryAccessDenied(
                "async executor returned a nested deferred result outside PACA authorization"
            )
        if inspect.isgenerator(result):
            result.close()
            raise MemoryAccessDenied(
                "async executor returned a lazy generator outside PACA authorization"
            )
        if inspect.isasyncgen(result):
            await result.aclose()
            raise MemoryAccessDenied(
                "async executor returned a lazy async generator outside PACA authorization"
            )
        return decision, result

    def execute_effect(
        self,
        capability_token: str,
        request: Request,
        executor: Callable[[Request], Any],
    ) -> tuple[Decision, Any | None]:
        """Check signed authority and exact request provenance immediately before effect."""
        fenced_executor = self._require_fenced_executor(executor)
        decision, snapshot, issued, accesses = self._authorize_effect(
            capability_token,
            request,
        )
        if decision is None or issued is None:
            return Decision("deny"), None
        if decision.verdict != "allow":
            return decision, None
        if snapshot is None:
            return Decision("deny", digest=decision.digest), None
        self._revalidate_effect_snapshot(
            capability_token,
            decision,
            snapshot,
            issued,
            accesses,
        )
        if self.require_resource_commit_fence:
            permit = self._issue_effect_commit_permit(
                capability_token,
                decision,
                snapshot,
            )
            result = fenced_executor.execute_authorized(snapshot, permit)
        else:
            result = executor(snapshot)
        if inspect.isawaitable(result):
            # The synchronous entry point cannot perform the post-construction
            # async authority check. Reject and cancel anything awaitable rather
            # than returning a Task/Future that may already be executing.
            cancel = getattr(result, "cancel", None)
            if callable(cancel):
                cancel()
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise MemoryAccessDenied(
                "synchronous effect executor must not return an awaitable; "
                "use the async runtime with an unstarted native coroutine"
            )
        if inspect.isgenerator(result):
            result.close()
            raise MemoryAccessDenied(
                "synchronous effect executor must not return a lazy generator"
            )
        if inspect.isasyncgen(result):
            raise MemoryAccessDenied(
                "synchronous effect executor must not return a lazy async generator"
            )
        return decision, result


# Keep the historical module name for introspection and pickle lookup compatibility.
PACAAgentRuntime.__module__ = "paca.memory"


__all__ = ["PACAAgentRuntime"]
