"""Fail-closed lifecycle enforcement for PACA-managed agent effects.

This module is the enforcement companion to PACA's authorization and provenance
primitives.  It deliberately operates on metadata, not model text: tool output
and retrieved content must be labelled by a trusted adapter before they can be
used in a consequential request.  The controller makes four continuity checks
explicit at the PACA runtime boundary: authority, information, usage and final
effect identity.  It does not make direct provider clients, raw stores or host
process APIs safe by itself.
"""

from __future__ import annotations

import contextlib
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import NoReturn, TypeVar

from .runtime import ACTIONS, Request

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_T = TypeVar("_T")
_DEFAULT_TOOL_ACTIONS = frozenset(
    action
    for action, spec in ACTIONS.items()
    if spec.get("cls") not in {"memory"} and action != "delegate"
)


class LifecycleSecurityError(PermissionError):
    """A lifecycle invariant rejected an operation."""


class LifecyclePhase(str, Enum):
    SESSION = "session"
    INPUT = "input"
    RETRIEVAL = "retrieval"
    PLAN = "plan"
    TOOL = "tool"
    MEMORY = "memory"
    MESSAGE = "message"
    DELEGATION = "delegation"
    EFFECT = "effect"
    COMMIT = "commit"
    SHUTDOWN = "shutdown"


@dataclass(frozen=True)
class LifecycleSecurityPolicy:
    """Deterministic policy for the lifecycle controller.

    The defaults are intentionally production-oriented.  Reads may consume
    untrusted data, but consequential actions cannot use untrusted or
    incomplete-lineage values without first passing through a trusted adapter.
    """

    allowed_actions: frozenset[str] | None = None
    allowed_tools: frozenset[str] = frozenset()
    require_tool_for: frozenset[str] | None = None
    require_complete_lineage_for: frozenset[str] = frozenset(
        {"egress", "write", "destructive", "exec", "setting", "delegate"}
    )
    deny_untrusted_for: frozenset[str] = frozenset(
        {"egress", "write", "destructive", "exec", "setting", "delegate"}
    )
    require_authority_lineage: bool = True
    require_tool_implementation_digest: bool = True
    max_audit_events: int = 4096
    # Bound process-local replay memory. Exhaustion fails closed; receipts are
    # deliberately not evicted because eviction would re-enable duplicate commits.
    max_committed_effects: int = 100_000

    def __post_init__(self) -> None:
        if self.allowed_actions is not None:
            unknown = set(self.allowed_actions) - set(ACTIONS)
            if unknown:
                raise ValueError(f"unknown lifecycle actions: {sorted(unknown)}")
        if self.require_tool_for is None:
            object.__setattr__(self, "require_tool_for", _DEFAULT_TOOL_ACTIONS)
        unknown_classes = set(self.require_complete_lineage_for) | set(
            self.deny_untrusted_for
        )
        known_classes = {str(spec.get("cls")) for spec in ACTIONS.values()}
        if unknown_classes - known_classes:
            raise ValueError(
                "unknown lifecycle effect classes: "
                + ", ".join(sorted(unknown_classes - known_classes))
            )
        if not isinstance(self.require_authority_lineage, bool):
            raise TypeError("require_authority_lineage must be a boolean")
        if not isinstance(self.require_tool_implementation_digest, bool):
            raise TypeError("require_tool_implementation_digest must be a boolean")
        if (
            isinstance(self.max_audit_events, bool)
            or not isinstance(self.max_audit_events, int)
            or not 128 <= self.max_audit_events <= 100_000
        ):
            raise ValueError("max_audit_events must be between 128 and 100000")
        if (
            isinstance(self.max_committed_effects, bool)
            or not isinstance(self.max_committed_effects, int)
            or not 128 <= self.max_committed_effects <= 1_000_000
        ):
            raise ValueError("max_committed_effects must be between 128 and 1000000")


@dataclass(frozen=True)
class LifecycleSession:
    session_id: str
    principal: str
    tenant: str
    task_id: str
    purpose: str
    policy_epoch: int | None = None


@dataclass(frozen=True)
class LifecycleAuditEvent:
    sequence: int
    phase: str
    operation: str
    decision: str
    session_id: str | None
    principal: str | None
    tenant: str | None
    task_id: str | None
    subject: str | None
    digest: str | None
    reason: str | None
    created_at: float


class LifecycleSecurityController:
    """Enforce and audit the PACA-owned part of an agent lifecycle.

    A controller has one active session and one-way stop semantics.  It binds
    effect requests to that session, rejects untrusted data at consequential
    boundaries, requires pinned tool implementations, and makes an authorized
    request digest one-use even if a caller bypasses the monitor's effect token.
    """

    def __init__(
        self,
        policy: LifecycleSecurityPolicy | None = None,
        *,
        clock: Callable[[], float] = time.time,
        audit_sink: Callable[[LifecycleAuditEvent], None] | None = None,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        if audit_sink is not None and not callable(audit_sink):
            raise TypeError("audit_sink must be callable")
        self.policy = policy or LifecycleSecurityPolicy()
        self._clock = clock
        self._audit_sink = audit_sink
        self._events: deque[LifecycleAuditEvent] = deque(
            maxlen=self.policy.max_audit_events
        )
        self._used_effects: set[str] = set()
        self._session: LifecycleSession | None = None
        self._stopped_reason: str | None = None
        self._sequence = 0
        self._lock = threading.RLock()

    @property
    def session(self) -> LifecycleSession | None:
        with self._lock:
            return self._session

    @property
    def stopped(self) -> bool:
        with self._lock:
            return self._stopped_reason is not None

    @property
    def audit_events(self) -> tuple[LifecycleAuditEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def _emit(
        self,
        phase: LifecyclePhase,
        operation: str,
        decision: str,
        *,
        subject: str | None = None,
        digest: str | None = None,
        reason: str | None = None,
    ) -> LifecycleAuditEvent:
        session = self._session
        self._sequence += 1
        event = LifecycleAuditEvent(
            sequence=self._sequence,
            phase=phase.value,
            operation=operation,
            decision=decision,
            session_id=session.session_id if session else None,
            principal=session.principal if session else None,
            tenant=session.tenant if session else None,
            task_id=session.task_id if session else None,
            subject=subject,
            digest=digest,
            reason=reason,
            created_at=float(self._clock()),
        )
        self._events.append(event)
        if self._audit_sink is not None:
            self._audit_sink(event)
        return event

    @staticmethod
    def _required_text(name: str, value: str) -> str:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError(f"{name} must be a non-empty NUL-free string")
        return value

    def start_session(
        self,
        *,
        session_id: str,
        principal: str,
        tenant: str,
        task_id: str,
        purpose: str,
        policy_epoch: int | None = None,
    ) -> LifecycleSession:
        with self._lock:
            if self._stopped_reason is not None:
                raise LifecycleSecurityError("lifecycle controller is stopped")
            if self._session is not None:
                raise LifecycleSecurityError("a lifecycle session is already active")
            if policy_epoch is not None and (
                isinstance(policy_epoch, bool)
                or not isinstance(policy_epoch, int)
                or policy_epoch < 0
            ):
                raise ValueError("policy_epoch must be a non-negative integer or None")
            session = LifecycleSession(
                self._required_text("session_id", session_id),
                self._required_text("principal", principal),
                self._required_text("tenant", tenant),
                self._required_text("task_id", task_id),
                self._required_text("purpose", purpose),
                policy_epoch,
            )
            self._session = session
            self._emit(
                LifecyclePhase.SESSION,
                "start",
                "allow",
                subject=session.session_id,
            )
            return session

    def stop(self, reason: str) -> None:
        with self._lock:
            self._stopped_reason = self._required_text("reason", reason)
            self._emit(
                LifecyclePhase.SHUTDOWN,
                "kill_switch",
                "deny",
                reason=self._stopped_reason,
            )

    def close_session(self) -> None:
        with self._lock:
            if self._session is None:
                return
            self._emit(
                LifecyclePhase.SHUTDOWN,
                "close",
                "allow",
                subject=self._session.session_id,
            )
            self._session = None

    def observe(
        self,
        phase: LifecyclePhase,
        operation: str,
        *,
        subject: str | None = None,
        digest: str | None = None,
        trusted: bool | None = None,
    ) -> LifecycleAuditEvent:
        """Record a non-effect lifecycle transition without trusting its content."""
        if not isinstance(phase, LifecyclePhase):
            raise TypeError("phase must be a LifecyclePhase")
        self._required_text("operation", operation)
        if digest is not None and _DIGEST.fullmatch(digest) is None:
            raise ValueError("digest must be a lowercase SHA-256 value")
        if trusted is not None and not isinstance(trusted, bool):
            raise TypeError("trusted must be a boolean or None")
        with self._lock:
            if self._stopped_reason is not None:
                raise LifecycleSecurityError("lifecycle controller is stopped")
            return self._emit(
                phase,
                operation,
                "allow" if trusted is not False else "observe-untrusted",
                subject=subject,
                digest=digest,
            )

    def run_context_transition(
        self,
        *,
        phase: LifecyclePhase,
        operation: str,
        principal: str,
        tenant: str,
        task_id: str,
        purpose: str,
        policy_epoch: int | None,
        subject: str,
        digest: str,
        action: Callable[[], _T],
    ) -> _T:
        """Run one trusted communication/delegation operation in the active session.

        The callback must be a PACA-owned adapter operation, never model- or
        user-supplied code. It runs while the lifecycle lock is held so stop,
        close and other session transitions cannot race the operation. This
        binds only calls routed through this runtime; it is not host mediation.
        """
        allowed_operations = {
            LifecyclePhase.DELEGATION: frozenset({"delegate"}),
            LifecyclePhase.MESSAGE: frozenset({"send", "receive"}),
        }
        if (
            phase not in allowed_operations
            or operation not in allowed_operations[phase]
        ):
            raise ValueError("unsupported lifecycle context transition")
        self._required_text("principal", principal)
        self._required_text("tenant", tenant)
        self._required_text("task_id", task_id)
        self._required_text("purpose", purpose)
        self._required_text("subject", subject)
        if policy_epoch is not None and (
            isinstance(policy_epoch, bool)
            or not isinstance(policy_epoch, int)
            or policy_epoch < 0
        ):
            raise ValueError("policy_epoch must be a non-negative integer or None")
        if _DIGEST.fullmatch(digest) is None:
            raise ValueError("digest must be a lowercase SHA-256 value")
        if not callable(action):
            raise TypeError("context transition action must be callable")

        with self._lock:
            session = self._session

            def reject(reason: str) -> NoReturn:
                self._emit(
                    phase,
                    operation,
                    "deny",
                    subject=subject,
                    digest=digest,
                    reason=reason,
                )
                raise LifecycleSecurityError(reason)

            if self._stopped_reason is not None:
                reject("lifecycle controller is stopped")
            if session is None:
                reject("an active lifecycle session is required")
            if (
                principal != session.principal
                or tenant != session.tenant
                or task_id != session.task_id
                or purpose != session.purpose
            ):
                reject(
                    "communication or delegation authority is outside the active session"
                )
            if (
                session.policy_epoch is not None
                and policy_epoch != session.policy_epoch
            ):
                reject(
                    "communication or delegation authority is outside the active policy epoch"
                )

            self._emit(
                phase,
                operation,
                "context-validated",
                subject=subject,
                digest=digest,
            )
            try:
                # The audit sink is trusted host code and is called from _emit.
                # RLock permits same-thread re-entry, so verify that an audit
                # callback did not stop or replace this session before dispatch.
                if self._stopped_reason is not None or self._session is not session:
                    raise LifecycleSecurityError(
                        "active lifecycle session changed during transition audit"
                    )
                result = action()
            except Exception as exc:
                # Do not persist exception text: adapter errors may contain data.
                self._emit(
                    phase,
                    operation,
                    "failed",
                    subject=subject,
                    digest=digest,
                    reason=type(exc).__name__,
                )
                raise
            self._emit(
                phase,
                operation,
                "completed",
                subject=subject,
                digest=digest,
            )
            return result

    def _reject(self, request: Request, reason: str) -> NoReturn:
        digest = None
        with contextlib.suppress(Exception):
            digest = request.digest
        self._emit(
            LifecyclePhase.EFFECT,
            "authorize",
            "deny",
            subject=getattr(request, "action", None),
            digest=digest,
            reason=reason,
        )
        raise LifecycleSecurityError(reason)

    def _assert_request(self, request: Request) -> str:
        if not isinstance(request, Request):
            raise LifecycleSecurityError("lifecycle requires a typed PACA Request")
        if self._stopped_reason is not None:
            self._reject(request, "lifecycle controller is stopped")
        session = self._session
        if session is None:
            self._reject(request, "an active lifecycle session is required")
        if (
            request.cap.principal != session.principal
            or request.cap.tenant != session.tenant
            or request.cap.task_id != session.task_id
        ):
            self._reject(request, "request authority is outside the active session")
        authority_lineage = request.cap.authority_lineage
        if self.policy.require_authority_lineage and authority_lineage is None:
            self._reject(
                request,
                "effect request requires immutable authority lineage",
            )
        if authority_lineage is not None:
            if authority_lineage.purpose != session.purpose:
                self._reject(request, "request purpose is outside the active session")
            if (
                session.policy_epoch is not None
                and authority_lineage.policy_epoch != session.policy_epoch
            ):
                self._reject(
                    request,
                    "request authority is outside the active policy epoch",
                )
        action = request.action
        spec = ACTIONS.get(action)
        if not isinstance(spec, Mapping):
            self._reject(request, "unknown action is not lifecycle-authorized")
        if (
            self.policy.allowed_actions is not None
            and action not in self.policy.allowed_actions
        ):
            self._reject(request, "action is outside the lifecycle allowlist")
        effect_class = spec.get("cls")
        require_tool_for = self.policy.require_tool_for
        if require_tool_for is None:
            self._reject(request, "lifecycle tool policy is not initialized")
        if action in require_tool_for and request.tool is None:
            self._reject(request, "consequential action requires a typed tool manifest")
        if request.tool is not None:
            if (
                self.policy.allowed_tools
                and request.tool.name not in self.policy.allowed_tools
            ):
                self._reject(request, "tool is outside the lifecycle allowlist")
            if (
                action in require_tool_for
                and self.policy.require_tool_implementation_digest
                and request.tool.implementation_digest is None
            ):
                self._reject(request, "tool implementation must be digest-pinned")
        if effect_class in self.policy.require_complete_lineage_for:
            for name, argument in request.args.items():
                if not argument.lineage_refs or argument.lineage_incomplete:
                    self._reject(
                        request,
                        f"{action} argument {name!r} lacks complete trusted lineage",
                    )
        for name, argument in request.args.items():
            label = argument.label
            if (
                effect_class in self.policy.deny_untrusted_for
                and label.integrity == "untrusted"
            ):
                self._reject(
                    request,
                    f"{action} argument {name!r} contains untrusted content",
                )
            if label.tenant_unknown or (
                label.sensitivity > 0 and session.tenant not in label.tenants
            ):
                self._reject(
                    request,
                    f"{action} argument {name!r} has an unknown or mismatched tenant",
                )
        try:
            digest = request.digest
        except Exception as exc:
            self._reject(request, f"request digest could not be computed: {exc}")
        self._emit(
            LifecyclePhase.EFFECT,
            "authorize",
            "allow",
            subject=action,
            digest=digest,
        )
        return digest

    def authorize_request(self, request: Request) -> str:
        """Check a frozen request before PACA's monitor decision."""
        with self._lock:
            return self._assert_request(request)

    def commit_authorization(self, request: Request) -> str:
        """Consume a one-use lifecycle authorization immediately before execution."""
        with self._lock:
            digest = self._assert_request(request)
            if digest in self._used_effects:
                self._reject(
                    request, "effect request digest has already been committed"
                )
            if len(self._used_effects) >= self.policy.max_committed_effects:
                self._reject(
                    request,
                    "in-memory committed-effect receipt capacity is exhausted; refusing further effects",
                )
            self._used_effects.add(digest)
            self._emit(
                LifecyclePhase.COMMIT,
                "effect_authorized",
                "allow",
                subject=request.action,
                digest=digest,
            )
            return digest


__all__ = [
    "LifecycleAuditEvent",
    "LifecyclePhase",
    "LifecycleSecurityController",
    "LifecycleSecurityError",
    "LifecycleSecurityPolicy",
    "LifecycleSession",
]
