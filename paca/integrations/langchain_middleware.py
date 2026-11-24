"""LangChain middleware that routes agent tool calls through the PACA runtime.

The middleware snapshots the framework request and registered tool identity
before authorization, then rechecks them before handing a detached request to
the original handler. Trusted application callbacks remain part of the TCB.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from typing import Any

try:
    from langchain.agents.middleware import AgentMiddleware
except ImportError as exc:  # pragma: no cover - covered by optional-dependency test
    raise ImportError(
        "PACA tool middleware requires the optional dependency "
        "paca-plus-plus[langgraph]"
    ) from exc

from ..memory import MemoryAccessDenied
from ..runtime import Request, Tool


def _snapshot_tool_call_request(
    request: Any,
    tool_call: Mapping[str, Any],
    expected_digest: str,
) -> Any:
    """Create a framework request whose tool payload cannot follow caller mutation."""
    try:
        copied_call = copy.deepcopy(dict(tool_call))
        if _tool_call_digest(copied_call) != expected_digest:
            raise MemoryAccessDenied(
                "LangChain tool call changed while being snapshotted"
            )
        copied_state = copy.deepcopy(getattr(request, "state", None))
        original_tool = getattr(request, "tool", None)
        if original_tool is None:
            raise MemoryAccessDenied("LangChain tool implementation is missing")
        copied_tool = copy.copy(original_tool)
        override = getattr(request, "override", None)
        if callable(override):
            snapshot = override(
                tool_call=copied_call,
                tool=copied_tool,
                state=copied_state,
            )
        else:
            snapshot = copy.copy(request)
            snapshot.tool_call = copied_call
            snapshot.tool = copied_tool
            snapshot.state = copied_state
        if (
            _tool_call_digest(getattr(snapshot, "tool_call", {})) != expected_digest
            or getattr(getattr(snapshot, "tool", None), "name", None)
            != getattr(original_tool, "name", None)
            or not _same_state_snapshot(
                getattr(snapshot, "state", None),
                copied_state,
            )
        ):
            raise MemoryAccessDenied(
                "LangChain request snapshot does not preserve the authorized call"
            )
        return snapshot
    except MemoryAccessDenied:
        raise
    except Exception as exc:
        raise MemoryAccessDenied(
            "LangChain request cannot be safely snapshotted for tool execution"
        ) from exc


def _same_state_snapshot(current: Any, expected: Any) -> bool:
    """Compare framework state conservatively; ambiguous equality fails closed."""
    try:
        result = current == expected
        return result if isinstance(result, bool) else False
    except Exception:  # noqa: BLE001 - arbitrary equality failures make the snapshot unverifiable.
        return False


def _tool_call_digest(tool_call: Mapping[str, Any]) -> str:
    """Fingerprint the exact JSON tool call handed to LangChain's handler."""
    try:
        encoded = json.dumps(
            dict(tool_call),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MemoryAccessDenied(
            "LangChain tool arguments must be canonical JSON before mediation"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


class PACALangChainToolMiddleware(AgentMiddleware):
    """Intercept every LangChain/LangGraph agent tool call through PACA runtime.

    request_factory is trusted application code. It must map every configured tool
    to an action-specific PACA Request and preserve argument/resource provenance.
    Unknown or unmapped tools fail closed. The middleware does not modify tools or
    allow an unmediated fallback path.
    """

    def __init__(
        self,
        runtime: Any,
        *,
        capability_token_provider: Callable[[Any], str],
        tool_manifest_provider: Callable[[Any], Tool],
        request_factory: Callable[[Any], Request],
    ) -> None:
        super().__init__()
        if (
            not callable(capability_token_provider)
            or not callable(tool_manifest_provider)
            or not callable(request_factory)
        ):
            raise TypeError(
                "trusted capability, registered-tool manifest and action-mapping callbacks are required"
            )
        self.runtime = runtime
        self._token_provider = capability_token_provider
        self._tool_manifest_provider = tool_manifest_provider
        self._request_factory = request_factory

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        tool_call = getattr(request, "tool_call", None)
        tool = getattr(request, "tool", None)
        if (
            not isinstance(tool_call, Mapping)
            or not isinstance(tool_call.get("name"), str)
            or not tool_call.get("name")
            or tool is None
            or getattr(tool, "name", None) != tool_call.get("name")
        ):
            raise MemoryAccessDenied(
                "LangChain tool identity is missing or does not match the registered tool"
            )
        tool_call_digest = _tool_call_digest(tool_call)
        original_state = copy.deepcopy(getattr(request, "state", None))
        factory_request = _snapshot_tool_call_request(
            request,
            tool_call,
            tool_call_digest,
        )
        factory_state = copy.deepcopy(getattr(factory_request, "state", None))
        actual_manifest = self._tool_manifest_provider(tool)
        if (
            not isinstance(actual_manifest, Tool)
            or actual_manifest.name != tool_call["name"]
        ):
            raise MemoryAccessDenied(
                "registered tool has no trusted PACA manifest or its identity differs"
            )
        paca_request = self._request_factory(factory_request)
        if not _same_state_snapshot(
            getattr(factory_request, "state", None),
            factory_state,
        ) or not _same_state_snapshot(
            getattr(request, "state", None),
            original_state,
        ):
            raise MemoryAccessDenied(
                "LangChain graph state changed while its PACA request was being constructed"
            )
        if not isinstance(paca_request, Request):
            raise TypeError("request_factory must return a PACA Request")
        if paca_request.tool != actual_manifest:
            raise MemoryAccessDenied(
                "PACA action mapping does not match the registered tool manifest"
            )
        if (
            _tool_call_digest(getattr(request, "tool_call", {})) != tool_call_digest
            or _tool_call_digest(getattr(factory_request, "tool_call", {}))
            != tool_call_digest
            or not _same_state_snapshot(
                getattr(request, "state", None),
                original_state,
            )
        ):
            raise MemoryAccessDenied(
                "LangChain tool call or graph state changed while its PACA request was being constructed"
            )
        frozen_request = _snapshot_tool_call_request(
            request,
            tool_call,
            tool_call_digest,
        )
        if self._tool_manifest_provider(frozen_request.tool) != actual_manifest:
            raise MemoryAccessDenied(
                "snapshotted tool implementation differs from the registered manifest"
            )
        token = self._token_provider(request)
        signed = self.runtime.authority.verify(token)
        pin = signed.capability.tool_pins.get(tool_call["name"])
        if pin is None or not hmac.compare_digest(pin, actual_manifest.hash):
            raise MemoryAccessDenied(
                "LangChain tool manifest is not pinned by the authenticated capability"
            )

        def checked_handler(_validated: Any) -> Any:
            current_call = getattr(request, "tool_call", None)
            current_tool = getattr(request, "tool", None)
            if (
                not isinstance(current_call, Mapping)
                or _tool_call_digest(current_call) != tool_call_digest
                or current_tool is None
                or getattr(current_tool, "name", None) != actual_manifest.name
                or not _same_state_snapshot(
                    getattr(request, "state", None),
                    original_state,
                )
                or not _same_state_snapshot(
                    getattr(frozen_request, "state", None),
                    original_state,
                )
            ):
                raise MemoryAccessDenied(
                    "LangChain tool call or identity changed after PACA authorization"
                )
            current_manifest = self._tool_manifest_provider(current_tool)
            if current_manifest != actual_manifest:
                raise MemoryAccessDenied(
                    "registered tool manifest changed after PACA authorization"
                )
            if _tool_call_digest(frozen_request.tool_call) != tool_call_digest:
                raise MemoryAccessDenied(
                    "frozen LangChain tool call changed before handler invocation"
                )
            if self._tool_manifest_provider(frozen_request.tool) != actual_manifest:
                raise MemoryAccessDenied(
                    "snapshotted tool manifest changed before handler invocation"
                )
            return handler(frozen_request)

        decision, result = self.runtime.execute_effect(
            token,
            paca_request,
            checked_handler,
        )
        if decision.verdict != "allow":
            raise MemoryAccessDenied("PACA denied the LangChain tool call")
        return result

    async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        tool_call = getattr(request, "tool_call", None)
        tool = getattr(request, "tool", None)
        if (
            not isinstance(tool_call, Mapping)
            or not isinstance(tool_call.get("name"), str)
            or not tool_call.get("name")
            or tool is None
            or getattr(tool, "name", None) != tool_call.get("name")
        ):
            raise MemoryAccessDenied(
                "LangChain tool identity is missing or does not match the registered tool"
            )
        tool_call_digest = _tool_call_digest(tool_call)
        original_state = copy.deepcopy(getattr(request, "state", None))
        factory_request = _snapshot_tool_call_request(
            request,
            tool_call,
            tool_call_digest,
        )
        factory_state = copy.deepcopy(getattr(factory_request, "state", None))
        actual_manifest = self._tool_manifest_provider(tool)
        if (
            not isinstance(actual_manifest, Tool)
            or actual_manifest.name != tool_call["name"]
        ):
            raise MemoryAccessDenied(
                "registered tool has no trusted PACA manifest or its identity differs"
            )
        paca_request = self._request_factory(factory_request)
        if not _same_state_snapshot(
            getattr(factory_request, "state", None),
            factory_state,
        ) or not _same_state_snapshot(
            getattr(request, "state", None),
            original_state,
        ):
            raise MemoryAccessDenied(
                "LangChain graph state changed while its PACA request was being constructed"
            )
        if not isinstance(paca_request, Request):
            raise TypeError("request_factory must return a PACA Request")
        if paca_request.tool != actual_manifest:
            raise MemoryAccessDenied(
                "PACA action mapping does not match the registered tool manifest"
            )
        if (
            _tool_call_digest(getattr(request, "tool_call", {})) != tool_call_digest
            or _tool_call_digest(getattr(factory_request, "tool_call", {}))
            != tool_call_digest
            or not _same_state_snapshot(
                getattr(request, "state", None),
                original_state,
            )
        ):
            raise MemoryAccessDenied(
                "LangChain tool call or graph state changed while its PACA request was being constructed"
            )
        frozen_request = _snapshot_tool_call_request(
            request,
            tool_call,
            tool_call_digest,
        )
        if self._tool_manifest_provider(frozen_request.tool) != actual_manifest:
            raise MemoryAccessDenied(
                "snapshotted tool implementation differs from the registered manifest"
            )
        token = self._token_provider(request)
        signed = self.runtime.authority.verify(token)
        pin = signed.capability.tool_pins.get(tool_call["name"])
        if pin is None or not hmac.compare_digest(pin, actual_manifest.hash):
            raise MemoryAccessDenied(
                "LangChain tool manifest is not pinned by the authenticated capability"
            )

        async def checked_handler(_validated: Any) -> Any:
            current_call = getattr(request, "tool_call", None)
            current_tool = getattr(request, "tool", None)
            if (
                not isinstance(current_call, Mapping)
                or _tool_call_digest(current_call) != tool_call_digest
                or current_tool is None
                or getattr(current_tool, "name", None) != actual_manifest.name
                or not _same_state_snapshot(
                    getattr(request, "state", None),
                    original_state,
                )
                or not _same_state_snapshot(
                    getattr(frozen_request, "state", None),
                    original_state,
                )
            ):
                raise MemoryAccessDenied(
                    "LangChain tool call or identity changed after PACA authorization"
                )
            current_manifest = self._tool_manifest_provider(current_tool)
            if current_manifest != actual_manifest:
                raise MemoryAccessDenied(
                    "registered tool manifest changed after PACA authorization"
                )
            if _tool_call_digest(frozen_request.tool_call) != tool_call_digest:
                raise MemoryAccessDenied(
                    "frozen LangChain tool call changed before handler invocation"
                )
            if self._tool_manifest_provider(frozen_request.tool) != actual_manifest:
                raise MemoryAccessDenied(
                    "snapshotted tool manifest changed before handler invocation"
                )
            result = handler(frozen_request)
            if hasattr(result, "__await__"):
                return await result
            return result

        decision, result = await self.runtime.aexecute_effect(
            token,
            paca_request,
            checked_handler,
        )
        if decision.verdict != "allow":
            raise MemoryAccessDenied("PACA denied the LangChain tool call")
        return result


__all__ = ["PACALangChainToolMiddleware"]
