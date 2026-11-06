"""AgentDojo tool-execution adapter for PACA++.

This module is optional and imports AgentDojo only when requested. The adapter places
PACA++ immediately before AgentDojo's FunctionsRuntime dispatch. Applications must
provide an explicit request builder: this module cannot infer task authority or data
sensitivity from arbitrary tool names and model arguments.
"""
from __future__ import annotations

import ast
import copy
import json
from collections.abc import Callable, Mapping
from typing import Any

try:
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
    from agentdojo.types import ChatToolResultMessage, text_content_block_from_string
except ImportError as exc:  # pragma: no cover - exercised in dependency-error tests
    raise ImportError(
        "The PACA++ AgentDojo adapter requires the optional dependency. "
        "Install it using the paca-plus-plus[agentdojo] extra."
    ) from exc

from ..monitor import Monitor
from ..provenance import Arg, Label
from ..runtime import Decision, Request

RAW_ARGUMENTS_KEY = "__paca_agentdojo_raw_arguments__"

RequestBuilder = Callable[[str, dict[str, Any], Any, dict[str, Any]], Request]
ApprovalProvider = Callable[[Request, Decision, Any, dict[str, Any]], str | None]
ResultLabeler = Callable[[str, dict[str, Any], Any, Any, dict[str, Any]], Label]


def _canonical_json(value: Any) -> str:
    """Canonical JSON used to bind the PACA decision to the arguments dispatched."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def aggregate_prior_output_labels(extra_args: Mapping[str, Any]) -> Label:
    """Conservatively join labels recorded for earlier AgentDojo tool outputs.

    A request builder should use this for values that may have been derived from any
    prior tool output when it cannot establish finer-grained lineage. Over-tainting can
    reduce utility, but silently treating unknown lineage as trusted is unsafe.
    """
    labels = extra_args.get("paca_output_labels", {})
    if not isinstance(labels, Mapping):
        return Label(integrity="untrusted", origins=frozenset({"unknown_agentdojo_lineage"}))
    recorded = list(labels.values())
    if not recorded or any(not isinstance(value, Label) for value in recorded):
        return Label(integrity="untrusted", origins=frozenset({"unknown_agentdojo_lineage"}))
    return Label.join(*recorded)


class PacaToolsExecutor(ToolsExecutor):
    """AgentDojo ToolsExecutor with a fail-closed PACA++ decision before dispatch.

    request_builder maps a registered AgentDojo function call to a PACA++ Request.
    It must create labels from trusted task/connectors, map every effect-relevant
    argument into the PACA action model, and create task-appropriate capabilities.
    Unknown or unmapped calls must raise; the adapter will not execute them.

    Approval is denied unless approval_provider returns an opaque token accepted by
    the Monitor's separately configured approval_verifier. A boolean callback is
    deliberately insufficient.
    """

    def __init__(
        self,
        monitor: Monitor,
        request_builder: RequestBuilder,
        *,
        approval_provider: ApprovalProvider | None = None,
        result_labeler: ResultLabeler | None = None,
        tool_output_formatter: Callable[[Any], str] | None = None,
    ) -> None:
        if not callable(request_builder):
            raise TypeError("request_builder must be callable")
        if approval_provider is not None and not callable(approval_provider):
            raise TypeError("approval_provider must be callable or None")
        if result_labeler is not None and not callable(result_labeler):
            raise TypeError("result_labeler must be callable or None")
        if tool_output_formatter is None:
            super().__init__()
        else:
            super().__init__(tool_output_formatter=tool_output_formatter)
        self.monitor = monitor
        self.request_builder = request_builder
        self.approval_provider = approval_provider
        self.result_labeler = result_labeler
        self._output_counter = 0
        self._last_steps: dict[str, int] = {}

    @staticmethod
    def _tool_call_result(
        tool_call: Any,
        message: str,
        *,
        error: str | None = None,
    ) -> ChatToolResultMessage:
        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string(message)],
            tool_call_id=getattr(tool_call, "id", None),
            tool_call=tool_call,
            error=error,
        )

    @staticmethod
    def _is_string_list(value: str) -> bool:
        try:
            parsed = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return False
        return isinstance(parsed, list)

    def _deny_result(self, tool_call: Any, reason: str) -> ChatToolResultMessage:
        return self._tool_call_result(
            tool_call,
            "PACA++ did not authorize this tool call; no tool result was released.",
            error=reason,
        )

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: Any = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, Any, dict[str, Any]]:
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args or {}
        tool_calls = messages[-1].get("tool_calls")
        if not tool_calls:
            return query, runtime, env, messages, extra_args or {}

        state = extra_args if extra_args is not None else {}
        tool_call_results: list[ChatToolResultMessage] = []
        registered_names = {tool.name for tool in runtime.functions.values()}

        for tool_call in tool_calls:
            function_name = getattr(tool_call, "function", None)
            if not isinstance(function_name, str) or not function_name:
                tool_call_results.append(self._deny_result(tool_call, "Invalid or empty tool name."))
                continue
            if function_name not in registered_names:
                tool_call_results.append(self._tool_call_result(
                    tool_call,
                    "",
                    error=f"Invalid tool {function_name} provided.",
                ))
                continue

            supplied_args = getattr(tool_call, "args", None)
            if not isinstance(supplied_args, Mapping):
                tool_call_results.append(self._deny_result(tool_call, "Tool arguments are not a mapping."))
                continue

            try:
                execution_args = copy.deepcopy(dict(supplied_args))
                for key, value in list(execution_args.items()):
                    if isinstance(value, str) and self._is_string_list(value):
                        execution_args[key] = ast.literal_eval(value)
                argument_snapshot = _canonical_json(execution_args)

                request = self.request_builder(
                    function_name,
                    copy.deepcopy(execution_args),
                    env,
                    state,
                )
                if not isinstance(request, Request):
                    raise TypeError("request_builder did not return a PACA++ Request")
                if isinstance(request.step, bool) or not isinstance(request.step, int):
                    raise TypeError("request_builder must provide an integer request step")
                # Enforce monotonic steps within each capability, even if an application
                # mapper accidentally reuses a fixed initial step for subsequent calls.
                last_step = self._last_steps.get(request.cap.cap_id, request.step - 1)
                request.step = max(request.step, last_step + 1)
                self._last_steps[request.cap.cap_id] = request.step
                if RAW_ARGUMENTS_KEY in request.args:
                    raise ValueError(f"{RAW_ARGUMENTS_KEY} is reserved by the adapter")

                # Bind the complete dispatched argument object into Request.digest,
                # including fields that the application-specific policy mapping does
                # not itself interpret. The request builder still must map every
                # effect-relevant field to the correct action and provenance fields.
                request.args[RAW_ARGUMENTS_KEY] = Arg(
                    copy.deepcopy(execution_args),
                    Label(integrity="untrusted", origins=frozenset({"agentdojo_tool_call"})),
                )

                decision = self.monitor.decide(request)
                if decision.verdict == "needs_approval" and self.approval_provider is not None:
                    approval = self.approval_provider(request, decision, env, state)
                    if approval is not None:
                        if not isinstance(approval, str) or not approval.strip():
                            raise TypeError("approval_provider must return non-empty authenticated evidence or None")
                        request.approval = approval
                        decision = self.monitor.decide(request)

                if decision.verdict != "allow":
                    check_ids = ",".join(decision.checks) or "approval_required_or_policy_denied"
                    tool_call_results.append(self._deny_result(
                        tool_call,
                        f"PACA++ decision was {decision.verdict}; checks: {check_ids}.",
                    ))
                    continue

                bound_args = request.args[RAW_ARGUMENTS_KEY].value
                if _canonical_json(bound_args) != argument_snapshot:
                    tool_call_results.append(self._deny_result(
                        tool_call,
                        "PACA++ argument binding changed; tool was not executed.",
                    ))
                    continue

                if not self.monitor.verify(request, decision):
                    tool_call_results.append(self._deny_result(
                        tool_call,
                        "PACA++ effect-token verification failed; tool was not executed.",
                    ))
                    continue

            except Exception as exc:
                # Fail closed: request construction, canonicalization, authorization,
                # or token verification must never fall through to function dispatch.
                tool_call_results.append(self._deny_result(
                    tool_call,
                    f"PACA++ integration error ({type(exc).__name__}); tool was not dispatched.",
                ))
                continue

            # Keep function execution outside the authorization exception handler:
            # a function may raise after causing a partial external effect. Propagate
            # that runtime error instead of claiming that no effect occurred.
            # The mutable message-owned arguments are not used; dispatch the exact
            # normalized snapshot whose digest was authorized.
            result, error = runtime.run_function(env, function_name, execution_args)

            self._output_counter += 1
            call_id = getattr(tool_call, "id", None) or f"{function_name}:{self._output_counter}"
            try:
                if self.result_labeler is not None:
                    output_label = self.result_labeler(
                        function_name,
                        copy.deepcopy(execution_args),
                        result,
                        env,
                        state,
                    )
                elif request.resource is not None:
                    output_label = request.resource
                else:
                    output_label = Label(
                        integrity="untrusted",
                        origins=frozenset({f"agentdojo_tool_output:{function_name}"}),
                    )
                if not isinstance(output_label, Label):
                    raise TypeError("result_labeler must return a Label")
            except Exception:
                output_label = Label(
                    integrity="untrusted",
                    origins=frozenset({f"unclassified_agentdojo_tool_output:{function_name}"}),
                )

            output_labels = state.setdefault("paca_output_labels", {})
            if not isinstance(output_labels, dict):
                output_labels = {}
                state["paca_output_labels"] = output_labels
            output_labels[str(call_id)] = output_label

            try:
                formatted_result = self.output_formatter(result)
            except Exception as exc:
                # The tool function has already returned. Do not label this as a
                # denied or unexecuted action; only result formatting failed.
                tool_call_results.append(self._tool_call_result(
                    tool_call,
                    "The tool function returned, but its result could not be formatted.",
                    error=f"Output formatting failed ({type(exc).__name__}).",
                ))
                continue
            tool_call_results.append(self._tool_call_result(
                tool_call,
                formatted_result,
                error=error,
            ))

        return query, runtime, env, [*messages, *tool_call_results], state


__all__ = [
    "PacaToolsExecutor",
    "aggregate_prior_output_labels",
    "RAW_ARGUMENTS_KEY",
]
