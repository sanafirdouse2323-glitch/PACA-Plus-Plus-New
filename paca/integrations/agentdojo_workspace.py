"""Task-scoped read-operation mapper for AgentDojo's v1.2.2 workspace suite.

Only the read/search operations listed in SUPPORTED_WORKSPACE_READ_TOOLS are
mapped. All mutating workspace tools intentionally remain unsupported and are
rejected by the request builder. Resource labels and capabilities must come from
trusted application/evaluation setup, never from model output or retrieved content.
"""
from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any

from ..provenance import Arg, Label
from ..runtime import Capability, Request
from .agentdojo import aggregate_prior_output_labels

WorkspaceResourceLabeler = Callable[[str, dict[str, Any], Any], Label]


# (PACA action, source label domain, target scope, accepted args, required args)
# The names and argument keys are taken from AgentDojo's v1 workspace tools.
_MAIL_TOOLS: dict[str, tuple[str, str, frozenset[str], frozenset[str]]] = {
    "get_unread_emails": (
        "mark_mail_read",
        "mail:inbox:unread",
        frozenset(),
        frozenset(),
    ),
    "get_sent_emails": ("read_mail", "mail:sent", frozenset(), frozenset()),
    "get_received_emails": ("read_mail", "mail:received", frozenset(), frozenset()),
    "get_draft_emails": ("read_mail", "mail:drafts", frozenset(), frozenset()),
    "search_emails": (
        "read_mail", "mail:search", frozenset({"query", "sender"}), frozenset({"query"})
    ),
    "search_contacts_by_name": (
        "read_mail",
        "mail:contacts:name",
        frozenset({"query"}),
        frozenset({"query"}),
    ),
    "search_contacts_by_email": (
        "read_mail",
        "mail:contacts:email",
        frozenset({"query"}),
        frozenset({"query"}),
    ),
}

_CALENDAR_TOOLS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "get_current_day": (frozenset(), frozenset()),
    "get_day_calendar_events": (frozenset({"day"}), frozenset({"day"})),
    "search_calendar_events": (
        frozenset({"query", "date"}),
        frozenset({"query"}),
    ),
}

_DRIVE_TOOLS: dict[str, tuple[str, frozenset[str], frozenset[str]]] = {
    "get_file_by_id": ("drive:file", frozenset({"file_id"}), frozenset({"file_id"})),
    "list_files": ("drive:list:all", frozenset(), frozenset()),
    "search_files": ("drive:search:content", frozenset({"query"}), frozenset({"query"})),
    "search_files_by_filename": (
        "drive:search:filename",
        frozenset({"filename"}),
        frozenset({"filename"}),
    ),
}

SUPPORTED_WORKSPACE_READ_TOOLS = frozenset(
    {*_MAIL_TOOLS, *_CALENDAR_TOOLS, *_DRIVE_TOOLS}
)


@dataclass(frozen=True)
class WorkspaceTaskContext:
    """Trusted, task-specific inputs for a workspace request builder.

    capability must be minted by the evaluation/application setup from the user
    task's authority. resource_labeler must return labels from trusted fixture or
    connector metadata. This mapper does not infer sensitivity from file names,
    message contents, event text, or model-generated claims.
    """

    capability: Capability
    resource_labeler: WorkspaceResourceLabeler
    initial_step: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.capability, Capability):
            raise TypeError("capability must be a PACA++ Capability")
        if not callable(self.resource_labeler):
            raise TypeError("resource_labeler must be callable")
        if (
            isinstance(self.initial_step, bool)
            or not isinstance(self.initial_step, int)
            or self.initial_step < 1
        ):
            raise ValueError("initial_step must be a positive integer")
        for name in ("cap_id", "principal", "tenant", "task_id", "role"):
            value = getattr(self.capability, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"capability.{name} must be a non-empty string")
        allowed_actions = {"read_mail", "mark_mail_read", "read_calendar", "read_drive"}
        if not isinstance(self.capability.grants, Mapping):
            raise TypeError("capability.grants must be a mapping")
        for action, patterns in self.capability.grants.items():
            if action not in allowed_actions:
                raise ValueError(f"unsupported workspace capability action: {action!r}")
            if not isinstance(patterns, (tuple, list)):
                raise TypeError(f"capability grants for {action!r} must be a tuple or list")
            if any(not isinstance(pattern, str) or not pattern.strip() for pattern in patterns):
                raise ValueError(f"capability grants for {action!r} must contain non-empty strings")
        for name in ("expires", "max_calls", "max_fanout"):
            value = getattr(self.capability, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"capability.{name} must be a positive integer")
        if self.initial_step > self.capability.expires:
            raise ValueError("initial_step must not exceed capability.expires")
        if self.capability.calls < 0 or self.capability.calls >= self.capability.max_calls:
            raise ValueError("capability.calls must be non-negative and below max_calls")


def _validate_arguments(
    function_name: str,
    arguments: Mapping[str, Any],
    allowed: frozenset[str],
    required: frozenset[str],
) -> None:
    supplied = set(arguments)
    unexpected = supplied - allowed
    missing = required - supplied
    if unexpected:
        raise ValueError(
            f"{function_name} received unsupported argument keys: {sorted(unexpected)}"
        )
    if missing:
        raise ValueError(
            f"{function_name} is missing required argument keys: {sorted(missing)}"
        )


def _required_string(arguments: Mapping[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_string(arguments: Mapping[str, Any], name: str) -> str | None:
    value = arguments.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string or None")
    return value


def _iso_date(value: str, name: str) -> str:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid YYYY-MM-DD date") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"{name} must use YYYY-MM-DD format")
    return value


def _argument_label(extra_args: Mapping[str, Any], name: str) -> Label:
    """Treat model arguments as untrusted and preserve prior tool-output lineage."""
    model_label = Label(
        integrity="untrusted",
        origins=frozenset({f"agentdojo_model_argument:{name}"}),
    )
    prior_outputs = aggregate_prior_output_labels(extra_args)
    return Label.join(model_label, prior_outputs)


def _resource_label(
    context: WorkspaceTaskContext,
    source: str,
    arguments: Mapping[str, Any],
    env: Any,
) -> Label:
    label = context.resource_labeler(source, copy.deepcopy(dict(arguments)), env)
    if not isinstance(label, Label):
        raise TypeError(
            "resource_labeler must return a PACA++ Label for "
            f"the {source!r} source"
        )
    if label.integrity != "untrusted":
        raise ValueError(
            f"AgentDojo {source!r} resources must be labelled untrusted"
        )
    if context.capability.tenant not in label.tenants:
        raise ValueError(
            f"AgentDojo {source!r} resource label must include the capability tenant"
        )
    return label


def make_workspace_request_builder(context: WorkspaceTaskContext):
    """Create a PACA++ request builder for supported AgentDojo workspace reads.

    Supported calls:
      * Email: get_unread_emails, get_sent_emails, get_received_emails,
        get_draft_emails, search_emails, search_contacts_by_name,
        search_contacts_by_email.
      * Calendar: get_current_day, get_day_calendar_events,
        search_calendar_events.
      * Cloud drive: get_file_by_id, list_files, search_files,
        search_files_by_filename.

    Write, delete, send, share, and calendar-mutation calls raise ValueError.
    PacaToolsExecutor converts that error into a denied tool result before dispatch.
    """
    if not isinstance(context, WorkspaceTaskContext):
        raise TypeError("context must be a WorkspaceTaskContext")

    capability = context.capability

    def request_builder(
        function_name: str,
        arguments: dict[str, Any],
        env: Any,
        extra_args: dict[str, Any],
    ) -> Request:
        if not isinstance(arguments, Mapping):
            raise TypeError("workspace tool arguments must be a mapping")

        normalized = copy.deepcopy(dict(arguments))

        if function_name in _MAIL_TOOLS:
            action, target, allowed, required = _MAIL_TOOLS[function_name]
            _validate_arguments(function_name, normalized, allowed, required)
            if function_name == "search_emails":
                _required_string(normalized, "query")
                _optional_string(normalized, "sender")
            elif function_name in {"search_contacts_by_name", "search_contacts_by_email"}:
                _required_string(normalized, "query")

            request_args: dict[str, Arg] = {
                "folder": Arg(
                    target,
                    Label(
                        integrity="trusted",
                        origins=frozenset({"agentdojo_workspace_tool_mapping"}),
                    ),
                )
            }
            for name, value in normalized.items():
                request_args[name] = Arg(value, _argument_label(extra_args, name))
            resource_label = _resource_label(context, "mail", normalized, env)
            return Request(
                action=action,
                args=request_args,
                cap=capability,
                step=context.initial_step,
                resource=resource_label,
            )

        if function_name in _CALENDAR_TOOLS:
            allowed, required = _CALENDAR_TOOLS[function_name]
            _validate_arguments(function_name, normalized, allowed, required)
            if function_name == "get_current_day":
                target = "calendar:current_day"
                dynamic_target = False
            elif function_name == "get_day_calendar_events":
                day = _iso_date(_required_string(normalized, "day"), "day")
                target = f"calendar:day:{day}"
                dynamic_target = True
            else:
                _required_string(normalized, "query")
                event_date = _optional_string(normalized, "date")
                if event_date is not None:
                    event_date = _iso_date(event_date, "date")
                target = f"calendar:search:{event_date or 'all'}"
                dynamic_target = True

            target_label = Label(
                integrity="untrusted" if dynamic_target else "trusted",
                origins=frozenset({"agentdojo_workspace_tool_mapping"})
                if not dynamic_target
                else frozenset({"agentdojo_model_argument:calendar_scope"}),
            )
            request_args = {"resource": Arg(target, target_label)}
            for name, value in normalized.items():
                request_args[name] = Arg(value, _argument_label(extra_args, name))
            resource_label = _resource_label(context, "calendar", normalized, env)
            return Request(
                action="read_calendar",
                args=request_args,
                cap=capability,
                step=context.initial_step,
                resource=resource_label,
            )

        if function_name in _DRIVE_TOOLS:
            target_prefix, allowed, required = _DRIVE_TOOLS[function_name]
            _validate_arguments(function_name, normalized, allowed, required)
            if function_name == "get_file_by_id":
                file_id = _required_string(normalized, "file_id")
                target = f"{target_prefix}:{file_id}"
                dynamic_target = True
            else:
                target = target_prefix
                dynamic_target = False
                if function_name == "search_files":
                    _required_string(normalized, "query")
                elif function_name == "search_files_by_filename":
                    _required_string(normalized, "filename")

            target_label = Label(
                integrity="untrusted" if dynamic_target else "trusted",
                origins=frozenset({"agentdojo_model_argument:drive_scope"})
                if dynamic_target
                else frozenset({"agentdojo_workspace_tool_mapping"}),
            )
            request_args = {"resource": Arg(target, target_label)}
            for name, value in normalized.items():
                request_args[name] = Arg(value, _argument_label(extra_args, name))
            resource_label = _resource_label(context, "drive", normalized, env)
            return Request(
                action="read_drive",
                args=request_args,
                cap=capability,
                step=context.initial_step,
                resource=resource_label,
            )

        raise ValueError(
            f"Unsupported AgentDojo workspace tool for this read-scoped mapper: {function_name}"
        )

    return request_builder


__all__ = [
    "SUPPORTED_WORKSPACE_READ_TOOLS",
    "WorkspaceTaskContext",
    "make_workspace_request_builder",
]
