from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("agentdojo")

from agentdojo.functions_runtime import FunctionCall
from agentdojo.task_suite.load_suites import get_suite

from paca.integrations.agentdojo import PacaToolsExecutor
from paca.integrations.agentdojo_workspace import (
    SUPPORTED_WORKSPACE_READ_TOOLS,
    WorkspaceTaskContext,
    make_workspace_request_builder,
)
from paca.monitor import Monitor
from paca.provenance import Label
from paca.runtime import Capability


class RuntimeStub:
    def __init__(self, names: list[str], result: Any = "workspace-result") -> None:
        self.functions = {name: SimpleNamespace(name=name) for name in names}
        self.result = result
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def run_function(self, env: Any, function_name: str, arguments: dict[str, Any]):
        self.calls.append((function_name, arguments))
        return self.result, None


def _capability(grants: dict[str, tuple[str, ...]]) -> Capability:
    return Capability(
        "workspace-cap",
        "benchmark-user@example.test",
        "workspace-tenant",
        "workspace-task-1",
        "assistant",
        grants,
        expires=100,
    )


def _labeler(source: str, arguments: dict[str, Any], env: Any) -> Label:
    return {
        "mail": Label(
            "untrusted", sensitivity=2, tenant="workspace-tenant",
            origins=frozenset({"fixture:mail"}),
        ),
        "calendar": Label(
            "untrusted", sensitivity=1, tenant="workspace-tenant",
            origins=frozenset({"fixture:calendar"}),
        ),
        "drive": Label(
            "untrusted", sensitivity=3, tenant="workspace-tenant",
            origins=frozenset({"fixture:drive"}),
        ),
    }[source]


def _executor(
    function_name: str,
    arguments: dict[str, Any],
    grants: dict[str, tuple[str, ...]],
    *,
    labeler=_labeler,
):
    context = WorkspaceTaskContext(
        capability=_capability(grants),
        resource_labeler=labeler,
    )
    builder = make_workspace_request_builder(context)
    runtime = RuntimeStub([function_name])
    monitor = Monitor()
    executor = PacaToolsExecutor(monitor, builder)
    call = FunctionCall(function=function_name, args=arguments, id="workspace-call-1")
    messages = [{"role": "assistant", "content": None, "tool_calls": [call]}]
    result = executor.query("workspace task", runtime, object(), messages, {})
    return result, runtime, monitor


def test_supported_tool_names_exist_in_agentdojo_v1_2_2_workspace_suite():
    suite = get_suite("v1.2.2", "workspace")
    registered_names = {tool.name for tool in suite.tools}

    assert SUPPORTED_WORKSPACE_READ_TOOLS
    assert SUPPORTED_WORKSPACE_READ_TOOLS <= registered_names
    assert len(SUPPORTED_WORKSPACE_READ_TOOLS) == 14


def test_workspace_mapper_authorizes_mail_read_and_labels_output():
    (query, runtime_result, env, messages, state), runtime, monitor = _executor(
        "get_unread_emails",
        {},
        {"mark_mail_read": ("mail:inbox:unread",)},
    )

    assert len(runtime.calls) == 1
    assert runtime.calls[0] == ("get_unread_emails", {})
    assert messages[-1]["role"] == "tool"
    assert state["paca_output_labels"]["workspace-call-1:1"].sensitivity == 2
    assert state["paca_output_labels"]["workspace-call-1:1"].integrity == "untrusted"
    assert monitor.audit.entries[-2]["verdict"] == "allow"


def test_workspace_mapper_authorizes_exact_calendar_day_scope():
    (_, _, _, messages, state), runtime, _ = _executor(
        "get_day_calendar_events",
        {"day": "2024-05-15"},
        {"read_calendar": ("calendar:day:2024-05-15",)},
    )

    assert len(runtime.calls) == 1
    assert runtime.calls[0] == ("get_day_calendar_events", {"day": "2024-05-15"})
    assert state["paca_output_labels"]["workspace-call-1:1"].sensitivity == 1
    assert messages[-1]["error"] is None


def test_workspace_mapper_denies_calendar_day_outside_capability_scope():
    (_, _, _, messages, _), runtime, monitor = _executor(
        "get_day_calendar_events",
        {"day": "2024-05-16"},
        {"read_calendar": ("calendar:day:2024-05-15",)},
    )

    assert runtime.calls == []
    assert "PACA++ did not authorize" in messages[-1]["content"][0]["content"]
    assert "C1" in messages[-1]["error"]
    assert monitor.audit.entries[-1]["verdict"] == "deny"


def test_workspace_mapper_authorizes_one_drive_file_id():
    (_, _, _, messages, state), runtime, _ = _executor(
        "get_file_by_id",
        {"file_id": "13"},
        {"read_drive": ("drive:file:13",)},
    )

    assert runtime.calls == [("get_file_by_id", {"file_id": "13"})]
    assert state["paca_output_labels"]["workspace-call-1:1"].sensitivity == 3
    assert messages[-1]["error"] is None


def test_workspace_mapper_denies_drive_file_id_outside_capability_scope():
    (_, _, _, messages, _), runtime, _ = _executor(
        "get_file_by_id",
        {"file_id": "14"},
        {"read_drive": ("drive:file:13",)},
    )

    assert runtime.calls == []
    assert "C1" in messages[-1]["error"]


def test_workspace_mapper_denies_cross_tenant_resource_label():
    def cross_tenant_labeler(source, arguments, env):
        return Label(
            "untrusted",
            sensitivity=2,
            tenants=frozenset({"workspace-tenant", "different-tenant"}),
            origins=frozenset({"untrusted-cross-tenant-fixture"}),
        )

    (_, _, _, messages, _), runtime, _ = _executor(
        "get_unread_emails",
        {},
        {"read_mail": ("mail:inbox:unread",)},
        labeler=cross_tenant_labeler,
    )

    assert runtime.calls == []
    assert "C6" in messages[-1]["error"]


@pytest.mark.parametrize(
    ("function_name", "arguments"),
    [
        ("send_email", {"recipients": ["attacker@example.test"], "subject": "x", "body": "y"}),
        ("delete_email", {"email_id": "1"}),
        ("create_calendar_event", {"title": "x", "start_time": "2024-05-15 10:00", "end_time": "2024-05-15 11:00"}),
        ("cancel_calendar_event", {"event_id": "1"}),
        ("reschedule_calendar_event", {"event_id": "1", "new_start_time": "2024-05-15 10:00"}),
        ("add_calendar_event_participants", {"event_id": "1", "participants": ["attacker@example.test"]}),
        ("create_file", {"filename": "x.txt", "content": "x"}),
        ("append_to_file", {"file_id": "1", "content": "x"}),
        ("delete_file", {"file_id": "1"}),
        ("share_file", {"file_id": "1", "email": "attacker@example.test", "permission": "read"}),
    ],
)
def test_workspace_mapper_fails_closed_for_mutating_workspace_tools(function_name, arguments):
    (_, _, _, messages, _), runtime, _ = _executor(
        function_name,
        arguments,
        {
            "read_mail": ("*",),
            "read_calendar": ("*",),
            "read_drive": ("*",),
        },
    )

    assert runtime.calls == []
    assert "integration error (ValueError)" in messages[-1]["error"]


@pytest.mark.parametrize(
    ("function_name", "arguments"),
    [
        ("search_emails", {"query": ""}),
        ("search_contacts_by_name", {}),
        ("search_files", {"query": ""}),
        ("search_files_by_filename", {"filename": ""}),
        ("get_file_by_id", {"file_id": ""}),
        ("get_day_calendar_events", {"day": "2024-02-31"}),
        ("search_calendar_events", {"query": "meeting", "date": "15-05-2024"}),
    ],
)
def test_workspace_mapper_rejects_invalid_required_arguments(function_name, arguments):
    action = (
        "read_mail"
        if function_name in {
            "search_emails", "search_contacts_by_name"
        }
        else "read_calendar"
        if function_name in {"get_day_calendar_events", "search_calendar_events"}
        else "read_drive"
    )
    grants = {
        "read_mail": ("*",),
        "read_calendar": ("*",),
        "read_drive": ("*",),
    }
    (_, _, _, messages, _), runtime, _ = _executor(
        function_name,
        arguments,
        grants,
    )

    assert action in grants
    assert runtime.calls == []
    assert "integration error (ValueError)" in messages[-1]["error"]


def test_workspace_mapper_preserves_prior_output_lineage_on_search_arguments():
    context = WorkspaceTaskContext(
        capability=_capability({"read_mail": ("mail:search",)}),
        resource_labeler=_labeler,
    )
    builder = make_workspace_request_builder(context)
    prior = Label(
        "untrusted",
        sensitivity=3,
        tenant="workspace-tenant",
        origins=frozenset({"prior-tool-output"}),
    )

    request = builder(
        "search_emails",
        {"query": "invoice"},
        object(),
        {"paca_output_labels": {"prior-call:1": prior}},
    )

    assert request.action == "read_mail"
    assert request.args["query"].label.integrity == "untrusted"
    assert request.args["query"].label.sensitivity == 3
    assert "prior-tool-output" in request.args["query"].label.origins
    assert "agentdojo_model_argument:query" in request.args["query"].label.origins


def test_workspace_mapper_requires_trusted_resource_labeler():
    with pytest.raises(TypeError, match="resource_labeler must be callable"):
        WorkspaceTaskContext(
            capability=_capability({"read_mail": ("mail:inbox:unread",)}),
            resource_labeler=None,  # type: ignore[arg-type]
        )



def test_workspace_mapper_argument_contracts_match_agentdojo_v1_2_2_schemas():
    suite = get_suite("v1.2.2", "workspace")
    actual_tools = {tool.name: tool for tool in suite.tools}
    expected_arguments = {
        "get_unread_emails": set(),
        "get_sent_emails": set(),
        "get_received_emails": set(),
        "get_draft_emails": set(),
        "search_emails": {"query", "sender"},
        "search_contacts_by_name": {"query"},
        "search_contacts_by_email": {"query"},
        "get_current_day": set(),
        "get_day_calendar_events": {"day"},
        "search_calendar_events": {"query", "date"},
        "get_file_by_id": {"file_id"},
        "list_files": set(),
        "search_files": {"query"},
        "search_files_by_filename": {"filename"},
    }

    for tool_name, expected in expected_arguments.items():
        assert tool_name in actual_tools
        actual = set(actual_tools[tool_name].parameters.model_fields)
        assert actual == expected, f"{tool_name} schema changed: {actual!r} != {expected!r}"


def test_unread_mail_read_receipt_needs_separate_capability_action():
    (_, _, _, messages, _), runtime, monitor = _executor(
        "get_unread_emails",
        {},
        {"read_mail": ("mail:inbox:unread",)},
    )

    assert runtime.calls == []
    assert "C1" in messages[-1]["error"]
    assert monitor.audit.entries[-1]["verdict"] == "deny"


def test_workspace_mapper_rejects_resource_label_marked_trusted():
    def trusted_labeler(source, arguments, env):
        return Label(
            "trusted",
            sensitivity=1,
            tenant="workspace-tenant",
            origins=frozenset({"incorrectly-trusted-fixture"}),
        )

    (_, _, _, messages, _), runtime, _ = _executor(
        "get_sent_emails",
        {},
        {"read_mail": ("mail:sent",)},
        labeler=trusted_labeler,
    )

    assert runtime.calls == []
    assert "integration error (ValueError)" in messages[-1]["error"]


def test_workspace_mapper_rejects_resource_label_without_capability_tenant():
    def missing_tenant_labeler(source, arguments, env):
        return Label(
            "untrusted",
            sensitivity=1,
            origins=frozenset({"missing-tenant-fixture"}),
        )

    (_, _, _, messages, _), runtime, _ = _executor(
        "get_sent_emails",
        {},
        {"read_mail": ("mail:sent",)},
        labeler=missing_tenant_labeler,
    )

    assert runtime.calls == []
    assert "integration error (ValueError)" in messages[-1]["error"]


def test_workspace_context_rejects_capabilities_for_unmapped_effects():
    capability = _capability({"send_email": ("attacker@example.test",)})

    with pytest.raises(ValueError, match="unsupported workspace capability action"):
        WorkspaceTaskContext(
            capability=capability,
            resource_labeler=_labeler,
        )
