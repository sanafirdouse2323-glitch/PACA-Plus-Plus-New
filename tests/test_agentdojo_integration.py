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
    assert state["paca_output_labels"]["call-1:1"].sensitivity == 2
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


def test_agentdojo_adapter_advances_step_for_repeated_calls_under_one_capability():
    cap = Capability(
        "cap-step", "user@example.test", "tenant-a", "task-step", "assistant",
        {"read_file": ("/tenant-a/report.txt",)}, expires=100,
    )
    observed_steps: list[int] = []

    def request_builder(function_name, arguments, env, extra_args):
        request = Request(
            "read_file",
            {"path": Arg(arguments["path"], Label("untrusted"))},
            cap,
            step=1,
            resource=Label("untrusted", sensitivity=1, tenant="tenant-a"),
        )
        observed_steps.append(request.step)
        return request

    runtime = RuntimeStub(["read_report"])
    monitor = Monitor()
    executor = PacaToolsExecutor(monitor, request_builder)
    _run(executor, runtime, "read_report", {"path": "/tenant-a/report.txt"})
    _run(executor, runtime, "read_report", {"path": "/tenant-a/report.txt"})

    assert observed_steps == [1, 1]  # builder may reuse an initial step
    assert len(runtime.calls) == 2
    assert executor._last_steps[cap.cap_id] == 2
    assert [entry["step"] for entry in monitor.audit.entries if "step" in entry] == [1, 2]


def test_agentdojo_adapter_does_not_claim_tool_was_not_executed_after_runtime_error():
    cap = Capability(
        "cap-runtime-error", "user@example.test", "tenant-a", "task-runtime-error", "assistant",
        {"read_file": ("/tenant-a/report.txt",)}, expires=100,
    )

    def request_builder(function_name, arguments, env, extra_args):
        return Request(
            "read_file",
            {"path": Arg(arguments["path"], Label("untrusted"))},
            cap,
            step=1,
            resource=Label("untrusted", sensitivity=1, tenant="tenant-a"),
        )

    class RaisingRuntime(RuntimeStub):
        def run_function(self, env, function_name, arguments):
            self.calls.append((function_name, arguments))
            raise RuntimeError("downstream connector failed after dispatch")

    runtime = RaisingRuntime(["read_report"])
    executor = PacaToolsExecutor(Monitor(), request_builder)

    with pytest.raises(RuntimeError, match="downstream connector failed"):
        _run(executor, runtime, "read_report", {"path": "/tenant-a/report.txt"})

    assert len(runtime.calls) == 1


def test_aggregate_prior_output_labels_fails_closed_on_any_unlabelled_entry():
    valid = Label("trusted", sensitivity=0, tenant="tenant-a")
    result = aggregate_prior_output_labels({"paca_output_labels": {"first": valid, "second": "missing-label"}})

    assert result.integrity == "untrusted"
    assert "unknown_agentdojo_lineage" in result.origins


def test_agentdojo_adapter_accepts_only_verifier_accepted_approval_evidence():
    cap = Capability(
        "cap-approved", "user@example.test", "tenant-a", "task-approved", "assistant",
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
    monitor = Monitor(approval_verifier=lambda request, evidence: evidence == "signed-approval-evidence")
    executor = PacaToolsExecutor(
        monitor,
        request_builder,
        approval_provider=lambda request, decision, env, state: "signed-approval-evidence",
    )
    _run(executor, runtime, "send_update", {
        "recipient": "person@partner.example",
        "body": "public update",
    })

    assert len(runtime.calls) == 1


def test_agentdojo_adapter_rejects_boolean_approval_callback():
    cap = Capability(
        "cap-bool-approval", "user@example.test", "tenant-a", "task-bool-approval", "assistant",
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
    monitor = Monitor(approval_verifier=lambda request, evidence: True)
    executor = PacaToolsExecutor(
        monitor,
        request_builder,
        approval_provider=lambda request, decision, env, state: True,  # type: ignore[return-value]
    )
    _, _, _, messages, _ = _run(executor, runtime, "send_update", {
        "recipient": "person@partner.example",
        "body": "public update",
    })

    assert runtime.calls == []
    assert "integration error" in messages[-1]["error"]


def test_agentdojo_adapter_does_not_overwrite_output_labels_when_call_id_repeats():
    cap = Capability(
        "cap-reused-call-id", "user@example.test", "tenant-a", "task-reused-call-id", "assistant",
        {"read_file": ("/tenant-a/report.txt",)}, expires=100,
    )

    def request_builder(function_name, arguments, env, extra_args):
        return Request(
            "read_file",
            {"path": Arg(arguments["path"], Label("untrusted"))},
            cap,
            step=1,
            resource=Label(
                "untrusted", sensitivity=3, tenant="tenant-a",
                origins=frozenset({"sensitive_report_store"}),
            ),
        )

    runtime = RuntimeStub(["read_report"], result="report")
    executor = PacaToolsExecutor(Monitor(), request_builder)
    state = {
        "paca_output_labels": {
            "call-1:prior": Label(
                "untrusted", sensitivity=1, tenant="tenant-a",
                origins=frozenset({"earlier_result"}),
            )
        }
    }

    _run(executor, runtime, "read_report", {"path": "/tenant-a/report.txt"}, state)

    labels = state["paca_output_labels"]
    assert "call-1:prior" in labels
    assert "call-1:1" in labels
    assert labels["call-1:prior"].sensitivity == 1
    assert labels["call-1:1"].sensitivity == 3
    assert aggregate_prior_output_labels(state).sensitivity == 3



def test_agentdojo_adapter_rejects_monitor_with_effect_token_check_disabled():
    monitor = Monitor(disable={"C13"})

    with pytest.raises(ValueError, match="C13 effect-token verification cannot be disabled"):
        PacaToolsExecutor(monitor, lambda *args: None)


def test_agentdojo_adapter_fails_closed_when_request_builder_mutates_arguments():
    cap = Capability(
        "cap-mutation", "user@example.test", "tenant-a", "task-mutation", "assistant",
        {"read_file": ("/tenant-a/report.txt",)}, expires=100,
    )

    def request_builder(function_name, arguments, env, extra_args):
        # Simulate a mapper accidentally replacing an attacker-selected target
        # with an allowed one while preparing the policy request.
        arguments["path"] = "/tenant-a/report.txt"
        return Request(
            "read_file",
            {"path": Arg(arguments["path"], Label("untrusted", origins=frozenset({"tool_call"})))},
            cap,
            step=1,
            resource=Label("untrusted", sensitivity=1, tenant="tenant-a"),
        )

    runtime = RuntimeStub(["read_report"])
    executor = PacaToolsExecutor(Monitor(), request_builder)
    _, _, _, messages, _ = _run(
        executor,
        runtime,
        "read_report",
        {"path": "/tenant-a/attacker-selected.txt"},
    )

    assert runtime.calls == []
    assert "integration error (ValueError)" in messages[-1]["error"]
    assert "attacker-selected" not in messages[-1]["error"]


def test_agentdojo_adapter_fails_closed_when_effect_token_verification_fails(monkeypatch):
    cap = Capability(
        "cap-verify-failure", "user@example.test", "tenant-a", "task-verify-failure", "assistant",
        {"read_file": ("/tenant-a/report.txt",)}, expires=100,
    )

    def request_builder(function_name, arguments, env, extra_args):
        return Request(
            "read_file",
            {"path": Arg(arguments["path"], Label("untrusted"))},
            cap,
            step=1,
            resource=Label("untrusted", sensitivity=1, tenant="tenant-a"),
        )

    runtime = RuntimeStub(["read_report"])
    monitor = Monitor()
    monkeypatch.setattr(monitor, "verify", lambda request, decision: False)
    executor = PacaToolsExecutor(monitor, request_builder)
    _, _, _, messages, _ = _run(
        executor,
        runtime,
        "read_report",
        {"path": "/tenant-a/report.txt"},
    )

    assert runtime.calls == []
    assert "effect-token verification failed" in messages[-1]["error"]


def test_agentdojo_adapter_advances_steps_for_multiple_calls_in_one_dispatch():
    cap = Capability(
        "cap-multi-call", "user@example.test", "tenant-a", "task-multi-call", "assistant",
        {"read_file": ("/tenant-a/report.txt",)}, expires=100,
    )

    def request_builder(function_name, arguments, env, extra_args):
        return Request(
            "read_file",
            {"path": Arg(arguments["path"], Label("untrusted"))},
            cap,
            step=1,
            resource=Label("untrusted", sensitivity=1, tenant="tenant-a"),
        )

    runtime = RuntimeStub(["read_report"])
    monitor = Monitor()
    executor = PacaToolsExecutor(monitor, request_builder)
    calls = [
        FunctionCall(function="read_report", args={"path": "/tenant-a/report.txt"}, id="multi-1"),
        FunctionCall(function="read_report", args={"path": "/tenant-a/report.txt"}, id="multi-2"),
    ]
    messages = [{
        "role": "assistant",
        "content": None,
        "tool_calls": calls,
    }]

    _, _, _, result_messages, _ = executor.query("task", runtime, object(), messages, {})

    assert len(runtime.calls) == 2
    assert len(result_messages) == 3
    assert [entry["step"] for entry in monitor.audit.entries if "step" in entry] == [1, 2]


def test_agentdojo_adapter_metrics_count_verified_dispatches():
    cap = Capability(
        "cap-metrics-allow", "user@example.test", "tenant-a", "task-metrics-allow", "assistant",
        {"read_file": ("/tenant-a/report.txt",)}, expires=100,
    )

    def request_builder(function_name, arguments, env, extra_args):
        return Request(
            "read_file",
            {"path": Arg(arguments["path"], Label("untrusted"))},
            cap,
            step=1,
            resource=Label("untrusted", sensitivity=1, tenant="tenant-a"),
        )

    runtime = RuntimeStub(["read_report"])
    executor = PacaToolsExecutor(Monitor(), request_builder)
    _run(executor, runtime, "read_report", {"path": "/tenant-a/report.txt"})

    assert executor.metrics["tool_calls_seen"] == 1
    assert executor.metrics["denied_calls"] == 0
    assert executor.metrics["authorized_dispatches"] == 1
    assert executor.metrics["dispatch_attempts"] == 1
    assert executor.metrics["policy_decision_ns"] > 0


def test_agentdojo_adapter_metrics_count_fail_closed_mapper_denials():
    def request_builder(function_name, arguments, env, extra_args):
        raise ValueError("unmapped task operation")

    runtime = RuntimeStub(["unknown_workspace_operation"])
    executor = PacaToolsExecutor(Monitor(), request_builder)
    _run(executor, runtime, "unknown_workspace_operation", {"target": "outside-scope"})

    assert runtime.calls == []
    assert executor.metrics["tool_calls_seen"] == 1
    assert executor.metrics["denied_calls"] == 1
    assert executor.metrics["authorized_dispatches"] == 0
    assert executor.metrics["dispatch_attempts"] == 0
    assert executor.metrics["policy_decision_ns"] > 0
