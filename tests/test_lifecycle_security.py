import pytest

from paca.lifecycle import (
    LifecycleSecurityController,
    LifecycleSecurityError,
)
from paca.provenance import Arg, Label
from paca.runtime import Capability, Request, Tool


def _tool(name="mail"):
    return Tool(
        name=name,
        version="1.0.0",
        description="test tool",
        schema=("to", "body"),
        implementation_digest="a" * 64,
    )


def _request(*, action="send_email", trusted=True, complete=True, tool=True, task="task-1"):
    label = Label(
        "trusted" if trusted else "untrusted",
        tenant="acme",
        origins=frozenset({"connector"}),
    )
    ref = frozenset({"lineage-1"}) if complete else frozenset()
    arg = Arg("bob@corp.example" if action == "send_email" else "inbox", label, ref, not complete)
    body = Arg("report", label, ref, not complete)
    manifest = _tool() if tool else None
    capability = Capability(
        cap_id="cap-1",
        principal="agent-1",
        tenant="acme",
        task_id=task,
        role="assistant",
        grants={action: ("*",)},
        expires=9999999999,
        tool_pins={manifest.name: manifest.hash} if manifest else {},
    )
    args = {"to": arg, "body": body} if action == "send_email" else {"folder": arg}
    return Request(action, args, capability, 1, tool=manifest)


def _controller():
    controller = LifecycleSecurityController()
    controller.start_session(
        session_id="session-1",
        principal="agent-1",
        tenant="acme",
        task_id="task-1",
        purpose="test",
    )
    return controller


def test_untrusted_content_can_be_read_but_not_used_for_egress():
    controller = _controller()
    assert controller.authorize_request(
        _request(action="read_mail", trusted=False, complete=False)
    )
    with pytest.raises(LifecycleSecurityError, match="untrusted content"):
        controller.authorize_request(_request(trusted=False))


def test_consequential_request_requires_complete_lineage_and_pinned_tool():
    controller = _controller()
    with pytest.raises(LifecycleSecurityError, match="complete trusted lineage"):
        controller.authorize_request(_request(complete=False))
    with pytest.raises(LifecycleSecurityError, match="typed tool manifest"):
        controller.authorize_request(_request(tool=False))


def test_session_binding_kill_switch_and_one_use_commit():
    controller = _controller()
    request = _request()
    controller.commit_authorization(request)
    with pytest.raises(LifecycleSecurityError, match="already been committed"):
        controller.commit_authorization(request)
    with pytest.raises(LifecycleSecurityError, match="active session"):
        controller.authorize_request(_request(task="other-task"))
    controller.stop("incident-42")
    with pytest.raises(LifecycleSecurityError, match="stopped"):
        controller.authorize_request(request)
    assert any(event.operation == "kill_switch" for event in controller.audit_events)

