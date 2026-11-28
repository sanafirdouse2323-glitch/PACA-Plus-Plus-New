from __future__ import annotations

from paca.agent_runtime import PACAAgentRuntime
from paca.authority_runtime import HMACCapabilityAuthority, SQLiteAuthorityRegistry
from paca.durable import SQLiteProvenanceRepository
from paca.lifecycle import LifecyclePhase, LifecycleSecurityController
from paca.memory import (
    HMACAgentMessageCodec,
    MemoryAccessDenied,
    SQLiteMemoryValueStore,
    TrustedConnectorAdapter,
    TrustedMemoryAdapter,
)


def _environment(tmp_path):
    now = [1_000]

    def clock():
        return now[0]

    registry = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3", clock=clock)
    issuer = HMACCapabilityAuthority(
        registry,
        issuer_id="paca-lifecycle-test-issuer",
        key_id="lifecycle-test-key",
        key=b"K" * 32,
        audience="paca-lifecycle-test",
        identity_verifier=lambda principal, tenant: bool(
            principal and tenant == "acme"
        ),
        task_context_verifier=lambda principal, tenant, task_id, purpose: bool(
            principal and tenant == "acme" and task_id == "task-1" and purpose == "research"
        ),
        clock=clock,
    )
    repository = SQLiteProvenanceRepository(tmp_path / "lineage.sqlite3")
    values = SQLiteMemoryValueStore(tmp_path / "memory-values.sqlite3")
    memory = TrustedMemoryAdapter(repository, values, issuer, clock=clock)
    messages = HMACAgentMessageCodec(
        b"M" * 32,
        issuer,
        repository,
        memory=memory,
        clock=clock,
    )
    root = issuer.issue(
        principal="agent-a",
        tenant="acme",
        task_id="task-1",
        purpose="research",
        grants={
            "mem_read": ("mem/*",),
            "mem_write": ("mem/*",),
            "delegate": ("worker-b",),
            "send_agent_message": ("worker-b",),
        },
        expires_at=2_000,
        max_calls=40,
        max_fanout=5,
    )
    connector = TrustedConnectorAdapter(
        memory,
        connector_id="research-source:acme",
        source_class="external_content",
        tenant="acme",
        sensitivity=1,
        integrity="untrusted",
    )
    return {
        "clock": clock,
        "registry": registry,
        "issuer": issuer,
        "memory": memory,
        "messages": messages,
        "root": root,
        "connector": connector,
    }


def _runtime(env, capability_token: str, *, session_principal: str | None = None):
    capability = env["issuer"].verify(capability_token).capability
    lineage = capability.authority_lineage
    assert lineage is not None
    lifecycle = LifecycleSecurityController(clock=env["clock"])
    lifecycle.start_session(
        session_id=f"session:{session_principal or capability.principal}",
        principal=session_principal or capability.principal,
        tenant=capability.tenant,
        task_id=capability.task_id,
        purpose=lineage.purpose,
        policy_epoch=lineage.policy_epoch,
    )
    runtime = PACAAgentRuntime(
        env["issuer"],
        env["memory"],
        object(),
        env["messages"],
        lifecycle_security=lifecycle,
    )
    return runtime, lifecycle


def _payload(env):
    return env["connector"].ingest(
        {"text": "untrusted research source"},
        object_id="mem/source-1",
        version_id="v1",
        purpose="research",
        capability_token=env["root"].token,
    )


def _recipient(env):
    return env["issuer"].issue(
        principal="worker-b",
        tenant="acme",
        task_id="task-1",
        purpose="research",
        grants={
            "mem_read": ("mem/*",),
            "receive_agent_message": ("agent-a",),
        },
        expires_at=1_900,
        max_calls=20,
    )


def test_delegation_is_bound_to_the_active_parent_session(tmp_path):
    env = _environment(tmp_path)
    runtime, lifecycle = _runtime(
        env, env["root"].token, session_principal="other-agent"
    )

    try:
        runtime.delegate(
            env["root"].token,
            principal="worker-b",
            grants={"mem_read": ("mem/*",)},
            expires_at=1_800,
            max_calls=20,
            max_fanout=2,
        )
    except MemoryAccessDenied as exc:
        assert "outside the active session" in str(exc)
    else:
        raise AssertionError("delegation from another principal must be rejected")

    denied = [
        event
        for event in lifecycle.audit_events
        if event.phase == LifecyclePhase.DELEGATION.value
    ]
    assert denied
    assert denied[-1].decision == "deny"


def test_valid_delegation_records_a_session_bound_transition(tmp_path):
    env = _environment(tmp_path)
    runtime, lifecycle = _runtime(env, env["root"].token)

    delegated = runtime.delegate(
        env["root"].token,
        principal="worker-b",
        grants={"mem_read": ("mem/*",)},
        expires_at=1_800,
        max_calls=20,
        max_fanout=2,
    )

    assert delegated.capability.principal == "worker-b"
    events = [
        event
        for event in lifecycle.audit_events
        if event.phase == LifecyclePhase.DELEGATION.value
    ]
    assert [event.decision for event in events] == [
        "context-validated",
        "completed",
    ]
    assert events[-1].subject == "worker-b"
    assert events[-1].digest is not None


def test_message_send_is_session_bound_and_audit_does_not_store_payload(tmp_path):
    env = _environment(tmp_path)
    runtime, lifecycle = _runtime(env, env["root"].token)
    payload = _payload(env)

    sealed = runtime.send_message(
        payload,
        sender="agent-a",
        recipient="worker-b",
        capability_token=env["root"].token,
    )

    assert isinstance(sealed, str) and sealed
    events = [
        event
        for event in lifecycle.audit_events
        if event.phase == LifecyclePhase.MESSAGE.value
    ]
    assert [event.decision for event in events] == [
        "context-validated",
        "completed",
    ]
    assert events[-1].operation == "send"
    assert events[-1].subject == "worker-b"
    assert "untrusted research source" not in repr(events)


def test_message_send_rejects_a_token_outside_the_active_session(tmp_path):
    env = _environment(tmp_path)
    runtime, lifecycle = _runtime(
        env, env["root"].token, session_principal="other-agent"
    )
    payload = _payload(env)

    try:
        runtime.send_message(
            payload,
            sender="agent-a",
            recipient="worker-b",
            capability_token=env["root"].token,
        )
    except MemoryAccessDenied as exc:
        assert "outside the active session" in str(exc)
    else:
        raise AssertionError("message send from another principal must be rejected")

    events = [
        event
        for event in lifecycle.audit_events
        if event.phase == LifecyclePhase.MESSAGE.value
    ]
    assert events[-1].decision == "deny"
    assert events[-1].operation == "send"


def test_message_receive_is_bound_to_recipient_session_before_receipt_consumption(
    tmp_path,
):
    env = _environment(tmp_path)
    sender, _ = _runtime(env, env["root"].token)
    recipient = _recipient(env)
    payload = _payload(env)
    sealed = sender.send_message(
        payload,
        sender="agent-a",
        recipient="worker-b",
        capability_token=env["root"].token,
    )

    wrong_runtime, wrong_lifecycle = _runtime(
        env, recipient.token, session_principal="other-agent"
    )
    try:
        wrong_runtime.receive_message(sealed, recipient_token=recipient.token)
    except MemoryAccessDenied as exc:
        assert "outside the active session" in str(exc)
    else:
        raise AssertionError("message receive for another principal must be rejected")

    correct_runtime, lifecycle = _runtime(env, recipient.token)
    received = correct_runtime.receive_message(
        sealed,
        recipient_token=recipient.token,
    )
    assert received.value == payload.value
    assert any(
        event.phase == LifecyclePhase.MESSAGE.value
        and event.operation == "receive"
        and event.decision == "completed"
        for event in lifecycle.audit_events
    )
    assert any(
        event.phase == LifecyclePhase.MESSAGE.value
        and event.operation == "receive"
        and event.decision == "deny"
        for event in wrong_lifecycle.audit_events
    )


def test_kill_switch_blocks_context_transition_before_adapter_call(tmp_path):
    env = _environment(tmp_path)
    runtime, lifecycle = _runtime(env, env["root"].token)
    payload = _payload(env)
    lifecycle.stop("test-stop")

    try:
        runtime.send_message(
            payload,
            sender="agent-a",
            recipient="worker-b",
            capability_token=env["root"].token,
        )
    except MemoryAccessDenied as exc:
        assert "stopped" in str(exc)
    else:
        raise AssertionError("stopped lifecycle must reject message sending")

    event = lifecycle.audit_events[-1]
    assert event.phase == LifecyclePhase.MESSAGE.value
    assert event.decision == "deny"
