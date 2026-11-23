"""Sandbox-boundary regression cases inspired by public agent-containment reports.

These tests exercise PACA++ New's reference monitor and a tiny, hand-authored
sandbox-style comparator. They do not launch OpenShell, OpenAI sandbox workloads,
microVMs, DPU watchdogs, real artifact services, or external agents. The artifact
store below is a protocol fixture used to test ordering and provenance preservation.
"""
from __future__ import annotations

from typing import Optional

from paca.baselines import SandboxScoped
from paca.monitor import Monitor
from paca.provenance import Arg, Label, derive
from paca.runtime import Capability, Request


def _capability(
    cap_id: str,
    task_id: str,
    tenant: str,
    grants: dict[str, tuple[str, ...]],
    role: str = "devops",
) -> Capability:
    return Capability(
        cap_id=cap_id,
        principal=f"agent@{tenant}",
        tenant=tenant,
        task_id=task_id,
        role=role,
        grants=grants,
        expires=100,
        max_calls=20,
    )


class _ArtifactStore:
    """In-memory test fixture; not a production persistence adapter."""

    def __init__(self) -> None:
        self._items: dict[str, Arg] = {}
        self.reads = 0

    def put(self, key: str, value: Arg) -> None:
        # Persist the Arg itself so its label is not silently discarded.
        self._items[key] = value

    def get(self, key: str) -> Optional[Arg]:
        self.reads += 1
        return self._items.get(key)


def _authorised(monitor: Monitor, request: Request) -> bool:
    decision = monitor.decide(request)
    return decision.verdict == "allow" and monitor.verify(request, decision)


def test_cross_session_artifact_reuse_keeps_untrusted_label_and_blocks_effect():
    store = _ArtifactStore()
    source = Arg(
        "make publish-secrets",
        Label(
            "untrusted",
            origins=frozenset({"prior_agent", "shared_artifact_store"}),
        ),
    )

    # Session A is allowed to save untrusted research notes. The write permission
    # does not convert the content into trusted instructions.
    writer_cap = _capability(
        "writer-cap",
        "writer-task",
        "acme",
        {"mem_write": ("notes/shared/*",)},
    )
    write_request = Request(
        "mem_write",
        {
            "key": Arg(
                "notes/shared/release-plan",
                Label("trusted", origins=frozenset({"configured_memory_key"})),
            ),
            "value": source,
        },
        writer_cap,
        1,
    )
    assert _authorised(Monitor(), write_request)
    store.put("notes/shared/release-plan", write_request.args["value"])

    # A fresh agent session retrieves the same stored Arg. The adapter contract
    # under test is to preserve the label; a real persistent store adapter is
    # still outstanding in the repository.
    received = store.get("notes/shared/release-plan")
    assert received is not None
    assert received.label.integrity == "untrusted"
    assert "shared_artifact_store" in received.label.origins

    # Simulate a model summary/compaction step. Explicit derivation must not
    # upgrade trust or erase the source origin.
    compacted = derive("release checklist", received)
    command = derive("make publish-secrets", compacted)
    assert command.label.integrity == "untrusted"
    assert "shared_artifact_store" in command.label.origins

    reader_cap = _capability(
        "reader-cap",
        "reader-task",
        "acme",
        {"run_command": ("make *",)},
    )
    request = Request(
        "run_command",
        {"command": command},
        reader_cap,
        1,
    )

    # The current sandbox comparator models path/process/host allow-lists only.
    # It is intentionally blind to information provenance; this is not a claim
    # about NVIDIA OpenShell or OpenAI's sandbox implementation.
    assert SandboxScoped().decide(request).verdict == "allow"

    decision = Monitor().decide(request)
    assert decision.verdict == "deny"
    assert "C4b" in decision.checks


def test_cross_tenant_memory_read_is_denied_before_artifact_value_lookup():
    store = _ArtifactStore()
    store.put(
        "shared/acme/quarterly-report",
        Arg(
            "restricted quarterly report",
            Label(
                "trusted",
                sensitivity=3,
                tenant="acme",
                origins=frozenset({"acme_memory_store"}),
            ),
        ),
    )

    reader_cap = _capability(
        "globex-reader-cap",
        "globex-task",
        "globex",
        {"mem_read": ("shared/*",)},
        role="assistant",
    )
    key = "shared/acme/quarterly-report"
    request = Request(
        "mem_read",
        {
            "key": Arg(
                key,
                Label("trusted", origins=frozenset({"agent_memory_lookup"})),
            )
        },
        reader_cap,
        1,
        resource=store._items[key].label,
    )

    monitor = Monitor()
    decision = monitor.decide(request)
    assert decision.verdict == "deny"
    assert "C6" in decision.checks

    # Model the required connector ordering: only fetch the value after both
    # authorisation and token verification. A production adapter implementing
    # this contract is not yet present.
    retrieved = None
    if decision.verdict == "allow" and monitor.verify(request, decision):
        retrieved = store.get(key)

    assert retrieved is None
    assert store.reads == 0
