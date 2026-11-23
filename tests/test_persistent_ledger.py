from __future__ import annotations

import os
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from paca.ledger import CapabilityConflict, SQLiteOperationLedger
from paca.monitor import Monitor
from paca.provenance import Arg, Label
from paca.runtime import Capability, Request


def make_capability(**overrides):
    values = {
        "cap_id": "persistent-capability",
        "principal": "test-user",
        "tenant": "tenant-a",
        "task_id": "persistent-task",
        "role": "assistant",
        "grants": {"read_file": ("/tenant-a/*",)},
        "expires": 100,
        "max_calls": 1,
        "max_fanout": 1,
    }
    values.update(overrides)
    return Capability(**values)


def read_request(capability, path="/tenant-a/report.txt", step=1):
    return Request(
        "read_file",
        {"path": Arg(path, Label("trusted", tenant="tenant-a"))},
        capability,
        step,
    )


def test_ledger_persists_budget_and_consumed_token_across_monitor_restart(tmp_path):
    database = tmp_path / "state" / "paca.sqlite3"
    first_ledger = SQLiteOperationLedger(database)
    first_monitor = Monitor(ledger=first_ledger)
    capability = make_capability()

    decision = first_monitor.decide(read_request(capability))
    assert decision.verdict == "allow"
    assert decision.token
    assert first_monitor.verify(read_request(capability), decision)
    assert not first_monitor.verify(read_request(capability), decision)

    # A new Monitor and ledger object see the committed call count after restart.
    second_ledger = SQLiteOperationLedger(database)
    second_monitor = Monitor(ledger=second_ledger)
    second_capability = make_capability()
    exhausted = second_monitor.decide(read_request(second_capability, step=2))
    assert exhausted.verdict == "deny"
    assert "C2" in exhausted.checks

    operations = second_ledger.operations("persistent-task")
    assert [item["execution_state"] for item in operations] == [
        "consumed",
        "not_executed",
    ]
    assert stat.S_IMODE(os.stat(database).st_mode) & 0o077 == 0


def test_token_consumption_is_atomic_across_two_ledger_instances(tmp_path):
    database = tmp_path / "shared.sqlite3"
    ledger_a = SQLiteOperationLedger(database)
    ledger_b = SQLiteOperationLedger(database)
    monitor = Monitor(ledger=ledger_a)
    capability = make_capability(max_calls=5)
    request = read_request(capability)

    decision = monitor.decide(request)
    assert decision.verdict == "allow" and decision.token

    def consume(ledger):
        return ledger.consume_token(decision.token, request.digest)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(consume, (ledger_a, ledger_b)))
    assert sorted(results) == [False, True]


def test_concurrent_authorizations_cannot_exceed_persisted_call_budget(tmp_path):
    database = tmp_path / "concurrent.sqlite3"
    capability_id = "one-call-capability"

    def authorize(step):
        ledger = SQLiteOperationLedger(database)
        monitor = Monitor(ledger=ledger)
        cap = make_capability(cap_id=capability_id, max_calls=1)
        request = read_request(cap, f"/tenant-a/report-{step}.txt", step)
        decision = monitor.decide(request)
        return decision.verdict, decision.checks

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(authorize, range(1, 9)))

    assert sum(verdict == "allow" for verdict, _ in results) == 1
    assert sum("C2" in checks for _, checks in results) == 7


def test_capability_id_cannot_be_reused_with_changed_authority(tmp_path):
    ledger = SQLiteOperationLedger(tmp_path / "authority.sqlite3")
    original = make_capability()
    ledger.register_capability(original)

    changed = make_capability(grants={"read_file": ("/tenant-a/private/*",)})
    with pytest.raises(CapabilityConflict):
        ledger.register_capability(changed)


def test_pending_approval_is_durable_but_does_not_add_a_quarantine_strike(tmp_path):
    ledger = SQLiteOperationLedger(tmp_path / "approval.sqlite3")
    monitor = Monitor(ledger=ledger)
    capability = make_capability(
        grants={"send_email": ("*@partner.example",)},
        max_calls=10,
    )
    request = Request(
        "send_email",
        {
            "to": Arg("person@partner.example", Label("untrusted")),
            "body": Arg("public update", Label("trusted", sensitivity=0, tenant="tenant-a")),
        },
        capability,
        1,
    )

    decision = monitor.decide(request)
    assert decision.verdict == "needs_approval"
    state = ledger.register_capability(capability)
    assert state.strikes == 0
    entries = ledger.operations("persistent-task")
    assert entries[-1]["decision"] == "needs_approval"
    assert entries[-1]["execution_state"] == "not_executed"


def test_ledger_token_expiry_is_enforced(tmp_path):
    now = [100.0]
    ledger = SQLiteOperationLedger(
        tmp_path / "expiry.sqlite3",
        token_ttl_seconds=5,
        clock=lambda: now[0],
    )
    monitor = Monitor(ledger=ledger)
    capability = make_capability()
    request = read_request(capability)
    decision = monitor.decide(request)
    assert decision.verdict == "allow" and decision.token

    now[0] = 106.0
    assert not ledger.consume_token(decision.token, request.digest)
    assert ledger.operations("persistent-task")[-1]["execution_state"] == "expired"
