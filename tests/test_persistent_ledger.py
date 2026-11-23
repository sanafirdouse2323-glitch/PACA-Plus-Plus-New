from __future__ import annotations

import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from paca.ledger import CapabilityConflict, LedgerError, SQLiteOperationLedger
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

    operations = second_ledger.operations("persistent-task", tenant="tenant-a")
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
    entries = ledger.operations("persistent-task", tenant="tenant-a")
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
    assert ledger.operations("persistent-task", tenant="tenant-a")[-1]["execution_state"] == "expired"

def test_persistent_task_state_is_scoped_by_tenant_when_task_ids_collide(tmp_path):
    ledger = SQLiteOperationLedger(tmp_path / "tenant-scoped.sqlite3")
    tenant_a = make_capability(
        cap_id="cap-tenant-a",
        tenant="tenant-a",
        task_id="shared-task-id",
        max_calls=10,
        max_fanout=1,
    )
    tenant_b = make_capability(
        cap_id="cap-tenant-b",
        tenant="tenant-b",
        task_id="shared-task-id",
        max_calls=10,
        max_fanout=1,
    )

    ledger.record_decision(
        tenant_a, "run_command", "denied-a", "deny", ("C1",), True,
    )
    first_token, failure = ledger.issue_authorization(
        tenant_a, "fetch_url", "allowed-a", destination="a.example",
        consequential=True, quarantine_after=3,
    )
    assert first_token and failure is None

    # A new destination for tenant A exceeds its own fan-out limit and records
    # another strike. These counters must not be visible to tenant B.
    denied_token, failure = ledger.issue_authorization(
        tenant_a, "fetch_url", "denied-fanout-a", destination="another.example",
        consequential=True, quarantine_after=3,
    )
    assert denied_token is None and failure == "C8"

    state_a = ledger.register_capability(tenant_a)
    assert state_a.calls == 1
    assert state_a.strikes == 2
    assert state_a.destinations == frozenset({"a.example"})

    state_b = ledger.register_capability(tenant_b)
    assert state_b.calls == 0
    assert state_b.strikes == 0
    assert state_b.destinations == frozenset()

    # Tenant B can use its own fan-out slot despite the colliding task ID.
    token_b, failure_b = ledger.issue_authorization(
        tenant_b, "fetch_url", "allowed-b", destination="b.example",
        consequential=True, quarantine_after=3,
    )
    assert token_b and failure_b is None
    state_b = ledger.register_capability(tenant_b)
    assert state_b.calls == 1
    assert state_b.strikes == 0
    assert state_b.destinations == frozenset({"b.example"})


def test_monitor_local_quarantine_is_scoped_by_tenant_and_task(tmp_path):
    monitor = Monitor(quarantine_after=1)
    tenant_a = make_capability(
        cap_id="local-cap-a",
        tenant="tenant-a",
        task_id="shared-local-task",
        grants={"run_command": ("not-the-command",)},
    )
    tenant_b = make_capability(
        cap_id="local-cap-b",
        tenant="tenant-b",
        task_id="shared-local-task",
        grants={"run_command": ("echo *",)},
    )

    denied = monitor.decide(Request(
        "run_command",
        {"command": Arg("echo safe", Label("trusted", tenant="tenant-a"))},
        tenant_a,
        1,
    ))
    assert denied.verdict == "deny"
    assert "C1" in denied.checks

    allowed = monitor.decide(Request(
        "run_command",
        {"command": Arg("echo safe", Label("trusted", tenant="tenant-b"))},
        tenant_b,
        1,
    ))
    assert allowed.verdict == "allow"
    assert "C12" not in allowed.checks


def test_monitor_local_egress_fanout_is_scoped_by_tenant_and_task():
    monitor = Monitor(quarantine_after=5)
    tenant_a = make_capability(
        cap_id="egress-cap-a",
        tenant="tenant-a",
        task_id="shared-egress-task",
        grants={"fetch_url": ("https://*",)},
        max_fanout=1,
    )
    tenant_b = make_capability(
        cap_id="egress-cap-b",
        tenant="tenant-b",
        task_id="shared-egress-task",
        grants={"fetch_url": ("https://*",)},
        max_fanout=1,
    )

    first = monitor.decide(Request(
        "fetch_url",
        {"url": Arg("https://a.example/path", Label("trusted", tenant="tenant-a"))},
        tenant_a,
        1,
    ))
    second = monitor.decide(Request(
        "fetch_url",
        {"url": Arg("https://b.example/path", Label("trusted", tenant="tenant-b"))},
        tenant_b,
        1,
    ))
    assert first.verdict == "allow"
    assert second.verdict == "allow"
    assert "C8" not in second.checks


def test_unscoped_populated_legacy_ledger_fails_closed_without_resetting_state(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE task_state (task_id TEXT PRIMARY KEY, strikes INTEGER NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE destinations (task_id TEXT NOT NULL, destination TEXT NOT NULL, "
            "PRIMARY KEY(task_id, destination))"
        )
        connection.execute(
            "INSERT INTO task_state(task_id, strikes) VALUES('legacy-task', 2)"
        )
        connection.execute(
            "INSERT INTO destinations(task_id, destination) VALUES('legacy-task', 'old.example')"
        )

    with pytest.raises(LedgerError, match="reviewed offline migration"):
        SQLiteOperationLedger(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT strikes FROM task_state WHERE task_id='legacy-task'"
        ).fetchone() == (2,)
        assert connection.execute(
            "SELECT destination FROM destinations WHERE task_id='legacy-task'"
        ).fetchone() == ("old.example",)


def test_empty_unscoped_ledger_schema_is_reinitialized_with_tenant_scope(tmp_path):
    database = tmp_path / "empty-legacy.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE task_state (task_id TEXT PRIMARY KEY, strikes INTEGER NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE destinations (task_id TEXT NOT NULL, destination TEXT NOT NULL, "
            "PRIMARY KEY(task_id, destination))"
        )

    ledger = SQLiteOperationLedger(database)
    with sqlite3.connect(database) as connection:
        task_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(task_state)")
        }
        destination_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(destinations)")
        }
        version = connection.execute(
            "SELECT value FROM ledger_meta WHERE key='schema_version'"
        ).fetchone()
    assert "task_scope" in task_columns and "task_id" not in task_columns
    assert "task_scope" in destination_columns and "task_id" not in destination_columns
    assert version == ("3",)
    assert ledger.register_capability(make_capability()).strikes == 0

def test_capability_id_cannot_be_reused_with_changed_authority_lineage(tmp_path):
    env = _environment(tmp_path)
    ledger = SQLiteOperationLedger(tmp_path / "lineage-binding.sqlite3")
    original = env["issuer"].verify(env["root"].token).capability
    ledger.register_capability(original)

    # Purpose and policy epoch live in the immutable authority record rather than
    # the mutable Capability fields. The ledger fingerprint must still bind them.
    changed_record = replace(
        original.authority_lineage,
        purpose="different-purpose",
        policy_epoch=original.authority_lineage.policy_epoch + 1,
    )
    changed = replace(original, authority_lineage=changed_record)
    with pytest.raises(CapabilityConflict):
        ledger.register_capability(changed)

def test_operation_history_is_scoped_by_tenant_and_task(tmp_path):
    ledger = SQLiteOperationLedger(tmp_path / "history-scope.sqlite3")
    tenant_a = make_capability(
        cap_id="history-a",
        tenant="tenant-a",
        task_id="same-task",
    )
    tenant_b = make_capability(
        cap_id="history-b",
        tenant="tenant-b",
        task_id="same-task",
    )
    ledger.record_decision(
        tenant_a, "read_file", "digest-a", "deny", ("C1",), True,
    )
    ledger.record_decision(
        tenant_b, "read_file", "digest-b", "deny", ("C1",), True,
    )

    with pytest.raises(ValueError, match="tenant is required"):
        ledger.operations("same-task")

    rows_a = ledger.operations("same-task", tenant="tenant-a")
    rows_b = ledger.operations("same-task", tenant="tenant-b")
    assert len(rows_a) == len(rows_b) == 1
    assert rows_a[0]["tenant"] == "tenant-a"
    assert rows_a[0]["request_digest"] == "digest-a"
    assert rows_b[0]["tenant"] == "tenant-b"
    assert rows_b[0]["request_digest"] == "digest-b"
    assert ledger.operations(tenant="tenant-a") == rows_a
    # The unfiltered API is an explicit trusted-administrator view.
    assert len(ledger.operations()) == 2


def test_populated_legacy_operation_history_fails_closed_without_tenant_mapping(tmp_path):
    database = tmp_path / "legacy-history.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE operations ("
            "operation_id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "cap_id TEXT NOT NULL, task_id TEXT NOT NULL, action TEXT NOT NULL,"
            "request_digest TEXT NOT NULL, decision TEXT NOT NULL,"
            "checks_json TEXT NOT NULL, execution_state TEXT NOT NULL, created_at REAL NOT NULL)"
        )
        connection.execute(
            "INSERT INTO operations(cap_id,task_id,action,request_digest,decision,"
            "checks_json,execution_state,created_at) "
            "VALUES('legacy-cap','same-task','read_file','old-digest','deny','[]','not_executed',1.0)"
        )

    with pytest.raises(LedgerError, match="reviewed offline migration"):
        SQLiteOperationLedger(database)

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT cap_id, task_id, request_digest FROM operations"
        ).fetchone()
    assert row == ("legacy-cap", "same-task", "old-digest")
