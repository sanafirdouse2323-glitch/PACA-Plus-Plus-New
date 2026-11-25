from __future__ import annotations

import hashlib
import sqlite3

import pytest

from paca.authority_runtime import (
    AuthorityRegistryError,
    HMACCapabilityAuthority,
    SQLiteAuthorityRegistry,
)
from paca.memory import canonical_value_bytes


def _environment(tmp_path):
    now = [1_000]

    def clock():
        return now[0]

    registry = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3", clock=clock)
    authority = HMACCapabilityAuthority(
        registry,
        issuer_id="test-issuer",
        key_id="test-key",
        key=b"K" * 32,
        audience="test-resource-pep",
        identity_verifier=lambda principal, tenant: (
            principal == "agent-a" and tenant == "tenant-a"
        ),
        task_context_verifier=lambda principal, tenant, task_id, purpose: (
            principal == "agent-a"
            and tenant == "tenant-a"
            and task_id == "task-a"
            and purpose == "report"
        ),
        clock=clock,
    )
    signed = authority.issue(
        principal="agent-a",
        tenant="tenant-a",
        task_id="task-a",
        purpose="report",
        grants={
            "read_file": ("reports/*",),
            "write_file": ("reports/*",),
        },
        expires_at=2_000,
        max_calls=20,
        max_fanout=2,
        tool_pins={"write_file": "test-tool-pin"},
    )
    return registry, authority, signed


def _seed_resource(registry, authority, signed):
    resource = "reports/annual.json"
    payload = {"content": "confidential report contents"}
    payload_digest = hashlib.sha256(canonical_value_bytes(payload)).hexdigest()
    permit_token = authority.issue_resource_commit_permit(
        signed.token,
        request_digest="a" * 64,
        action="write_file",
        resource=resource,
        payload_digest=payload_digest,
    )
    permit = authority.verify_resource_commit_permit(permit_token)
    provenance = {"classification": "internal", "source": "trusted-adapter"}
    registry.commit_fenced_resource_write(
        permit,
        payload,
        provenance_metadata=provenance,
    )
    return resource, payload, provenance


def _receipt(operation_id: str):
    return {
        "session_id": "session-a",
        "nonce_digest": hashlib.sha256(operation_id.encode()).hexdigest(),
        "operation_id": operation_id,
        "request_digest": hashlib.sha256(
            (operation_id + "-request").encode()
        ).hexdigest(),
    }


def _access_receipt_count(registry):
    with sqlite3.connect(registry.database) as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM paca_resource_access_receipts"
        ).fetchone()[0]


def test_fenced_write_can_bind_commit_to_authenticated_principal(tmp_path):
    registry, authority, signed = _environment(tmp_path)
    resource = "reports/annual.json"
    payload = {"content": "new report"}
    payload_digest = hashlib.sha256(canonical_value_bytes(payload)).hexdigest()
    permit = authority.verify_resource_commit_permit(
        authority.issue_resource_commit_permit(
            signed.token,
            request_digest="c" * 64,
            action="write_file",
            resource=resource,
            payload_digest=payload_digest,
        )
    )

    with pytest.raises(AuthorityRegistryError, match="active authority record"):
        registry.commit_fenced_resource_write(
            permit,
            payload,
            expected_principal="different-agent",
        )

    assert registry.usage(signed.capability.cap_id)[0] == 0
    with sqlite3.connect(registry.database) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM paca_resource_values").fetchone()[
                0
            ]
            == 0
        )


def test_fenced_read_binds_principal_and_rejects_mismatch_without_receipt(tmp_path):
    registry, authority, signed = _environment(tmp_path)
    resource, _, _ = _seed_resource(registry, authority, signed)
    used_before = registry.usage(signed.capability.cap_id)[0]

    with pytest.raises(AuthorityRegistryError, match="session does not match"):
        registry.read_fenced_resource(
            authority_id=signed.capability.cap_id,
            tenant="tenant-a",
            task_id="task-a",
            purpose="report",
            resource=resource,
            max_calls=20,
            access_receipt=_receipt("wrong-principal"),
            expected_principal="different-agent",
            max_bytes=4096,
        )

    assert registry.usage(signed.capability.cap_id)[0] == used_before
    assert _access_receipt_count(registry) == 0


def test_fenced_read_enforces_actual_disclosure_size_before_receipt_and_quota(
    tmp_path,
):
    registry, authority, signed = _environment(tmp_path)
    resource, payload, provenance = _seed_resource(registry, authority, signed)
    used_before = registry.usage(signed.capability.cap_id)[0]
    receipt = _receipt("bounded-read")
    response = {
        "found": True,
        "resource": resource,
        "version": 1,
        "action": "write_file",
        "value": payload,
        "payload_digest": hashlib.sha256(canonical_value_bytes(payload)).hexdigest(),
        "provenance_metadata": provenance,
    }
    byte_limit = len(canonical_value_bytes(response)) - 1

    with pytest.raises(AuthorityRegistryError, match="disclosure byte limit"):
        registry.read_fenced_resource(
            authority_id=signed.capability.cap_id,
            tenant="tenant-a",
            task_id="task-a",
            purpose="report",
            resource=resource,
            max_calls=20,
            access_receipt=receipt,
            expected_principal="agent-a",
            max_bytes=byte_limit,
        )

    assert registry.usage(signed.capability.cap_id)[0] == used_before
    assert _access_receipt_count(registry) == 0

    result = registry.read_fenced_resource(
        authority_id=signed.capability.cap_id,
        tenant="tenant-a",
        task_id="task-a",
        purpose="report",
        resource=resource,
        max_calls=20,
        access_receipt=receipt,
        expected_principal="agent-a",
        max_bytes=byte_limit + 1,
    )
    assert result["found"] is True
    assert result["value"] == payload
    assert result["provenance_metadata"] == provenance
    assert _access_receipt_count(registry) == 1



def test_authority_record_persists_and_enforces_per_capability_call_ceiling(
    tmp_path,
):
    registry, _, signed = _environment(tmp_path)
    authority_id = signed.capability.cap_id

    record = registry.get_authority(authority_id)
    assert record is not None
    assert record.max_calls == 20
    assert record.as_dict()["max_calls"] == 20

    # A caller cannot raise the durable per-capability limit by supplying a
    # larger max_calls argument to a generic registry operation.
    for _ in range(20):
        registry.consume_effect(authority_id, max_calls=10_000)

    with pytest.raises(AuthorityRegistryError, match="call budget is exhausted"):
        registry.consume_effect(authority_id, max_calls=10_000)

    assert registry.usage(authority_id)[0] == 20
