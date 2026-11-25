from __future__ import annotations

import hashlib
import sqlite3

import pytest

from paca.authority_runtime import (
    AuthorityRegistryError,
    HMACCapabilityAuthority,
    SQLiteAuthorityRegistry,
)
from paca.contracts import digest_object


def _broker_registry(tmp_path):
    now = [1_000]

    def clock():
        return now[0]

    registry = SQLiteAuthorityRegistry(
        tmp_path / "broker-authority.sqlite3", clock=clock
    )
    authority = HMACCapabilityAuthority(
        registry,
        issuer_id="broker-test-issuer",
        key_id="broker-test-key",
        key=b"B" * 32,
        audience="paca-broker-test",
        identity_verifier=lambda principal, tenant: (
            principal == "agent-a" and tenant == "acme"
        ),
        task_context_verifier=lambda principal, tenant, task_id, purpose: (
            principal == "agent-a"
            and tenant == "acme"
            and task_id == "task-broker"
            and purpose == "report-write"
        ),
        clock=clock,
    )
    signed = authority.issue(
        principal="agent-a",
        tenant="acme",
        task_id="task-broker",
        purpose="report-write",
        grants={
            "read_file": ("/acme/*",),
            "write_file": ("/acme/*",),
        },
        expires_at=2_000,
        max_calls=20,
        max_fanout=2,
    )
    return registry, authority, signed, clock


def _access_receipt(
    session_id: str,
    operation_id: str,
    nonce: str,
    request_digest: str,
    payload_digest: str | None = None,
):
    nonce_digest = hashlib.sha256(
        b"PACA++/BROKER-NONCE/V1\\n"
        + session_id.encode("utf-8")
        + b"\\n"
        + nonce.encode("utf-8")
    ).hexdigest()
    receipt = {
        "session_id": session_id,
        "nonce_digest": nonce_digest,
        "operation_id": operation_id,
        "request_digest": request_digest,
    }
    if payload_digest is not None:
        receipt["payload_digest"] = payload_digest
    return receipt


def test_registry_broker_write_stores_provenance_and_access_receipt_atomically(
    tmp_path,
):
    registry, authority, signed, _clock = _broker_registry(tmp_path)
    resource = "/acme/reports/report.txt"
    payload = {"content": "brokered report body"}
    payload_digest = digest_object(payload, purpose="payload")
    request_digest = digest_object(
        {"operation_id": "write-1", "resource": resource, "payload": payload},
        purpose="request",
    )
    permit_token = authority.issue_resource_commit_permit(
        signed.token,
        request_digest=request_digest,
        action="write_file",
        resource=resource,
        payload_digest=payload_digest,
    )
    permit = authority.verify_resource_commit_permit(permit_token)
    provenance = {
        "tenant": "acme",
        "task_id": "task-broker",
        "purpose": "report-write",
        "payload_digest": payload_digest,
        "integrity": "untrusted",
        "sensitivity": 2,
        "provenance_refs": ["source-object:v1"],
        "evidence_digest": digest_object(
            {"source": "source-object:v1", "payload_digest": payload_digest},
            purpose="provenance",
        ),
    }
    receipt = _access_receipt(
        "session-1", "write-1", "nonce-write-0001", request_digest, payload_digest
    )

    result = registry.commit_fenced_resource_write(
        permit,
        payload,
        access_receipt=receipt,
        provenance_metadata=provenance,
        protocol_payload_digest=True,
        expected_resource_version=0,
    )

    assert result["version"] == 1
    with sqlite3.connect(registry.database) as connection:
        metadata_row = connection.execute(
            "SELECT metadata_json FROM paca_resource_provenance "
            "WHERE tenant=? AND task_id=? AND resource_key=? AND resource_version=1",
            ("acme", "task-broker", resource),
        ).fetchone()
        access_row = connection.execute(
            "SELECT outcome,operation_id,payload_digest FROM paca_resource_access_receipts "
            "WHERE session_id=? AND nonce_digest=?",
            (receipt["session_id"], receipt["nonce_digest"]),
        ).fetchone()
    assert metadata_row is not None
    assert __import__("json").loads(metadata_row[0]) == provenance
    assert access_row == ("committed", "write-1", payload_digest)


def test_registry_broker_read_rechecks_read_scope_and_consumes_nonce_once(tmp_path):
    registry, authority, signed, _clock = _broker_registry(tmp_path)
    resource = "/acme/reports/report.txt"
    payload = {"content": "readable body"}
    payload_digest = digest_object(payload, purpose="payload")
    write_request_digest = digest_object(
        {"operation_id": "write-before-read", "resource": resource, "payload": payload},
        purpose="request",
    )
    permit = authority.verify_resource_commit_permit(
        authority.issue_resource_commit_permit(
            signed.token,
            request_digest=write_request_digest,
            action="write_file",
            resource=resource,
            payload_digest=payload_digest,
        )
    )
    provenance = {
        "tenant": "acme",
        "task_id": "task-broker",
        "purpose": "report-write",
        "payload_digest": payload_digest,
        "integrity": "untrusted",
        "sensitivity": 1,
        "provenance_refs": ["source:v1"],
        "evidence_digest": digest_object({"source": "source:v1"}, purpose="provenance"),
    }
    registry.commit_fenced_resource_write(
        permit,
        payload,
        provenance_metadata=provenance,
        protocol_payload_digest=True,
        expected_resource_version=0,
    )

    request_digest = digest_object(
        {"operation_id": "read-1", "resource": resource}, purpose="request"
    )
    receipt = _access_receipt("session-1", "read-1", "nonce-read-0001", request_digest)
    result = registry.read_fenced_resource(
        authority_id=signed.capability.cap_id,
        tenant="acme",
        task_id="task-broker",
        purpose="report-write",
        resource=resource,
        max_calls=signed.capability.max_calls,
        access_receipt=receipt,
        expected_resource_version=1,
    )
    assert result["found"] is True
    assert result["value"] == payload
    assert result["provenance_metadata"] == provenance

    with pytest.raises(AuthorityRegistryError, match="replay|duplicate"):
        registry.read_fenced_resource(
            authority_id=signed.capability.cap_id,
            tenant="acme",
            task_id="task-broker",
            purpose="report-write",
            resource=resource,
            max_calls=signed.capability.max_calls,
            access_receipt=receipt,
            expected_resource_version=1,
        )


def test_registry_broker_read_denies_when_authority_has_no_read_grant(tmp_path):
    registry, authority, _signed, _clock = _broker_registry(tmp_path)
    write_only = authority.issue(
        principal="agent-a",
        tenant="acme",
        task_id="task-broker",
        purpose="report-write",
        grants={"write_file": ("/acme/*",)},
        expires_at=2_000,
        max_calls=5,
        max_fanout=1,
    )
    request_digest = digest_object({"read": "/acme/a.txt"}, purpose="request")
    receipt = _access_receipt(
        "session-2", "read-denied", "nonce-read-denied", request_digest
    )
    with pytest.raises(AuthorityRegistryError, match="does not grant"):
        registry.read_fenced_resource(
            authority_id=write_only.capability.cap_id,
            tenant="acme",
            task_id="task-broker",
            purpose="report-write",
            resource="/acme/a.txt",
            max_calls=write_only.capability.max_calls,
            access_receipt=receipt,
        )


def test_registry_broker_write_compare_and_swap_failure_rolls_back_receipts_and_usage(
    tmp_path,
):
    registry, authority, signed, _clock = _broker_registry(tmp_path)
    resource = "/acme/reports/cas.txt"
    first_payload = {"content": "version one"}
    first_digest = digest_object(first_payload, purpose="payload")
    first_request = digest_object(
        {"operation": "first", "resource": resource}, purpose="request"
    )
    first_permit = authority.verify_resource_commit_permit(
        authority.issue_resource_commit_permit(
            signed.token,
            request_digest=first_request,
            action="write_file",
            resource=resource,
            payload_digest=first_digest,
        )
    )
    registry.commit_fenced_resource_write(
        first_permit,
        first_payload,
        protocol_payload_digest=True,
        expected_resource_version=0,
    )
    before_usage = registry.usage(signed.capability.cap_id)
    second_payload = {"content": "stale writer"}
    second_digest = digest_object(second_payload, purpose="payload")
    second_request = digest_object(
        {"operation": "stale", "resource": resource}, purpose="request"
    )
    second_permit = authority.verify_resource_commit_permit(
        authority.issue_resource_commit_permit(
            signed.token,
            request_digest=second_request,
            action="write_file",
            resource=resource,
            payload_digest=second_digest,
        )
    )
    receipt = _access_receipt(
        "session-cas", "write-stale", "nonce-stale-write", second_request, second_digest
    )
    with pytest.raises(AuthorityRegistryError, match="version precondition"):
        registry.commit_fenced_resource_write(
            second_permit,
            second_payload,
            access_receipt=receipt,
            protocol_payload_digest=True,
            expected_resource_version=0,
        )
    assert registry.usage(signed.capability.cap_id) == before_usage
    with sqlite3.connect(registry.database) as connection:
        exists = connection.execute(
            "SELECT 1 FROM paca_resource_access_receipts WHERE operation_id='write-stale'"
        ).fetchone()
        version = connection.execute(
            "SELECT version FROM paca_resource_values WHERE tenant=? AND task_id=? AND resource_key=?",
            ("acme", "task-broker", resource),
        ).fetchone()[0]
    assert exists is None
    assert version == 1
