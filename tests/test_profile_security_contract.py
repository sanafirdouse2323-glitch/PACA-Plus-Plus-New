from __future__ import annotations

import hashlib

import pytest

from paca.authority_runtime import (
    CapabilityAuthenticationError,
    HMACCapabilityAuthority,
    SQLiteAuthorityRegistry,
)
from paca.memory import canonical_value_bytes
from paca.provenance import Arg, Label, ProvenanceGraph, derive
from paca.resource_commit import FencedResourceExecutor, ResourceCommitDenied
from paca.runtime import Request, Tool


def _write_case(tmp_path, *, task_id: str = "profile-contract-task"):
    now = [1_000]

    def clock() -> int:
        return now[0]

    registry = SQLiteAuthorityRegistry(tmp_path / "authority.sqlite3", clock=clock)
    authority = HMACCapabilityAuthority(
        registry,
        issuer_id="profile-contract-issuer",
        key_id="profile-contract-key",
        key=b"profile-contract-secret-key-material-32-bytes",
        audience="profile-contract-runtime",
        identity_verifier=lambda principal, tenant: (
            principal == "agent-a" and tenant == "acme"
        ),
        task_context_verifier=lambda principal, tenant, requested_task, purpose: (
            principal == "agent-a"
            and tenant == "acme"
            and requested_task == task_id
            and purpose == "profile-contract-test"
        ),
        clock=clock,
    )
    tool = Tool(
        "write_file",
        "1.0",
        "Write one authorised local resource",
        ("path", "content"),
    )
    signed = authority.issue(
        principal="agent-a",
        tenant="acme",
        task_id=task_id,
        purpose="profile-contract-test",
        grants={"write_file": ("/acme/*",)},
        expires_at=2_000,
        max_calls=5,
        max_task_calls=10,
        tool_pins={"write_file": tool.hash},
    )
    capability = authority.verify(signed.token).capability
    request = Request(
        "write_file",
        {
            "path": Arg("/acme/report.txt", Label("trusted", tenant="acme")),
            "content": Arg(
                {"report": "approved"},
                Label("untrusted", sensitivity=1, tenant="acme"),
            ),
        },
        capability,
        1,
        tool=tool,
    )
    payload_digest = hashlib.sha256(
        canonical_value_bytes({"content": {"report": "approved"}})
    ).hexdigest()
    permit = authority.issue_resource_commit_permit(
        signed.token,
        request_digest=request.digest,
        action="write_file",
        resource="/acme/report.txt",
        payload_digest=payload_digest,
    )
    return registry, authority, signed, request, permit


def test_capability_authorization_is_revoked_for_every_profile(tmp_path):
    registry, authority, signed, _request, _permit = _write_case(tmp_path)
    verified = authority.verify(signed.token)
    assert verified.capability.cap_id == signed.capability.cap_id
    assert registry.is_active(signed.capability.cap_id)

    registry.revoke(signed.capability.cap_id, "profile contract revocation test")

    assert not registry.is_active(signed.capability.cap_id)
    with pytest.raises(CapabilityAuthenticationError):
        authority.verify(signed.token)


def test_provenance_contract_preserves_taint_sensitivity_and_lineage():
    graph = ProvenanceGraph()
    source = graph.add_source(
        "untrusted external instruction",
        object_id="external-message",
        version_id="v1",
        source="mail:message-1",
        source_class="external_content",
        content_digest=hashlib.sha256(
            b"untrusted external instruction"
        ).hexdigest(),
        label=Label(
            "untrusted",
            sensitivity=2,
            tenant="acme",
            origins=frozenset({"mail:message-1"}),
        ),
        purpose="profile-contract-test",
    )
    derived = graph.derive(
        "model-generated summary",
        source,
        object_id="summary",
        version_id="v1",
        content_digest=hashlib.sha256(b"model-generated summary").hexdigest(),
        transformation="summarise",
        purpose="profile-contract-test",
    )

    assert derived.label.integrity == "untrusted"
    assert derived.label.sensitivity == 2
    assert derived.label.tenants == frozenset({"acme"})
    assert len(derived.lineage_refs) == 1
    node = graph.get_node(next(iter(derived.lineage_refs)))
    assert node is not None
    assert node.parent_ids == tuple(source.lineage_refs)
    assert node.source_class == "model_generated"

    incomplete = derive(
        "summary with opaque framework context",
        source,
        Arg("untracked context", Label("trusted", tenant="acme")),
    )
    assert incomplete.label.integrity == "untrusted"
    assert incomplete.lineage_refs == source.lineage_refs
    assert incomplete.lineage_incomplete is True


def test_resource_commit_is_request_bound_and_single_use(tmp_path):
    _registry, authority, _signed, request, permit = _write_case(tmp_path)
    executor = FencedResourceExecutor(authority)

    result = executor.execute_authorized(request, permit)
    assert result

    with pytest.raises(ResourceCommitDenied):
        executor.execute_authorized(request, permit)


def test_resource_commit_rejects_capability_revoked_after_permit_issuance(tmp_path):
    registry, authority, signed, request, permit = _write_case(tmp_path)
    registry.revoke(signed.capability.cap_id, "revoke before resource commit")

    with pytest.raises(ResourceCommitDenied):
        FencedResourceExecutor(authority).execute_authorized(request, permit)
