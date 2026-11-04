import hmac

import pytest

from paca.baselines import SandboxScoped
from paca.monitor import Monitor, is_internal_host
from paca.provenance import Arg, Label, derive
from paca.runtime import Capability, Request


def make_cap(**kwargs):
    values = {
        "cap_id": "c1", "principal": "tester", "tenant": "acme", "task_id": "task-1",
        "role": "assistant",
        "grants": {
            "send_email": ("bob@corp.example",), "merge_pr": ("#1",),
            "read_file": ("/acme/*",), "delegate": ("worker-1",),
        },
        "expires": 30,
    }
    values.update(kwargs)
    return Capability(**values)


def test_join_preserves_all_tenants_and_monitor_detects_mixed_tenant_data():
    mixed = derive(
        "combined",
        Arg("internal", Label("trusted", 1, "acme")),
        Arg("external", Label("trusted", 1, "globex")),
    )
    assert mixed.label.tenant is None
    assert mixed.label.tenants == frozenset({"acme", "globex"})
    decision = Monitor().decide(Request(
        "send_email", {"to": Arg("bob@corp.example"), "body": mixed}, make_cap(), 1
    ))
    assert decision.verdict == "deny"
    assert "C6" in decision.checks


def test_request_digest_is_order_independent_but_binds_provenance():
    cap = make_cap()
    first = Request("send_email", {
        "to": Arg("bob@corp.example"), "body": Arg("report", Label("trusted", 2, "acme"))
    }, cap, 1)
    reordered = Request("send_email", {
        "body": Arg("report", Label("trusted", 2, "acme")), "to": Arg("bob@corp.example")
    }, cap, 1)
    tainted = Request("send_email", {
        "to": Arg("bob@corp.example"), "body": Arg("report", Label("untrusted", 2, "acme"))
    }, cap, 1)
    assert first.digest == reordered.digest
    assert first.digest != tainted.digest


def test_effect_token_is_single_use_and_binds_exact_request():
    monitor = Monitor()
    request = Request("send_email", {
        "to": Arg("bob@corp.example"), "body": Arg("hello")
    }, make_cap(), 1)
    decision = monitor.decide(request)
    assert decision.verdict == "allow"
    assert monitor.verify(request, decision)
    assert not monitor.verify(request, decision)


def test_effect_token_rejects_changed_provenance_after_authorisation():
    monitor = Monitor()
    request = Request("send_email", {
        "to": Arg("bob@corp.example"),
        "body": Arg("hello", Label("trusted", 0, "acme")),
    }, make_cap(), 1)
    decision = monitor.decide(request)
    request.args["body"] = Arg("hello", Label("untrusted", 0, "acme"))
    assert not monitor.verify(request, decision)


def test_effect_token_rejects_authority_change_after_authorisation():
    monitor = Monitor()
    cap = make_cap()
    request = Request("send_email", {
        "to": Arg("bob@corp.example"), "body": Arg("hello")
    }, cap, 1)
    decision = monitor.decide(request)
    cap.grants["send_email"] = ("mallory@evil.example",)
    assert not monitor.verify(request, decision)


def test_delegation_rejects_broader_child_pattern_and_allows_narrower_prefix():
    monitor = Monitor()
    cap = make_cap(grants={
        "delegate": ("worker-1",), "read_file": ("/acme/docs/*",)
    })
    broadened = Request("delegate", {
        "agent": Arg("worker-1"), "child_grants": Arg({"read_file": ["/acme/*"]})
    }, cap, 1)
    narrowed = Request("delegate", {
        "agent": Arg("worker-1"), "child_grants": Arg({"read_file": ["/acme/docs/reports/*"]})
    }, cap, 1)
    assert "C11" in monitor.decide(broadened).checks
    assert monitor.decide(narrowed).verdict == "allow"


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "::1", "fc00::1", "service.local"])
def test_internal_host_detection_includes_ipv4_ipv6_and_local_names(host):
    assert is_internal_host(host)


def test_sandbox_domain_allowlist_does_not_accept_suffix_spoofing():
    cap = make_cap()
    spoofed = Request("send_email", {
        "to": Arg("attacker@notcorp.example"), "body": Arg("hello")
    }, cap, 1)
    allowed = Request("send_email", {
        "to": Arg("bob@corp.example"), "body": Arg("hello")
    }, cap, 1)
    sandbox = SandboxScoped()
    assert sandbox.decide(spoofed).verdict == "needs_approval"
    assert sandbox.decide(allowed).verdict == "allow"


def test_digest_knowledge_is_not_accepted_as_human_approval_by_default():
    monitor = Monitor()
    request = Request("merge_pr", {"pr": Arg("#1")}, make_cap(), 1)
    request.approval = request.digest
    assert monitor.decide(request).verdict == "needs_approval"


def test_approval_requires_explicit_verifier_and_is_bound_to_request():
    monitor = Monitor(approval_verifier=lambda req, token: hmac.compare_digest(token, req.digest))
    request = Request("merge_pr", {"pr": Arg("#1")}, make_cap(), 1)
    request.approval = request.digest
    assert monitor.decide(request).verdict == "allow"
