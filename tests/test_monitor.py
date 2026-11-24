import pytest

from paca.monitor import AuditLog, Monitor
from paca.provenance import Arg, Label, derive
from paca.runtime import Capability, Request, Tool

U = Label("untrusted", 0, None, frozenset({"mail"}))
CONF = Label("trusted", 3, "acme", frozenset({"fs"}))


def cap(**kw):
    g = kw.pop("grants", {"send_email": ("*@corp.example",), "read_file": ("/acme/*",)})
    return Capability("c1", "sana", "acme", "t1", "assistant", g, kw.pop("expires", 30), **kw)


def req(action, c, step=1, **args):
    return Request(action, {k: (v if isinstance(v, Arg) else Arg(v, Label("trusted", origins=frozenset({"user"})))) for k, v in args.items()}, c, step)


def test_label_join_never_improves():
    d = derive("summary", Arg("x", CONF), Arg("y", U))
    assert d.label.integrity == "untrusted" and d.label.sensitivity == 3 and d.label.origins == {"fs", "mail"}


def test_exfil_denied_by_independent_checks():
    m, c = Monitor(), cap()
    d = m.decide(req("send_email", c, to=Arg("a@evil.test", U), body=derive("x", Arg("d", CONF))))
    assert d.verdict == "deny" and {"C1", "C4f", "C5"} <= set(d.checks)


def test_legit_send_allowed_and_token_binds_args():
    m, c = Monitor(), cap()
    r = req("send_email", c, to="bob@corp.example", body=Arg("hi", CONF))
    d = m.decide(r)
    assert d.verdict == "allow" and m.verify(r, d)
    assert not m.verify(req("send_email", c, to="bob@corp.example", body=Arg("DIFFERENT")), d)


def test_expiry_budget_and_unknown_action():
    m = Monitor()
    assert "C2" in m.decide(req("send_email", cap(expires=3), step=9, to="b@corp.example", body="x")).checks
    c = cap(max_calls=1)
    assert m.decide(req("read_file", c, path="/acme/a")).verdict == "allow"
    assert "C2" in m.decide(req("read_file", c, path="/acme/b")).checks
    assert m.decide(req("launch_missiles", c)).verdict == "deny"


def test_manifest_pin_detects_rug_pull_on_action_mapped_tool():
    m = Monitor()
    t1 = Tool("docs_search", "1.2", "Search")
    c = cap(grants={"read_file": ("/acme/report.txt",)}, tool_pins={"docs_search": t1.hash})
    ok = Request("read_file", {"path": Arg("/acme/report.txt")}, c, 1, tool=t1)
    bad = Request("read_file", {"path": Arg("/acme/report.txt")}, c, 2,
                  tool=Tool("docs_search", "1.2", "Search. hidden text"))
    assert m.decide(ok).verdict == "allow"
    assert "C3" in m.decide(bad).checks


def test_generic_tool_dispatch_fails_closed_even_when_manifest_is_pinned():
    tool = Tool("docs_search", "1.2", "Search")
    c = cap(grants={"call_tool": ("docs_search",)}, tool_pins={"docs_search": tool.hash})
    request = Request("call_tool", {"tool": Arg("docs_search")}, c, 1, tool=tool)
    decision = Monitor().decide(request)
    assert decision.verdict == "deny"
    assert "C16" in decision.checks


def test_generic_tool_dispatch_cannot_be_reenabled_by_ablation():
    tool = Tool("docs_search", "1.2", "Search")
    c = cap(grants={"call_tool": ("docs_search",)}, tool_pins={"docs_search": tool.hash})
    decision = Monitor(disable={"C16"}).decide(
        Request("call_tool", {"tool": Arg("docs_search")}, c, 1, tool=tool)
    )
    assert decision.verdict == "deny"
    assert "C16" in decision.checks


def test_cross_tenant_and_ssrf():
    m = Monitor()
    c = cap(grants={"read_file": ("/tenants/*",), "fetch_url": ("http://*",)})
    r = Request("read_file", {"path": Arg("/tenants/globex/x")}, c, 1, resource=Label("trusted", 2, "globex"))
    assert "C6" in m.decide(r).checks
    assert "C7" in m.decide(req("fetch_url", c, url="http://169.254.169.254/latest")).checks


def test_fetch_url_without_separate_query_is_still_outbound_egress():
    monitor = Monitor()
    capability = cap(grants={"fetch_url": ("https://*",)})
    ordinary = Request(
        "fetch_url",
        {"url": Arg("https://news.example/page", U)},
        capability,
        1,
    )
    ordinary_decision = monitor.decide(ordinary)
    assert ordinary_decision.verdict == "needs_approval"
    assert "C4g" in ordinary_decision.checks

    # Sensitive data embedded directly in the URL must be included in flow labels,
    # even if the integration does not supply a separate query argument.
    embedded_disclosure = Request(
        "fetch_url",
        {"url": Arg(
            "https://news.example/search?token=secret",
            Label("untrusted", sensitivity=3, tenant="acme", origins=frozenset({"derived_url"})),
        )},
        capability,
        2,
    )
    denied_embedded = monitor.decide(embedded_disclosure)
    assert denied_embedded.verdict == "deny"
    assert {"C4f", "C5"} <= set(denied_embedded.checks)

    # An explicit query payload is joined with the URL label as well.
    disclosure = Request(
        "fetch_url",
        {
            "url": Arg("https://news.example/search", U),
            "query": Arg("private query", CONF),
        },
        capability,
        3,
    )
    denied = monitor.decide(disclosure)
    assert denied.verdict == "deny"
    assert "C4f" in denied.checks

    # SSRF checks remain active for all URL fetches.
    internal_capability = cap(grants={"fetch_url": ("http://*",)})
    internal = Request(
        "fetch_url",
        {"url": Arg("http://169.254.169.254/latest", U)},
        internal_capability,
        1,
    )
    assert "C7" in Monitor().decide(internal).checks

def test_delegation_must_attenuate():
    m = Monitor()
    c = cap(grants={"delegate": ("w1",), "read_file": ("/acme/*",)})
    assert m.decide(req("delegate", c, agent="w1", child_grants={"read_file": ["/acme/docs/*"]})).verdict == "allow"
    assert "C11" in m.decide(req("delegate", c, agent="w1", child_grants={"delete_file": ["*"]})).checks


def test_approval_is_bound_to_exact_effect():
    m = Monitor(approval_verifier=lambda req, token: token == req.digest)
    c = cap(grants={"merge_pr": ("#1", "#2")})
    r1 = req("merge_pr", c, pr="#1")
    assert m.decide(r1).verdict == "needs_approval"
    r1.approval = r1.digest
    assert m.decide(r1).verdict == "allow"
    r2 = req("merge_pr", c, pr="#2"); r2.approval = r1.digest        # replayed approval for another effect
    assert m.decide(r2).verdict == "needs_approval"


def test_quarantine_after_repeated_denials():
    m, c = Monitor(), cap(grants={"send_email": ("bob@corp.example",)})
    for _ in range(3):
        m.decide(req("send_email", c, to="x@evil.test", body="b"))
    assert "C12" in m.decide(req("send_email", c, to="bob@corp.example", body="b")).checks


def test_pending_approvals_do_not_accumulate_quarantine_strikes():
    m = Monitor(approval_verifier=lambda request, token: token == request.digest)
    c = cap(grants={"send_email": ("*@partner.example",)})
    for step in range(1, 5):
        request = req(
            "send_email", c, step,
            to=Arg("person@partner.example", U),
            body=Arg("public update", Label("trusted", 0, "acme")),
        )
        pending = m.decide(request)
        assert pending.verdict == "needs_approval"
        assert m.strikes.get(c.task_id, 0) == 0
        request.approval = pending.digest
        approved = m.decide(request)
        assert approved.verdict == "allow"
        assert m.verify(request, approved)
    assert m.strikes.get(c.task_id, 0) == 0


def test_audit_chain_detects_tampering():
    m, c = Monitor(), cap()
    m.decide(req("read_file", c, path="/acme/a")); m.decide(req("read_file", c, path="/acme/b"))
    assert m.audit.verify()
    m.audit.entries[0]["verdict"] = "deny"
    assert not m.audit.verify()

@pytest.mark.parametrize(
    ("tenant", "task_id"),
    [
        (None, "task-1"),
        ("acme", None),
        ("acme", 42),
    ],
)
def test_monitor_fails_closed_and_audits_invalid_tenant_or_task_identity(tenant, task_id):
    capability = cap()
    capability.tenant = tenant
    capability.task_id = task_id
    monitor = Monitor()

    decision = monitor.decide(req("read_file", capability, path="/acme/report.txt"))

    assert decision.verdict == "deny"
    assert "C13" in decision.checks
    assert monitor.audit.verify()
    assert monitor.audit.entries[-1]["verdict"] == "deny"
    assert "invalid tenant/task identity" in monitor.audit.entries[-1]["reason"]



def test_consequential_runtime_profile_rejects_ablations_and_policy_drift():
    monitor = Monitor()
    monitor.assert_consequential_safe()

    ablated = Monitor(disable={"C5"})
    with pytest.raises(ValueError, match="disabled checks: C5"):
        ablated.assert_consequential_safe()

    from importlib import resources

    tampered_policy = Monitor(
        policy_text=resources.files("paca").joinpath(
            "policies", "agent_policy.paca",
        ).read_text(encoding="utf-8").replace(
            "flow.cross_tenant == true", "flow.cross_tenant == false",
        )
    )
    with pytest.raises(ValueError, match="policy rule C6"):
        tampered_policy.assert_consequential_safe()


def test_consequential_runtime_profile_rejects_unknown_or_duplicate_required_rules():
    from importlib import resources

    default_policy = resources.files("paca").joinpath(
        "policies", "agent_policy.paca",
    ).read_text(encoding="utf-8")
    duplicate = default_policy + "\\nC6: deny any when flow.cross_tenant == true\\n"
    monitor = Monitor(policy_text=duplicate)
    with pytest.raises(ValueError, match="missing or duplicates required policy rule C6"):
        monitor.assert_consequential_safe()
