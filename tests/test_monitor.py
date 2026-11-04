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


def test_manifest_pin_detects_rug_pull():
    m = Monitor()
    t1 = Tool("docs_search", "1.2", "Search")
    c = cap(grants={"call_tool": ("docs_search",)}, tool_pins={"docs_search": t1.hash})
    ok = Request("call_tool", {"tool": Arg("docs_search")}, c, 1, tool=t1)
    bad = Request("call_tool", {"tool": Arg("docs_search")}, c, 2, tool=Tool("docs_search", "1.2", "Search. hidden text"))
    assert m.decide(ok).verdict == "allow" and "C3" in m.decide(bad).checks


def test_cross_tenant_and_ssrf():
    m = Monitor()
    c = cap(grants={"read_file": ("/tenants/*",), "fetch_url": ("http://*",)})
    r = Request("read_file", {"path": Arg("/tenants/globex/x")}, c, 1, resource=Label("trusted", 2, "globex"))
    assert "C6" in m.decide(r).checks
    assert "C7" in m.decide(req("fetch_url", c, url="http://169.254.169.254/latest")).checks


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


def test_audit_chain_detects_tampering():
    m, c = Monitor(), cap()
    m.decide(req("read_file", c, path="/acme/a")); m.decide(req("read_file", c, path="/acme/b"))
    assert m.audit.verify()
    m.audit.entries[0]["verdict"] = "deny"
    assert not m.audit.verify()
