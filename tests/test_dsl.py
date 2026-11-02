from paca import PolicyEngine, evaluate_policy, parse_policy, parse_policy_set

CTX = {"user": {"role": "admin", "department": "engineering"}}


def test_readme_example_parses_and_permits():
    p = parse_policy("permit readFile when user.role == admin and user.department == engineering with obligation audit_log(user.id)")
    r = evaluate_policy(p, CTX)
    assert r.decision == "permit" and r.obligations == ["audit_log"]


def test_unmatched_deny_is_not_applicable_not_permit():
    assert evaluate_policy("deny deleteFile when user.role != admin", CTX).decision == "not_applicable"
    assert evaluate_policy("deny deleteFile when user.role == admin", CTX).decision == "deny"


def test_and_binds_tighter_than_or():
    p = parse_policy("permit a when x.a == 1 or x.b == 1 and x.c == 1")
    assert evaluate_policy(p, {"x": {"a": 1, "b": 0, "c": 0}}).passed
    assert not evaluate_policy(p, {"x": {"a": 0, "b": 1, "c": 0}}).passed


def test_missing_attribute_and_type_errors_fail_closed():
    assert not evaluate_policy("permit a when x.n > 3", {"x": {}}).passed
    assert not evaluate_policy("permit a when x.n > 3", {"x": {"n": "text"}}).passed


def test_policy_set_deny_overrides_and_obligation_map():
    ps = parse_policy_set("R1: deny any when a.x > 2  # note\nR2: permit any with obligation audit_log")
    e = PolicyEngine(default_decision="permit")
    assert e.evaluate_set(ps, {"a": {"x": 1}}).decision == "permit"
    r = e.evaluate_set(ps, {"a": {"x": 5}})
    assert r.decision == "deny" and ("deny", "R1") in r.fired and r.obligation_map["R2"] == ["audit_log"]


def test_bad_line_reports_line_number():
    import pytest
    with pytest.raises(ValueError, match="line 2"):
        parse_policy_set("permit a\nthis is nonsense")
