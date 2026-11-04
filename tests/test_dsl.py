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



def test_missing_attribute_does_not_satisfy_not_equal():
    assert evaluate_policy("permit read_file when user.role != banned", {"user": {}}).decision == "not_applicable"
    assert evaluate_policy("deny read_file when user.role != banned", {"user": {}}).decision == "not_applicable"


def test_logical_words_inside_quoted_values_are_not_connectors():
    p = parse_policy('permit read_file when user.department == "sales or engineering" and user.active == true')
    assert len(p.expressions) == 2
    assert p.connectors == ["and"]
    assert evaluate_policy(p, {"user": {"department": "sales or engineering", "active": True}}).decision == "permit"
    assert evaluate_policy(p, {"user": {"department": "sales", "active": True}}).decision == "not_applicable"


def test_compiler_preserves_connectors_and_all_obligations():
    from paca.compiler import compile_policy
    p = parse_policy("permit read_file when user.a == 1 or user.b == 2 with obligations audit_log, require_approval")
    compiled = compile_policy(p)
    assert compiled["connectors"] == ["or"]
    assert [item["name"] for item in compiled["obligations"]] == ["audit_log", "require_approval"]


def test_policy_set_strategy_and_default_are_honoured():
    from paca.ast import PolicySet
    from paca.engine import PolicyEngine
    ps = PolicySet(name="override", policies=[], strategy="permit_overrides", default_decision="permit")
    assert PolicyEngine(default_decision="deny").evaluate_set(ps, {}).decision == "permit"
    ps.strategy = "unknown"
    import pytest
    with pytest.raises(ValueError, match="Unsupported policy strategy"):
        PolicyEngine().evaluate_set(ps, {})
