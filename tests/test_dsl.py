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
    ps = parse_policy_set(
        "R1: deny any when a.x > 2 with obligation audit_log  # note\n"
        "R2: permit any with obligation require_approval"
    )
    e = PolicyEngine(default_decision="permit")
    assert e.evaluate_set(ps, {"a": {"x": 1}}).decision == "permit"
    r = e.evaluate_set(ps, {"a": {"x": 5}})
    assert r.decision == "deny"
    assert ("deny", "R1") in r.fired
    assert ("permit", "R2") not in r.fired
    assert r.matched_policies == ["R1", "R2"]
    assert r.obligation_map == {"R1": ["audit_log"]}
    assert r.obligations == ["audit_log"]


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



def test_policy_conflict_strategies_only_fire_effective_rules_and_obligations():
    from paca.parser import parse_policy_set

    source = (
        "D: deny any with obligation audit_log\n"
        "P: permit any with obligation require_approval"
    )
    permit_wins = parse_policy_set(source, strategy="permit_overrides", default_decision="deny")
    result = PolicyEngine().evaluate_set(permit_wins, {})
    assert result.decision == "permit"
    assert result.fired == [("permit", "P")]
    assert result.obligation_map == {"P": ["require_approval"]}
    assert result.obligations == ["require_approval"]
    assert result.matched_policies == ["D", "P"]

    deny_wins = parse_policy_set(source, strategy="deny_overrides", default_decision="permit")
    result = PolicyEngine().evaluate_set(deny_wins, {})
    assert result.decision == "deny"
    assert result.fired == [("deny", "D")]
    assert result.obligation_map == {"D": ["audit_log"]}

    first = parse_policy_set(source, strategy="first_applicable", default_decision="permit")
    result = PolicyEngine().evaluate_set(first, {})
    assert result.decision == "deny"
    assert result.fired == [("deny", "D")]
    assert result.obligation_map == {"D": ["audit_log"]}


def test_hash_inside_quoted_policy_value_is_not_a_comment():
    ps = parse_policy_set(
        'R1: permit post_message when resource.channel == "#finance" # finance channel rule'
    )
    policy = ps.policies[0]
    assert policy.expressions[0].value == "#finance"
    assert policy.description == "finance channel rule"
