from paca import Policy, PolicySet, PolicyEngine, evaluate_policy


def test_policy_parse_and_evaluate_smoke():
    policy = "permit readFile when user.role == admin and user.department == engineering"
    result = evaluate_policy(policy, {"user": {"role": "admin", "department": "engineering"}})
    assert result.decision == "permit"
    assert result.passed is True


def test_policy_set_deny_overrides_smoke():
    policies = [
        Policy(name="deny_guest", action="deleteFile", expressions=[], effect="deny"),
        Policy(name="allow_admin", action="deleteFile", expressions=[], effect="permit"),
    ]
    policy_set = PolicySet(name="ops", policies=policies, strategy="deny_overrides", default_decision="deny")
    engine = PolicyEngine(strategy="deny_overrides", default_decision="deny")
    result = engine.evaluate_set(policy_set, {"user": {"role": "guest"}})
    assert result.decision == "deny"


def test_or_logic_smoke():
    result = evaluate_policy(
        "permit readFile when user.role == admin or user.role == auditor",
        {"user": {"role": "auditor"}},
    )
    assert result.decision == "permit"
    assert result.passed is True
