from paca.evaluator import evaluate_policy


def test_evaluate_policy_permit_when_conditions_match():
    policy_text = "permit readFile when user.role == admin and user.department == engineering"
    context = {"user": {"role": "admin", "department": "engineering"}}

    result = evaluate_policy(policy_text, context)

    assert result.decision == "permit"
    assert result.passed is True
    assert result.matched_conditions == 2


def test_evaluate_policy_deny_when_conditions_fail():
    policy_text = "permit readFile when user.role == admin and user.department == engineering"
    context = {"user": {"role": "user", "department": "finance"}}

    result = evaluate_policy(policy_text, context)

    assert result.decision == "deny"
    assert result.passed is False


def test_evaluate_policy_with_flattened_context_keys():
    policy_text = "deny writeFile when user.role != admin"
    context = {"user.role": "guest"}

    result = evaluate_policy(policy_text, context)

    assert result.decision == "deny"
    assert result.passed is True
