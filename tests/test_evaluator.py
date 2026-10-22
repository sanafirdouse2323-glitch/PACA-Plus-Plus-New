from paca.fuzzer import generate_random_context, generate_random_policy


def test_fuzzer_creates_valid_policy():
    policy = generate_random_policy(seed=7)
    context = generate_random_context(seed=11)

    assert policy.effect in {"permit", "deny"}
    assert policy.action
    assert isinstance(policy.expressions, list)
    assert len(policy.expressions) >= 1
    assert isinstance(context, dict)
    assert "user" in context
