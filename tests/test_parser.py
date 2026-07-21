from paca.ast import Expression, Policy


def test_create_policy():
    expr = Expression(
        entity="user",
        attribute="role",
        operator="==",
        value="admin",
    )

    policy = Policy(
        name="AdminPolicy",
        action="readFile",
        expressions=[expr],
        effect="permit",
    )

    assert policy.name == "AdminPolicy"
    assert policy.action == "readFile"
    assert policy.effect == "permit"
    assert policy.expressions[0].attribute == "role"