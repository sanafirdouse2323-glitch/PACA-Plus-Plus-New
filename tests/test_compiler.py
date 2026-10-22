from paca.ast import Expression, Policy
from paca.parser import parse_policy


def test_parse_policy_basic_expression():
    policy = parse_policy(
        "permit readFile when user.role == admin and user.department == engineering"
    )

    assert policy.effect == "permit"
    assert policy.action == "readFile"
    assert len(policy.expressions) == 2
    assert policy.expressions[0].entity == "user"
    assert policy.expressions[0].attribute == "role"
    assert policy.expressions[0].value == "admin"
    assert policy.expressions[1].attribute == "department"


def test_construct_policy_directly():
    expr = Expression(entity="user", attribute="role", operator="==", value="admin")
    policy = Policy(name="AdminPolicy", action="readFile", expressions=[expr], effect="permit")

    assert policy.name == "AdminPolicy"
    assert policy.action == "readFile"
    assert policy.effect == "permit"
    assert policy.expressions[0].attribute == "role"
