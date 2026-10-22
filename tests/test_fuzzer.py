from paca.compiler import compile_policy, compile_policy_source


def test_compile_policy_from_object():
    policy = "permit readFile when user.role == admin and user.department == engineering"
    compiled = compile_policy(policy)

    assert compiled["effect"] == "permit"
    assert compiled["action"] == "readFile"
    assert compiled["conditions"][0]["attribute"] == "role"
    assert compiled["conditions"][1]["attribute"] == "department"


def test_compile_policy_from_source():
    compiled = compile_policy_source("deny deleteFile when user.role != admin")

    assert compiled["effect"] == "deny"
    assert compiled["action"] == "deleteFile"
    assert compiled["conditions"][0]["operator"] == "!="
