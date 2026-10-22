from __future__ import annotations

import random
from typing import Any, Dict, List

from .ast import Expression, Policy


def generate_random_policy(seed: int | None = None) -> Policy:
    """Create a deterministic, valid policy for testing and fuzzing."""

    rng = random.Random(seed)
    effects = ["permit", "deny"]
    actions = ["readFile", "writeFile", "deleteFile", "sshAccess", "deploy", "viewReport"]
    entities = ["user", "resource", "context", "session"]
    attributes = ["role", "department", "clearance", "trust", "risk", "source", "region"]
    operators = ["==", "!=", ">=", "<=", ">", "<"]

    action = rng.choice(actions)
    effect = rng.choice(effects)
    count = rng.randint(1, 3)
    expressions: List[Expression] = []
    for _ in range(count):
        expressions.append(
            Expression(
                entity=rng.choice(entities),
                attribute=rng.choice(attributes),
                operator=rng.choice(operators),
                value=rng.choice(["admin", "user", "engineering", "prod", "low", "high", 3, 7, 9]),
            )
        )

    return Policy(
        name=f"{effect}_{action}",
        action=action,
        expressions=expressions,
        effect=effect,
    )


def generate_random_context(seed: int | None = None) -> Dict[str, Any]:
    """Create a realistic runtime context for evaluating generated policies."""

    rng = random.Random(seed)
    context: Dict[str, Any] = {
        "user": {
            "role": rng.choice(["admin", "user", "auditor", "analyst"]),
            "department": rng.choice(["engineering", "security", "finance", "ops"]),
            "clearance": rng.randint(1, 5),
            "trust": rng.randint(1, 10),
        },
        "resource": {
            "type": rng.choice(["file", "database", "endpoint", "report"]),
            "owner": rng.choice(["ops", "engineering", "security"]),
            "risk": rng.randint(1, 10),
        },
        "session": {
            "source": rng.choice(["internal", "external", "vpn"]),
            "region": rng.choice(["us-east", "eu-west", "apac"]),
        },
    }
    return context


__all__ = ["generate_random_context", "generate_random_policy"]
