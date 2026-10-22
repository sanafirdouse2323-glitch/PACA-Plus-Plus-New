from __future__ import annotations

import random
from typing import Any, Dict

from .ast import Expression, Policy


def generate_random_policy(seed: int | None = None) -> Policy:
    rnd = random.Random(seed)
    expressions = [
        Expression(
            entity="user",
            attribute=rnd.choice(["role", "department", "clearance"]),
            operator=rnd.choice(["==", "!=", ">=", "<="]),
            value=rnd.choice(["admin", "engineering", 1, 0]),
        )
    ]
    effect = rnd.choice(["permit", "deny"])
    return Policy(
        name=f"{effect}_policy",
        action="readFile",
        expressions=expressions,
        effect=effect,
    )


def generate_random_context(seed: int | None = None) -> Dict[str, Any]:
    rnd = random.Random(seed)
    return {
        "user": {
            "role": rnd.choice(["admin", "user", "auditor"]),
            "department": rnd.choice(["engineering", "finance"]),
            "clearance": rnd.randint(0, 3),
        }
    }


__all__ = ["generate_random_policy", "generate_random_context"]
