"""Core compiler for PACA++ policies.

The compiler normalizes a policy into a simple dictionary-based representation
that can be consumed by backend-specific engines.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .ast import Policy
from .parser import parse_policy


def compile_policy(policy: Policy | str) -> Dict[str, Any]:
    """Compile a policy object or policy source string into a normalized dict."""

    if isinstance(policy, str):
        policy = parse_policy(policy)

    compiled = {
        "name": policy.name,
        "action": policy.action,
        "effect": policy.effect,
        "conditions": [
            {
                "entity": expr.entity,
                "attribute": expr.attribute,
                "operator": expr.operator,
                "value": expr.value,
            }
            for expr in policy.expressions
        ],
    }

    if policy.obligation is not None:
        compiled["obligation"] = {
            "name": policy.obligation.name,
            "parameter": policy.obligation.parameter,
        }

    return compiled


def compile_policy_source(source: str) -> Dict[str, Any]:
    """Convenience helper to compile a policy text directly."""

    return compile_policy(parse_policy(source))


__all__ = ["compile_policy", "compile_policy_source"]
