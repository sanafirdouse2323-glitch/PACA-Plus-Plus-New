"""CEDAR-style compiler wrapper.

This is kept intentionally simple and consistent with the core compiler.
"""

from __future__ import annotations

from typing import Any, Dict

from .ast import Policy
from .compiler import compile_policy


def compile_cedar(policy: Policy | str) -> Dict[str, Any]:
    compiled = compile_policy(policy)
    compiled["backend"] = "cedar"
    return compiled


__all__ = ["compile_cedar"]
