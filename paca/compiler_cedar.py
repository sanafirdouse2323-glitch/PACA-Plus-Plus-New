"""ASP-style compiler wrapper."""

from __future__ import annotations

from typing import Any, Dict

from .ast import Policy
from .compiler import compile_policy


def compile_asp(policy: Policy | str) -> Dict[str, Any]:
    compiled = compile_policy(policy)
    compiled["backend"] = "asp"
    return compiled


def compile_cedar(policy: Policy | str) -> Dict[str, Any]:
    compiled = compile_policy(policy)
    compiled["backend"] = "cedar"
    return compiled


__all__ = ["compile_asp", "compile_cedar"]
