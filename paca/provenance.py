"""CEDAR-style evaluator wrapper."""

from __future__ import annotations

from typing import Any, Dict

from .ast import Policy
from .evaluator import evaluate_policy


def evaluate_cedar(policy: Policy | str, context: Dict[str, Any]) -> Any:
    return evaluate_policy(policy, context)


__all__ = ["evaluate_cedar"]
