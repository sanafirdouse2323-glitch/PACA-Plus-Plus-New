"""Core policy evaluator for PACA++.

The evaluator operates on a simple dictionary-like runtime context and evaluates
all conditions using a permissive set of comparison operators.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .ast import EvaluationResult, Expression, Policy, ProvenanceRecord


def _lookup(context: Dict[str, Any], entity: str, attribute: str) -> Any:
    if not isinstance(context, dict):
        return None

    # Flat keys such as "user.role" or "user.role.value" are supported.
    flat_key = f"{entity}.{attribute}"
    if flat_key in context:
        return context[flat_key]

    if entity in context:
        bucket = context[entity]
        if isinstance(bucket, dict) and attribute in bucket:
            return bucket[attribute]

        if hasattr(bucket, attribute):
            return getattr(bucket, attribute)

    if attribute in context:
        return context[attribute]

    return None


def _compare(actual: Any, operator: str, expected: Any) -> bool:
    if operator == "==":
        return actual == expected
    if operator == "!=":
        return actual != expected
    if operator == ">=":
        return (actual is not None) and (actual >= expected)
    if operator == "<=":
        return (actual is not None) and (actual <= expected)
    if operator == ">":
        return (actual is not None) and (actual > expected)
    if operator == "<":
        return (actual is not None) and (actual < expected)
    raise ValueError(f"Unsupported operator: {operator!r}")


def _evaluate_expr(expr: Expression, context: Dict[str, Any]) -> tuple[bool, List[str], List[ProvenanceRecord]]:
    actual = _lookup(context, expr.entity, expr.attribute)
    passed = _compare(actual, expr.operator, expr.value)

    provenance = [
        ProvenanceRecord(
            source="context",
            entity=expr.entity,
            attribute=expr.attribute,
            value=actual,
            explanation=f"Evaluated {expr.entity}.{expr.attribute} {expr.operator} {expr.value!r}",
        )
    ]

    detail = (
        f"{expr.entity}.{expr.attribute} {expr.operator} {expr.value!r} "
        f"=> {'pass' if passed else 'fail'} (actual={actual!r})"
    )
    return passed, [detail], provenance


def evaluate_policy(
    policy: Policy | str,
    context: Dict[str, Any],
    provenance: Iterable[ProvenanceRecord] | None = None,
) -> EvaluationResult:
    """Evaluate a policy against a runtime context.

    A policy is considered satisfied when every expression passes. The effect is
    then applied to yield the final decision.
    """

    if isinstance(policy, str):
        from .parser import parse_policy

        policy = parse_policy(policy)

    if not isinstance(context, dict):
        raise TypeError("Policy evaluation requires a dictionary-like context.")

    if provenance is None:
        provenance = []

    details: List[str] = []
    all_provenance: List[ProvenanceRecord] = list(provenance)
    passed_conditions = 0
    total_conditions = len(policy.expressions)

    for expr in policy.expressions:
        ok, expr_details, expr_provenance = _evaluate_expr(expr, context)
        details.extend(expr_details)
        all_provenance.extend(expr_provenance)
        if ok:
            passed_conditions += 1

    satisfied = total_conditions == 0 or passed_conditions == total_conditions
    if policy.effect == "permit":
        decision = "permit" if satisfied else "deny"
    elif policy.effect == "deny":
        decision = "deny" if satisfied else "permit"
    else:
        raise ValueError(f"Unsupported policy effect: {policy.effect!r}")

    return EvaluationResult(
        decision=decision,
        passed=satisfied,
        matched_conditions=passed_conditions,
        total_conditions=total_conditions,
        details=details,
        provenance=all_provenance,
    )


__all__ = ["evaluate_policy"]
