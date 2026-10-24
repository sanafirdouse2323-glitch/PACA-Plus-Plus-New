from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from .ast import EvaluationResult, Expression, Policy, ProvenanceRecord


def _lookup(context: Dict[str, Any], entity: str, attribute: str) -> Any:
    if not isinstance(context, dict):
        return None

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
        return actual is not None and actual >= expected
    if operator == "<=":
        return actual is not None and actual <= expected
    if operator == ">":
        return actual is not None and actual > expected
    if operator == "<":
        return actual is not None and actual < expected
    if operator == "in":
        return expected is not None and actual in expected
    if operator == "contains":
        if actual is None:
            return False
        if isinstance(actual, str):
            return expected in actual
        try:
            return expected in actual
        except TypeError:
            return False
    if operator == "matches":
        if actual is None or expected is None:
            return False
        if not isinstance(expected, str):
            expected = str(expected)
        return re.search(expected, str(actual)) is not None
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


def _evaluate_condition_chain(
    expressions: List[Expression], connectors: List[str], context: Dict[str, Any]
) -> tuple[bool, List[str], List[ProvenanceRecord], int]:
    if not expressions:
        return True, ["Policy has no conditions; matched by default."], [], 0

    details: List[str] = []
    provenance: List[ProvenanceRecord] = []
    results: List[bool] = []
    for expr in expressions:
        ok, expr_details, expr_provenance = _evaluate_expr(expr, context)
        details.extend(expr_details)
        provenance.extend(expr_provenance)
        results.append(ok)

    passed = results[0]
    for connector, next_result in zip(connectors, results[1:]):
        if connector == "and":
            passed = passed and next_result
        elif connector == "or":
            passed = passed or next_result
        else:
            passed = next_result

    return passed, details, provenance, sum(1 for item in results if item)


def evaluate_policy(
    policy: Policy | str,
    context: Dict[str, Any],
    provenance: Iterable[ProvenanceRecord] | None = None,
) -> EvaluationResult:
    """Evaluate a policy against a runtime context."""
    if isinstance(policy, str):
        from .parser import parse_policy

        policy = parse_policy(policy)

    if not isinstance(context, dict):
        raise TypeError("Policy evaluation requires a dictionary-like context.")

    all_provenance: List[ProvenanceRecord] = list(provenance or [])
    details: List[str] = []
    passed = True
    matched_conditions = 0
    total_conditions = len(policy.expressions)

    if policy.expressions:
        passed, details, expr_provenance, matched_conditions = _evaluate_condition_chain(
            policy.expressions,
            list(getattr(policy, "connectors", [])),
            context,
        )
        all_provenance.extend(expr_provenance)
    else:
        details = ["Policy has no conditions; matched by default."]

    if policy.effect == "permit":
        decision = "permit" if passed else "deny"
    elif policy.effect == "deny":
        decision = "deny" if passed else "permit"
    else:
        raise ValueError(f"Unsupported policy effect: {policy.effect!r}")

    obligations = [
        obligation.name for obligation in (policy.obligations or ([policy.obligation] if policy.obligation else []))
    ]
    return EvaluationResult(
        decision=decision,
        passed=passed,
        matched_conditions=matched_conditions,
        total_conditions=total_conditions,
        details=details,
        provenance=all_provenance,
        policy_id=policy.name,
        obligations=obligations,
    )


__all__ = ["evaluate_policy"]
