"""Policy evaluation (three-valued: permit / deny / not_applicable).

Fixes over v0.2: a `deny` rule whose conditions do NOT hold is no longer reported as
`permit`, `and` binds tighter than `or`, and type errors fail closed.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

_MISSING = object()

from .ast import EvaluationResult, Expression, Policy, ProvenanceRecord


def _lookup(context: Dict[str, Any], entity: str, attribute: str) -> Any:
    if not isinstance(context, dict):
        return _MISSING
    flat = f"{entity}.{attribute}"
    if flat in context:
        return context[flat]
    bucket = context.get(entity)
    if isinstance(bucket, dict):
        return bucket[attribute] if attribute in bucket else _MISSING
    if bucket is not None and hasattr(bucket, attribute):
        return getattr(bucket, attribute)
    return _MISSING


def _compare(actual: Any, op: str, expected: Any) -> bool:
    if actual is _MISSING:
        return False
    try:
        if op == "==":
            return actual == expected
        if op == "!=":
            return actual != expected
        if op in (">=", "<=", ">", "<"):
            if actual is None or expected is None:
                return False
            return {">=": actual >= expected, "<=": actual <= expected,
                    ">": actual > expected, "<": actual < expected}[op]
        if op == "in":
            return expected is not None and actual in expected
        if op == "contains":
            return actual is not None and expected in actual
        if op == "matches":
            return actual is not None and re.search(str(expected), str(actual)) is not None
    except (TypeError, re.error):
        return False          # fail closed on incomparable types and malformed regular expressions
    raise ValueError(f"Unsupported operator: {op!r}")


def _eval_expr(expr: Expression, ctx: Dict[str, Any]):
    actual = _lookup(ctx, expr.entity, expr.attribute)
    ok = _compare(actual, expr.operator, expr.value)
    shown_actual = "<missing>" if actual is _MISSING else actual
    rec = ProvenanceRecord("context", expr.entity, expr.attribute, shown_actual,
                           f"{expr.entity}.{expr.attribute} {expr.operator} {expr.value!r}")
    return ok, f"{expr.entity}.{expr.attribute} {expr.operator} {expr.value!r} => {'pass' if ok else 'fail'} (actual={shown_actual!r})", rec


def evaluate_policy(policy: Policy | str, context: Dict[str, Any],
                    provenance: Iterable[ProvenanceRecord] | None = None) -> EvaluationResult:
    if isinstance(policy, str):
        from .parser import parse_policy
        policy = parse_policy(policy)
    if not isinstance(context, dict):
        raise TypeError("Policy evaluation requires a dictionary-like context.")
    if policy.effect not in ("permit", "deny"):
        raise ValueError(f"Unsupported policy effect: {policy.effect!r}")

    prov: List[ProvenanceRecord] = list(provenance or [])
    details: List[str] = []
    results: List[bool] = []
    for e in policy.expressions:
        ok, d, rec = _eval_expr(e, context)
        results.append(ok); details.append(d); prov.append(rec)

    if not results:
        matched, details = True, ["no conditions; applies unconditionally"]
    else:                                   # OR of AND-groups
        groups = [[results[0]]]
        for conn, r in zip(policy.connectors, results[1:]):
            if conn == "or":
                groups.append([r])
            else:
                groups[-1].append(r)
        matched = any(all(g) for g in groups)

    obls = [o.name for o in (policy.obligations or ([policy.obligation] if policy.obligation else []))]
    return EvaluationResult(
        decision=policy.effect if matched else "not_applicable",
        passed=matched, matched_conditions=sum(results), total_conditions=len(results),
        details=details, provenance=prov, policy_id=policy.name,
        obligations=obls if matched else [],
        matched_policies=[policy.name] if matched else [],
        fired=[(policy.effect, policy.name)] if matched else [],
        obligation_map={policy.name: obls} if matched and obls else {},
    )


def evaluate_policy_set(policies, context, provenance=None) -> List[EvaluationResult]:
    from .ast import PolicySet
    items = list(policies.policies) if isinstance(policies, PolicySet) else (
        [policies] if isinstance(policies, (Policy, str)) else list(policies))
    return [evaluate_policy(p, context, provenance) for p in items]


__all__ = ["evaluate_policy", "evaluate_policy_set"]
