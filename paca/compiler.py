from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Union

from .ast import Expression, Obligation, Policy

_POLICY_RE = re.compile(
    r"""(?is)^
    (?P<effect>permit|deny)
    \s+
    (?P<action>[A-Za-z_][A-Za-z0-9_.-]*)
    (?:\s+when\s+(?P<conditions>.+?))?
    (?:\s+with\s+(?:obligation|obligations)\s+(?P<obligation>.+?))?
    \s*$
    """
)

_CONDITION_RE = re.compile(
    r"""
    ^\s*(?P<entity>[A-Za-z_][A-Za-z0-9_.-]*)
    \s*\.\s*(?P<attribute>[A-Za-z_][A-Za-z0-9_.-]*)
    \s*(?P<operator>==|!=|>=|<=|>|<|in|contains|matches)
    \s*(?P<value>.+?)
    \s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _clean_value(raw: str):
    value = raw.strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    if re.fullmatch(r"[-+]?\d+", value):
        return int(value)
    if re.fullmatch(r"[-+]?\d+\.\d+", value):
        return float(value)
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.lower() == "null":
        return None
    return value


def _parse_condition(fragment: str) -> Expression:
    match = _CONDITION_RE.match(fragment.strip())
    if not match:
        raise ValueError(f"Unsupported condition fragment: {fragment!r}")

    data = match.groupdict()
    return Expression(
        entity=data["entity"],
        attribute=data["attribute"],
        operator=data["operator"],
        value=_clean_value(data["value"]),
    )


def _parse_conditions(raw: str) -> List[Expression]:
    if not raw or not raw.strip():
        return []
    parts = re.split(r"\s+(?:and|or)\s+", raw, flags=re.IGNORECASE)
    return [_parse_condition(part) for part in parts if part.strip()]


def _parse_obligation(raw: Optional[str]) -> Optional[Obligation]:
    if raw is None or not raw.strip():
        return None

    text = raw.strip()
    name_match = re.match(r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)", text)
    if not name_match:
        raise ValueError(f"Invalid obligation: {raw!r}")

    name = name_match.group("name")
    remainder = text[name_match.end():].strip()
    if remainder.startswith("(") and remainder.endswith(")"):
        parameter = remainder[1:-1].strip()
    else:
        parameter = ""
    return Obligation(name=name, parameter=parameter)


def parse_policy(source: str) -> Policy:
    """Parse a PACA++ policy string into a Policy AST object."""
    text = (source or "").strip()
    if not text:
        raise ValueError("Policy source is empty.")

    match = _POLICY_RE.match(text)
    if not match:
        raise ValueError(f"Could not parse policy: {source!r}")

    effect = match.group("effect").lower()
    action = match.group("action")
    conditions = match.group("conditions") or ""
    obligation_text = match.group("obligation")

    expressions = _parse_conditions(conditions)
    obligation = _parse_obligation(obligation_text)

    return Policy(
        name=f"{effect}_{action}",
        action=action,
        expressions=expressions,
        obligation=obligation,
        effect=effect,
    )


def parse_policy_file(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as handle:
        return parse_policy(handle.read())


def compile_policy(policy: Union[Policy, str]) -> Dict[str, Any]:
    """Normalize a Policy object or source string to a dict.

    We preserve both the legacy `expressions` key and the canonical
    `conditions` key so older callers and tests both work.
    """
    if isinstance(policy, str):
        policy = parse_policy(policy)

    conditions = [
        {
            "entity": expr.entity,
            "attribute": expr.attribute,
            "operator": expr.operator,
            "value": expr.value,
        }
        for expr in policy.expressions
    ]

    compiled = {
        "name": policy.name,
        "action": policy.action,
        "effect": policy.effect,
        "conditions": conditions,
        "expressions": conditions,
    }

    if policy.obligation is not None:
        compiled["obligation"] = {
            "name": policy.obligation.name,
            "parameter": policy.obligation.parameter,
        }
    else:
        compiled["obligation"] = None

    return compiled


def compile_policy_source(source: str) -> Dict[str, Any]:
    return compile_policy(parse_policy(source))


__all__ = [
    "compile_policy",
    "compile_policy_source",
    "parse_policy",
    "parse_policy_file",
]
