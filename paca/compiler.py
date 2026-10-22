"""Reference parser for the PACA++ policy DSL."""

from __future__ import annotations

import re
from typing import List, Optional

from .ast import Expression, Obligation, Policy

_POLICY_RE = re.compile(
    r"""(?is)^
    (?P<effect>permit|deny)
    \s+
    (?P<action>[A-Za-z_][A-Za-z0-9_.-]*)
    (?:\s+when\s+(?P<conditions>.+?))?
    (?:\s+with\s+obligation\s+(?P<obligation>.+?))?
    \s*$
    """
)

_CONDITION_RE = re.compile(
    r"""
    ^\s*(?P<entity>[A-Za-z_][A-Za-z0-9_\.]*)
    \s*\.\s*(?P<attribute>[A-Za-z_][A-Za-z0-9_]*)
    \s*(?P<operator>==|!=|>=|<=|>|<)
    \s*(?P<value>[^\s]+)
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
    return value


def _parse_condition(fragment: str) -> Expression:
    match = _CONDITION_RE.match(fragment.strip())
    if not match:
        raise ValueError(f"Unsupported condition fragment: {fragment!r}")

    data = match.groupdict()
    entity = data["entity"]
    attribute = data["attribute"]
    operator = data["operator"]
    value = _clean_value(data["value"])
    return Expression(entity=entity, attribute=attribute, operator=operator, value=value)


def _parse_conditions(raw: str) -> List[Expression]:
    if not raw or not raw.strip():
        return []

    # Split on Boolean connectives while respecting simple values that contain spaces.
    # For the current DSL, values are tokenized without spaces; this keeps the parser
    # intentionally simple and deterministic.
    split = re.split(r"\s+(?:and|or)\s+", raw, flags=re.IGNORECASE)
    return [_parse_condition(part) for part in split if part.strip()]


def _parse_obligation(raw: Optional[str]) -> Optional[Obligation]:
    if raw is None or not raw.strip():
        return None

    text = raw.strip()
    name_match = re.match(r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)", text)
    if not name_match:
        raise ValueError(f"Invalid obligation: {raw!r}")

    name = name_match.group("name")
    remainder = text[name_match.end() :].strip()
    if remainder.startswith("(") and remainder.endswith(")"):
        parameter = remainder[1:-1].strip()
    else:
        parameter = ""
    return Obligation(name=name, parameter=parameter)


def parse_policy(source: str) -> Policy:
    """Parse a PACA++ policy string into a `Policy` AST object."""

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
    """Read a policy file and parse it."""

    with open(path, "r", encoding="utf-8") as handle:
        return parse_policy(handle.read())


__all__ = ["parse_policy", "parse_policy_file"]
