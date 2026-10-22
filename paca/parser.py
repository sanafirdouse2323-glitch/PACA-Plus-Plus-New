"""Reference parser for the PACA++ policy DSL.

The parser accepts compact policy strings such as:

    permit readFile when user.role == admin and user.department == engineering
    deny deleteFile when user.role != admin with obligation audit_log(user.id)

It preserves the existing simple API (`parse_policy`) while adding support for
multiple obligations and logical connectors.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .ast import Expression, Obligation, Policy

_POLICY_RE = re.compile(
    r"""(?is)^
    (?P<effect>permit|deny)
    \s+
    (?P<action>[A-Za-z_][A-Za-z0-9_.-]*)
    (?:\s+when\s+(?P<conditions>.+?))?
    (?:\s+with\s+(?:obligation|obligations)\s+(?P<obligations>.+?))?
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
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.lower() in {"none", "null"}:
        return None
    if re.fullmatch(r"[-+]?\d+", value):
        return int(value)
    if re.fullmatch(r"[-+]?\d+\.\d+", value):
        return float(value)
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_clean_value(part.strip()) for part in inner.split(",")]
    return value


def _split_top_level(expr: str) -> List[str]:
    """Split an expression on `and`/`or` at the top level only."""

    fragments: List[str] = []
    current: List[str] = []
    depth = 0
    quote: Optional[str] = None
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote is not None:
            current.append(ch)
            if ch == "\\":
                i += 1
                if i < len(expr):
                    current.append(expr[i])
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            current.append(ch)
            i += 1
            continue

        if ch in "([":
            depth += 1
            current.append(ch)
            i += 1
            continue

        if ch in ")]":
            depth = max(depth - 1, 0)
            current.append(ch)
            i += 1
            continue

        if depth == 0:
            remaining = expr[i:].lower()
            if remaining.startswith(" and "):
                fragments.append("".join(current).strip())
                current = []
                i += 5
                continue
            if remaining.startswith(" or "):
                fragments.append("".join(current).strip())
                current = []
                i += 4
                continue

        current.append(ch)
        i += 1

    cleaned = "".join(current).strip()
    if cleaned:
        fragments.append(cleaned)
    return [fragment for fragment in fragments if fragment]


def _parse_condition(fragment: str) -> Expression:
    match = _CONDITION_RE.match(fragment.strip())
    if not match:
        raise ValueError(f"Unsupported condition fragment: {fragment!r}")

    data = match.groupdict()
    operator = data["operator"].lower()
    return Expression(
        entity=data["entity"],
        attribute=data["attribute"],
        operator=operator,
        value=_clean_value(data["value"]),
    )


def _parse_conditions(raw: str) -> Tuple[List[Expression], List[str]]:
    if not raw or not raw.strip():
        return [], []

    fragments = _split_top_level(raw)
    if not fragments:
        return [], []

    conditions = [_parse_condition(fragment) for fragment in fragments]
    connectors = [token.lower() for token in re.findall(r"\s+(and|or)\s+", raw, flags=re.IGNORECASE)]
    return conditions, connectors


def _parse_obligation(raw: Optional[str]) -> Optional[Obligation]:
    if raw is None or not raw.strip():
        return None

    text = raw.strip()
    if not text:
        return None

    if "," in text:
        obligations = [part.strip() for part in text.split(",") if part.strip()]
        parsed = [_parse_obligation(item) for item in obligations]
        return parsed[0] if parsed else None

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


def _parse_obligations(raw: Optional[str]) -> List[Obligation]:
    if raw is None or not raw.strip():
        return []

    fragments = [part.strip() for part in raw.split(",") if part.strip()]
    obligations: List[Obligation] = []
    for fragment in fragments:
        obligation = _parse_obligation(fragment)
        if obligation is not None:
            obligations.append(obligation)
    return obligations


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
    conditions_text = match.group("conditions") or ""
    obligations_text = match.group("obligations")

    expressions, connectors = _parse_conditions(conditions_text)
    parsed_obligations = _parse_obligations(obligations_text)
    obligation = parsed_obligations[0] if parsed_obligations else None

    return Policy(
        name=f"{effect}_{action}",
        action=action,
        expressions=expressions,
        obligation=obligation,
        obligations=parsed_obligations,
        effect=effect,
        description="",
        priority=0,
        connectors=connectors,
        metadata={},
    )


def parse_policy_file(path: str) -> Policy:
    """Read a policy file and parse it."""

    with open(path, "r", encoding="utf-8") as handle:
        return parse_policy(handle.read())


__all__ = ["parse_policy", "parse_policy_file"]
