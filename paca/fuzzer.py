"""Helpers for obligations attached to policies."""

from __future__ import annotations

from typing import Any, Dict


def obligation_check(obligation: Any, context: Dict[str, Any]) -> bool:
    """Return True when an obligation is satisfied by the runtime context.

    This is intentionally lightweight: the obligation is modeled as a symbolic
    check, not a solver-backed verification system.
    """

    if obligation is None:
        return True

    name = getattr(obligation, "name", str(obligation))
    parameter = getattr(obligation, "parameter", "")
    if name == "audit_log":
        return bool(context) and (parameter or True)
    if name == "notify":
        return bool(parameter)
    return True


__all__ = ["obligation_check"]
