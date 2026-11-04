"""Obligations attached to permit rules (executed by the monitor, not the model)."""
from __future__ import annotations

from typing import Callable, Dict, List

# Only these names have built-in semantics. Integrators may register additional handlers.
KNOWN = {"audit_log", "require_approval"}


class ObligationRunner:
    """Registry of obligation handlers; unknown obligations fail closed."""

    def __init__(self) -> None:
        self.handlers: Dict[str, Callable[..., None]] = {}

    def register(self, name: str, fn: Callable[..., None]) -> None:
        self.handlers[name] = fn

    def run(self, names: List[str], **ctx) -> List[str]:
        done = []
        for n in names:
            if n == "require_approval":      # enforced by the monitor's verdict logic
                done.append(n); continue
            fn = self.handlers.get(n)
            if fn is None:
                raise ValueError(f"unknown obligation {n!r}: refusing to proceed")
            fn(**ctx); done.append(n)
        return done


__all__ = ["ObligationRunner", "KNOWN"]
