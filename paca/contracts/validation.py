"""Versioned PACA++ message-schema validation.

Schema validation checks message shape only. Callers must separately establish
message signatures, peer identity, grant status, resource-scope containment,
quota, revocation and commit-boundary enforcement.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any


class ProtocolDependencyError(RuntimeError):
    """An optional protocol validation dependency is not installed."""


class ContractValidationError(ValueError):
    """A message does not match the selected PACA++ versioned schema."""


@lru_cache(maxsize=1)
def _validator() -> Any:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:  # pragma: no cover - depends on optional installation
        raise ProtocolDependencyError(
            "JSON Schema validation requires the PACA++ 'protocol' extra"
        ) from exc

    schema_path = files("paca.contracts").joinpath(
        "schemas", "v1.0.0", "paca-contracts.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_message(message: Any) -> None:
    """Validate a message against the closed v1.0.0 schema.

    Raises ContractValidationError for structural errors. This function does not
    verify the message's proof or trust the identity/claims contained in it.
    """
    validator = _validator()
    errors = sorted(
        validator.iter_errors(message),
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            error.message,
        ),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "$"
        raise ContractValidationError(
            f"PACA++ v1.0.0 message schema validation failed at {location}: {first.message}"
        )
