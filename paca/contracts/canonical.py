"""Strict JSON parsing, RFC 8785 canonicalization and domain-separated digests.

This module contains deterministic data-format primitives only. It does not
authenticate messages, verify signatures, establish caller identity, evaluate
policy, check revocation or authorize a resource operation.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

try:
    import rfc8785
except ImportError:  # pragma: no cover - exercised in environments without the extra
    rfc8785 = None


_MAX_SAFE_INTEGER = (2**53) - 1
_PURPOSE_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_DIGEST_DOMAIN = b"PACA++/DIGEST/V1\n"


class CanonicalizationError(ValueError):
    """A value cannot be represented as a PACA++ JCS canonical JSON value."""


class InvalidJSONError(CanonicalizationError):
    """JSON input is malformed or outside the protocol's accepted JSON subset."""


class _DuplicateKeyError(InvalidJSONError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise InvalidJSONError(f"non-JSON numeric constant is not permitted: {value}")


def _validate_value(value: Any, path: str = "$") -> None:
    """Enforce JSON/I-JSON value types before handing data to the JCS encoder."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise CanonicalizationError(
                f"string at {path} contains an unpaired Unicode surrogate"
            ) from exc
        return
    if isinstance(value, int):
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"integer at {path} is outside the I-JSON exact integer range; encode it as a decimal string"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(f"non-finite number at {path} is not permitted")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"object member name at {path} must be a string"
                )
            _validate_value(key, f"{path}.[member-name]")
            _validate_value(item, f"{path}.{key}")
        return
    raise CanonicalizationError(
        f"value at {path} has unsupported type {type(value).__name__}; use JSON values only"
    )


def parse_json(data: str | bytes) -> Any:
    """Parse JSON while rejecting duplicate keys, invalid UTF-8 and non-I-JSON values.

    The returned Python value is suitable for canonicalize(). Integer values outside
    the interoperable IEEE-754 safe range are rejected; encode exact large integers
    as decimal strings in protocol messages.
    """
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise InvalidJSONError("JSON message must be valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise TypeError("parse_json accepts str or bytes")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except InvalidJSONError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise InvalidJSONError("invalid JSON message") from exc
    _validate_value(value)
    return value


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785 JCS UTF-8 bytes for a JSON/I-JSON-compatible value.

    The rfc8785 dependency is optional and is required by the 'protocol' extra.
    This function never substitutes Python json.dumps(sort_keys=True), which is not
    an RFC 8785 implementation.
    """
    if rfc8785 is None:
        raise CanonicalizationError(
            "RFC 8785 support is unavailable; install PACA++ with the 'protocol' extra"
        )
    _validate_value(value)
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise CanonicalizationError("RFC 8785 canonicalization failed") from exc


def digest_object(value: Any, *, purpose: str) -> str:
    """Return a domain-separated lowercase SHA-256 digest of canonical JSON.

    purpose must be a stable, lowercase protocol token (for example 'request',
    'payload', 'grant' or 'audit-event'). The domain and purpose are included
    before the canonical bytes so equal JSON values in different contexts do not
    share a protocol digest.
    """
    if not isinstance(purpose, str) or not _PURPOSE_PATTERN.fullmatch(purpose):
        raise ValueError(
            "purpose must be a lowercase protocol token (1-64 characters)"
        )
    payload = canonicalize(value)
    domain = _DIGEST_DOMAIN + purpose.encode("ascii") + b"\n"
    return hashlib.sha256(domain + payload).hexdigest()
