"""Platform-neutral PACA++ protocol primitives and validators."""

from .canonical import (
    CanonicalizationError,
    InvalidJSONError,
    canonicalize,
    digest_object,
    parse_json,
)
from .signatures import (
    MessageAuthenticationError,
    MessageSigner,
    MessageSigningConfigurationError,
    MessageVerifier,
    TrustedMessageKey,
    VerifiedMessage,
)
from .validation import (
    ContractValidationError,
    ProtocolDependencyError,
    validate_message,
)

__all__ = [
    "CanonicalizationError",
    "ContractValidationError",
    "InvalidJSONError",
    "MessageAuthenticationError",
    "MessageSigner",
    "MessageSigningConfigurationError",
    "MessageVerifier",
    "ProtocolDependencyError",
    "TrustedMessageKey",
    "VerifiedMessage",
    "canonicalize",
    "digest_object",
    "parse_json",
    "validate_message",
]
