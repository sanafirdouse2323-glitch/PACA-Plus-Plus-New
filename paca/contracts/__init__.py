"""Platform-neutral PACA++ protocol primitives and validators."""

from .broker import (
    BrokerOperationError,
    BrokerOperationVerifier,
    BrokerSessionContext,
    VerifiedBrokerOperation,
)
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
    "BrokerOperationError",
    "BrokerOperationVerifier",
    "BrokerSessionContext",
    "CanonicalizationError",
    "ContractValidationError",
    "InvalidJSONError",
    "MessageAuthenticationError",
    "MessageSigner",
    "MessageSigningConfigurationError",
    "MessageVerifier",
    "ProtocolDependencyError",
    "TrustedMessageKey",
    "VerifiedBrokerOperation",
    "VerifiedMessage",
    "canonicalize",
    "digest_object",
    "parse_json",
    "validate_message",
]
