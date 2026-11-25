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
from .permits import (
    CommitPermitError,
    ProtocolCommitPermitVerifier,
    VerifiedProtocolCommitPermit,
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
    "CommitPermitError",
    "ContractValidationError",
    "InvalidJSONError",
    "MessageAuthenticationError",
    "MessageSigner",
    "MessageSigningConfigurationError",
    "MessageVerifier",
    "ProtocolCommitPermitVerifier",
    "ProtocolDependencyError",
    "TrustedMessageKey",
    "VerifiedBrokerOperation",
    "VerifiedMessage",
    "VerifiedProtocolCommitPermit",
    "canonicalize",
    "digest_object",
    "parse_json",
    "validate_message",
]
